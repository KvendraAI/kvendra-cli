# Security advisory — kvendra-cli 0.6.4

**Summary:** the authorization / enforcement layer of `kvendra-cli` had several
fail-open paths that could let an untrusted MCP client (an AI agent driving the
broker) bypass the allowlist and approval controls the CLI is meant to enforce.
The cryptographic core (Argon2id, AES-256-GCM, ed25519 grant signing, OAuth
PKCE) was sound; the defects were in *policy enforcement*. All exploitable
issues are fixed in **0.6.4** by failing closed.

- **Component:** `kvendra` CLI (MCP capability broker + local zero-knowledge vault)
- **Affected versions:** ≤ 0.6.3
- **Fixed in:** 0.6.4
- **Reporter:** Salva Ferrer — avtn.es (external static audit), plus an in-house
  adversarial pass for two additional issues
- **Tracking:** `ISSUE-KVD-CLI-B78ED5`

> **For users:** if you want the plain-language version of what the vault
> protects and what it does not — and how to raise your protection level —
> read [what protects you and what does not](protection-levels.md). This
> advisory is the engineering detail behind the fixes.

## Who is affected

Anyone running `kvendra mcp serve` and exposing the broker to an AI agent or any
other MCP client that can send `tools/call` requests. The broker is the trust
boundary between the agent and your credentials, so a policy bypass there is
what matters — the agent is explicitly modelled as potentially malicious (threat
vector V7).

## Findings and fixes

### Critical

**C1 — Empty `profile_id` bypassed both the allowlist and approval.**
A `tools/call` with an empty `profile_id` skipped allowlist enforcement (guarded
by `if !profile_id.is_empty()`) and was treated as non-destructive by the
approval layer. Because `kvendra.shell` needs no secret, an agent could run an
arbitrary binary with no allowlist and no confirmation.
*Fix:* every catalog primitive is credential-bound, so an empty `profile_id` is
now a hard deny (audit flag `empty_profile_denied`).

**C2 — The shell `binaries:` allowlist was never enforced.**
The enforcer read the binary from a field named `bin`, but the `kvendra.shell`
primitive emits it as `binary`. The lookup always returned "absent", so the
`binaries:` constraint was inert and any binary ran — while the enforcer's unit
tests used the wrong `bin` field too, so they stayed green.
*Fix:* the wire field name is a single shared constant read by both the
primitive and the enforcer; a `binaries:` constraint with no `binary` field in
the payload now fails closed. The complicit tests were corrected.

**C4 — A profile with a secret but no allowlist was fail-open.**
When a profile's allowlist YAML was absent, the enforcer returned "allowed", and
`kvendra secret add` never creates an allowlist — so the permissive state was
reachable in normal use.
*Fix:* absence of an allowlist for a credential-bound profile is now a hard deny
(`missing_allowlist_denied`).

### High

**H2 — Mutating operations skipped the `ask-destructive` prompt.**
The destructive-catalog predicates (`s3 sync --delete`, `git tag --force`,
mutating HTTP verbs, closing a GitHub issue) inspect fields that live in the
inner `args` payload, but the approval layer passed the whole MCP envelope, so
those fields read as absent and the op was classified non-destructive — no
confirmation prompt in the default mode.
*Fix:* the approval layer reads the inner payload, matching the enforcer.

**H4 — The escape-hatch per-session quota was never enforced.**
`unsafe_max_uses_per_session` was declared in the allowlist DSL but never read,
so `kvendra.unsafe.raw_token` — which returns the plaintext credential — had no
per-session cap.
*Fix:* the dispatcher enforces the quota (default 1 use per session,
`unsafe_quota_exceeded`).

**H5 — `git clone` URL enabled remote code execution and option injection.**
The clone URL was passed to `git` unvalidated. `git`'s `ext::` remote helper
runs an arbitrary command (`ext::sh -c '<cmd>'` = RCE), and a URL beginning with
`-` was parsed as a git option.
*Fix:* URLs are validated (scheme allowlist, no `transport::` helpers, no
leading `-`), a `--` terminator is inserted, and every git invocation runs with
`-c protocol.ext.allow=never -c protocol.file.allow=user`.

### Medium / hardening

- **URL allowlist regex was a substring match** (`Regex::is_match`), so a
  pattern pinning the host also matched a hostile URL that merely *contained*
  it — e.g. `https://evil.example/?x=https://api.github.com/` — leaking the
  Bearer token. URL patterns are now start-anchored.
- **The generic HTTP broker followed redirects with the credential attached.**
  `kvendra.http` now uses a no-redirect policy, so the secret never follows a
  `Location:` to an un-vetted host.
- **Secret-detection layer widened** with Slack, Stripe (live), Google API key
  and GitLab PAT patterns.

### Found during the in-house adversarial pass (beyond the external audit)

- **Path traversal via `profile_id`.** The agent-supplied `profile_id` was
  interpolated into vault filesystem paths with no validation, so `../…` or `/`
  could traverse. It is now validated against `[A-Za-z0-9._-]` with `..`
  rejected (`invalid_profile_denied`).
- **AppleScript approval-reason hardening.** The macOS approval dialog text is
  built partly from the agent-supplied `profile_id`; control characters are now
  stripped in addition to escaping quotes and backslashes.

### Found during the owner's pre-release adversarial review of the command surface

- **A1 — `kvendra unlock --extend` extended the session without any
  authentication.** The extend path bumped the on-disk session TTL with no
  master password, no presence check, and no anti-captured-env guard. Any
  process running as the owner could therefore keep a session — and the
  broker's credential access it grants — alive indefinitely by looping
  `unlock --extend`, defeating the absolute session-TTL gate the design
  advertises, without ever knowing the master password. Extend now
  re-authenticates with the master password (mirroring `kvendra bypass`).
  The rest of the privileged command surface was reviewed command-by-command
  and already re-authenticates. Residual: a same-uid attacker who crafts the
  session blob directly can still forge its TTL — that is the C3 boundary,
  whose real fix is hardware-backed key wrapping.

### Found in the adversarial pentest (cycle 4)

Each reproduced with a live PoC against the running broker and re-verified fixed.

- **N2 — arbitrary code execution via `kvendra.npm publish`.** npm runs the
  package's lifecycle scripts (`prepublishOnly` / `prepare` / `prepack`) from
  the caller-controlled `cwd`, so an agent allowed only to "publish" ran
  arbitrary code and harvested the master password from the environment —
  bypassing the allowlist/approval model entirely. Fixed with `--ignore-scripts`.
- **N1 — master password leaked to subprocesses.** Brokered subprocesses
  inherited the full `mcp serve` environment, including `KVENDRA_MCP_PASSWORD`.
  The sensitive `KVENDRA_*` vars are now scrubbed from every child.
- **N5 — option injection in aws/npm/pypi.** e.g. an s3 `src` of
  `--endpoint-url=http://evil/` redirected AWS to an attacker endpoint. The
  leading-`-` guard (previously git-only) now covers all brokered tools.
- **A5 — config-integrity bypass** and **A6 — allowlist-integrity bypass.** The
  HMAC that protects `config.toml` / a profile's allowlist could be bypassed by
  appending after the signature line or nulling the stored HMAC; the tampered
  file was then silently re-signed. Both now fail closed (refused as tampered).
- **A2 — PATH-hijack credential theft (partially mitigated).** A trojan tool in
  PATH runs under an allowlisted name and receives the injected credential.
  Relative-dir PATH plants are now blocked; absolute-dir hijack by a same-uid
  attacker is a documented residual (fix: pinned tool paths).

Documented residuals (same-uid boundary, tracked): no unlock lockout (A3);
audit-log tail truncation is undetected (N4); and while the vault is unlocked
the session blob is both readable and forgeable by a same-uid process (C3),
which is why hardware-backed key wrapping is the priority follow-up.

### Found in the pentest (cycle 5: same-uid file swaps, offline files, robustness)

- **S1b — an allowlist could be swapped between profiles.** The allowlist HMAC
  authenticates the YAML content but not the profile it belongs to, so a
  same-uid attacker could copy one profile's allowlist (+ its valid signature)
  onto another to widen it. The enforcer now binds the allowlist to the profile
  id it is used for.
- **S4c — a malformed JSON-RPC line killed the broker (DoS).** The `mcp serve`
  loop now replies with a parse error and keeps serving.
- **S1a — a secret blob could be swapped between profiles (residual).** The same
  swap on the encrypted secret makes a profile resolve another's credential;
  binding the blob to its profile is a format change tracked for a careful,
  migration-safe follow-up.

Robustness checks passed with no findings: `init` refuses to clobber an existing
vault, on-disk KDF parameters are production-grade (so offline attacks on the
encrypted files are bounded by the master password), and fuzzing found no crashes.

## Design-level items — documented, not code-patched

These are threat-model boundaries, not one-line bugs. They are stated honestly
in `THREAT-MODEL.md`; the real fixes are larger and tracked as follow-ups.

- **C3 — Unlocked-session blob.** While the vault is unlocked,
  `~/.kvendra/sessions/active.blob` is decryptable by a process running as your
  uid without the master password (its wrap key is machine-bound but derived
  from public inputs). This is the deliberate trade-off that lets `mcp serve`
  run without re-prompting, and it does not affect the at-rest guarantee (a
  locked vault exposes nothing). The proper fix is hardware-backed key wrapping
  (Secure Enclave / TPM / FIDO2). `THREAT-MODEL.md` §Promise and §V2 are
  corrected to say this plainly.
- **H1 — Offline audit-export authenticity.** The self-contained export bundle
  embeds the symmetric HMAC seed, so offline verification proves integrity but
  not authenticity. The bundle now carries an explicit `security_note`;
  asymmetric signing is the future fix.
- **H3 — Presence-gated approval is macOS-only.** On other platforms the
  approval prompt fails closed, so interactive confirmation must be turned off
  (`KVENDRA_APPROVAL_MODE=silent`) to operate. A cross-platform presence
  backend is future work.

## Remediation

Upgrade to 0.6.4:

```
cargo install kvendra    # resolves to 0.6.4
```

After upgrading, audit your profiles: any credential-bound profile now **must**
have an allowlist, or its calls will be refused. `kvendra secret validate --all`
lists profiles and their allowlists.

## Verifying the fixes

The repository ships an adversarial regression suite,
`tests/security_audit_salva.rs` — one attack per finding, run against the real
broker in a throwaway sandbox. The suite is red on 0.6.3 and green on 0.6.4:

```
cargo test --test security_audit_salva
```

## Credits

Thank you to **Salva Ferrer** (avtn.es) for the responsible, technically precise
report — it was accurate down to the file and line, and it held Kvendra to the
security bar the CLI promises. Thanks also to the wider community for the
scrutiny that keeps an open-core security tool honest. Responsible disclosure of
issues in any Kvendra product is welcome at **security@kvendra.ai** (see
`SECURITY.md`).
