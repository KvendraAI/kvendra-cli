# Security model — kvendra-cli 0.6.4

## Trust narrative

kvendra implements a **zero-knowledge vault** (random vault key wrapped
under an Argon2id-derived key since 0.9.0, AES-256-GCM ciphers, master
password never stored to disk) plus a **capability-based MCP broker**
(7 git/github/npm/pypi/aws/http/shell primitives + an escape hatch for raw
tokens).

> **0.9.0 update — key hierarchy and recovery.** See
> [Vault key hierarchy and recovery (0.9.0)](#vault-key-hierarchy-and-recovery-090)
> below. The rest of this page describes the 0.6.4 hardening and still holds.

> **Read first:** for plain-language expectations (what protects you, what does
> not, and how to raise it) see
> [protection-levels.md](security/protection-levels.md); for the engineering
> detail of the 0.6.4 security-hardening release — the fail-closed fixes from
> Salva Ferrer's external audit plus in-house adversarial passes — see the
> [0.6.4 advisory](security/advisory-cli-0.6.4.md).

The trust narrative (0.6.4):

1. **Defense layer 1 — Filesystem integrity**: `~/.kvendra/` is per-user
   (mode 0700), individual files mode 0600, sentinel + recovery codes +
   profile blobs all HMAC-protected against in-place tampering.

2. **Defense layer 2 — Allowlist gate**: each profile's allowlist YAML is
   HMAC-signed with `kvendra/allowlist-hmac/v1` sub-key (TOCTOU-safe).
   Boundary calls outside scope return `AllowlistViolation` with a canonical
   audit row flag (`allowlist_denied`). Since 0.6.4 the gate is **fail-closed**:
   a credential-bound profile with no allowlist, an empty/invalid `profile_id`,
   or an unsigned/tampered allowlist or `config.toml` are all denied — the
   external audit found and closed a family of fail-open paths here (see the
   advisory).

3. **Defense layer 3 — Approval gate**: destructive ops (write, push,
   destroy) require explicit user consent via TTY (CLI) or modal/dialog
   (MCP). Approval results are audit-logged with canonical flags
   (`mcp_approval_biometric_granted` / `mcp_approval_biometric_rejected`).

4. **Defense layer 4 — Audit log integrity**: every MCP call + every
   sensitive CLI op writes a row to `~/.kvendra/audit.db`, HMAC-chained
   with sub-key `kvendra/audit-hmac/v1`. Tampering detected via
   `kvendra audit --verify`.

## Vault key hierarchy and recovery (0.9.0)

Vaults created with 0.9.0 or later use an envelope:

- The **vault key** (MK) is 32 random bytes. Secret blobs, local variables,
  the HKDF sub-keys (allowlist/config HMAC, audit HMAC, backup) and the
  audit chain all hang from it.
- `sentinel.blob` **v2** stores MK wrapped (AES-256-GCM) under
  `Argon2id(master password, salt)`, plus `check`, an AEAD of a constant
  under MK that lets a candidate MK (from the session blob or the recovery
  phrase) be verified without the password.
- `recovery.blob` **v1** stores MK wrapped under
  `HKDF-SHA256(salt = vault_id, IKM = BIP-39 seed of the 12-word phrase,
  info = "kvendra/recovery-wrap/v1")`. The phrase itself is never stored.
- Every AEAD carries an AAD binding the format label, the format version and
  the public `vault_id` (and, for the password wrap, the Argon2id
  parameters), so a ciphertext cannot be moved between vaults or formats.

`kvendra recover` (forgotten password: 12-word phrase → new password) and
`kvendra passwd` (current password → new password) only re-wrap MK and
replace `sentinel.blob` with an atomic tmp + fsync + rename commit; the
previous sentinel is restored on any failure, and a crash leaves a vault
that opens with the old password or the new one. Both remove the session
blob and the keychain entries bound to THIS vault (owner tag = its
`vault_id`); entries of another vault or without an owner are left in
place, and the final message reports each entry as removed, absent or left.
A backend error reading the owner of `mcp-password/v1` aborts the change.
Rejected attempts happen before any
key exists, so they are logged to `audit.preauth.jsonl` (no secret, closed
vocabulary) and imported into the HMAC chain, flagged
`preauth_unauthenticated`, at the next successful unlock.

Limits, stated plainly:

- **The phrase is as powerful as the password**: phrase + a copy of the
  vault files = a new password of the attacker's choosing.
- **Changing the password does not revoke old copies**: an earlier
  `sentinel.blob` (in an older backup, a disk snapshot) still opens with
  the old password and yields the same MK. Recovery is for a forgotten
  password, not a stolen one; for a suspected leak, create a new vault.
- **Vaults created before 0.9.0** (sentinel v1, no `recovery.blob`) keep
  working, but `recover` and `passwd` refuse on them without changing
  anything. There is no migration in 0.9.0.

Full treatment: [`THREAT-MODEL.md`](../THREAT-MODEL.md) (V9 and "Changing
the password does not revoke old copies").

## Session blob threat model

`~/.kvendra/sessions/active.blob` is the new asset that lets
`kvendra mcp serve` start without re-prompting. It is **not** the
master password on its own — it is the vault key sealed under a
machine-bound wrap key with a short TTL.

### What protects the blob

- **AES-256-GCM** ciphertext + **HMAC-SHA256** sidecar
  (`active.blob.hmac`). The HMAC is verified in constant time before
  any decrypt is attempted; tamper surfaces as `HmacMismatch` and the
  blob is treated as if absent.
- **Wrap key derived via HKDF-SHA256** with info constant
  `kvendra/session-wrap/v1` (fourth alive sub-key under the
  ADR-KVD-022 convention). Salt: `hostname` + `uid` +
  `kvendra_home_canonical` joined with `0x1F`. The IKM is a fixed
  sentinel string — entropy comes from the machine-bound salt, not
  the master password (avoids the chicken-and-egg of needing the
  password to decrypt the blob that exists to *avoid* prompting).
- **Machine binding**: the blob also carries `hostname`, `uid` and
  `kvendra_home_canonical` inside the encrypted payload, cross-checked
  against the current machine on load. Copying the blob to another
  laptop fails the load.
- **TTL** (default 4h, max 24h, hard ceiling 7d) — the blob carries
  `expires_at` inside the encrypted payload. Loads past the TTL are
  treated as if the blob were absent.
- **`mode 0600` POSIX / ACL current-user-only Windows**.
- **`fs2::FileExt::lock_exclusive`** advisory flock on every write so
  concurrent `unlock --extend` operations are serialised.
- **Atomic write** (tmp + rename + fsync) so observers either see the
  old blob or the new one — never a torn write.

### What does NOT protect the blob

The blob is readable by any process running under the same user on
the same machine (`mode 0600`). That is the same trust boundary the
zero-knowledge vault assumes: a compromised user account ⇒ a
compromised vault. The blob narrows the window for the attacker by
adding a TTL, but it does **not** change the trust boundary. This is the
residual tracked as **C3** (`ISSUE-KVD-CLI-B12B18`); closing it locally needs
hardware-backed key wrapping (on the roadmap). See
[protection-levels.md](security/protection-levels.md), case B.

For attackers off-machine (backup leak, snapshot leak), the
machine-bound wrap key makes the blob opaque: the same blob loaded
on a different host derives a different wrap key and the AES-GCM tag
fails immediately.

### Anti-captured-env defense at write time

`kvendra unlock` refuses to run inside an MCP client subprocess so the
master password never reaches the blob via a captured channel. The
three layers are documented in `PAT-KVD-CLI-008` and in the
[`README.md`](../README.md) section "Cross-platform session model".
The defense is validated empirically — the `cargo test` harness has
the same captured-stdio profile as Claude Code's Bash tool, and the
test `captured_env::tty_unix::tests::rejects_under_cargo_test_harness`
asserts a deterministic rejection.

### Audit trail

`kvendra unlock`, `kvendra unlock --extend` and the session-blob load
path in `kvendra mcp serve` emit canonical flags
(`unlock_succeeded`, `unlock_extended`, `session_expired_at_read`,
`session_blob_tampered`, `session_blob_machine_mismatch`, ...) so
`kvendra audit --verify` and downstream dashboards can match exact
bytes. Pre-unlock rejects (no controlling TTY, stdio not owned) land
in `tracing` rather than `audit.db` because the HMAC sub-key does
not exist before the unlock — the same documented gap as
ADR-KVD-020 AC-USE-KEYCHAIN-8.

## Caveats (0.6.4)

### MCP password caching: RAM-only, not Touch ID

The `master_password_cache = "ram-only"` mode is the default and only mode for
MCP transport. Touch ID-protected password caching requires a signed binary
(Apple Developer ID), which is **not available** yet — it is on the
vault-hardening roadmap.

The full technical analysis of this caveat lives in `PAT-KVD-CLI-001` in
the project knowledge base. The summary:

- **Destructive ops via MCP** still require approval. The approval gate
  degrades from "Touch ID biometric" to "macOS modal consent dialog with
  Approve/Cancel buttons" — the cryptographic factor is weaker (button
  click vs fingerprint), but the structural promise is preserved: no
  silent automated bypass.
- **CLI-direct ops** (when user runs `kvendra` interactively) require
  TTY password prompt every time the cache expires (see
  `idle_timeout_minutes` in `config.toml`).
- **No silent silent approval** in either transport — `PAT-KVD-CLI-001`
  documents this with audit-log evidence from real-run testing.

Touch ID and signed-binary distribution are on the vault-hardening roadmap
(`ROAD-KVD-CLI-393064`), opt-in and layered.

## Reporting security issues

Security-relevant issues should be reported per the project's
[`SECURITY.md`](../SECURITY.md) policy.

## References

- [`docs/security/protection-levels.md`](security/protection-levels.md) — plain-language protection expectations (cases A/B/C).
- [`docs/security/advisory-cli-0.6.4.md`](security/advisory-cli-0.6.4.md) — the 0.6.4 security-hardening advisory (external audit + fixes).
- `ROAD-KVD-CLI-393064` — layered vault-hardening roadmap (hardware keys, ephemeral creds, server-assist, remote broker).
- `PAT-KVD-CLI-003` — allowlist enforcer permissive-on-absence anti-pattern (the class 0.6.4 closed fail-closed).
