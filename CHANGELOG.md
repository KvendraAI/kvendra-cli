# Changelog

All notable changes to the `kvendra` crate are documented here. The format
is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/) with
`-alpha.N` / `-beta.N` pre-release suffixes during the pre-1.0 phase.

## [0.1.0-alpha.10] — 2026-05-08

ISSUE-KVD-CLI-031 — Allowlist enforcer field-coverage fix. The Milestone 2
boundary smoke (AC-M2-6) caught two structural bugs in
`src/allowlist/enforcer.rs::check_args` that together blew the per-profile
authorisation surface wide open: (a) the three branches that **were**
implemented (`forbidden_args`, `methods`, `repos`) read their inputs from
the **top-level envelope** instead of the inner `args` payload, so any
real MCP `tools/call` request (canonical shape
`{profile_id, operation, args:{...}}`) silently bypassed those checks;
(b) **19 of the 22** declared `OperationConstraints` fields had no
enforcement branch at all and were dead letter — `buckets`, `distributions`,
`functions`, `binaries`, `packages`, `projects`, `refs`, `tag_pattern`,
`fields_allowed`, `forbidden_fields`, `forbidden_methods`,
`forbidden_env_export_to_agent`, `url_pattern_regex`, `endpoints`, `org`,
`repo` (singular alias), `cwd_pattern`, `args_constraints`,
`env_vars_to_inject`. The pre-existing tests passed because their fixtures
used a "flat" envelope shape that did not match the real MCP callsite —
PAT-KVD-004 reaffirmed (canonical shapes must be identical between tests
and runtime).

### Security

- **Allowlist enforcer now reads from the canonical MCP envelope's inner
  `args` payload** (D8). All 22 `OperationConstraints` fields have an
  enforcement branch. Any `kvendra.aws.s3_sync` / `cloudfront_invalidate`
  / `lambda_invoke` call against a resource outside the allowlist is now
  rejected with a clear `AllowlistViolation`. Same for
  `kvendra.shell.run` (binaries, cwd, argv templates, env injection),
  `kvendra.git` (refs, tag patterns, repo alias), `kvendra.github`
  (org/owner extraction, fields_allowed, forbidden_fields),
  `kvendra.npm` / `kvendra.pypi` (packages/projects), and
  `kvendra.http.request` (`forbidden_methods`, `endpoints` literal,
  `url_pattern_regex`).
- Closes the security gap that allowed the AC-M2-6 attacker trace
  (`s3://attacker-bucket/...` reaching dispatch on a profile scoped to
  `kvendra-com-prod`) and the symmetric paths through the other 18
  fields. Threat model L2 (data exfil via mis-scoped allowlist) is now
  structurally blocked at the enforcer.

### Added

- `regex` crate use in the enforcer for `url_pattern_regex`,
  `tag_pattern`, and `cwd_pattern` (already a transitive dep — no new
  Cargo dependency).
- New helpers in `src/allowlist/enforcer.rs`: `regex_match`,
  `regex_full_match`, `extract_bucket_from_s3_uri`,
  `extract_owner_from_repo`, `argv_matches_template`.
- D1..D8 decision register documented as module-level doc-comments in
  `enforcer.rs` and as field-level doc-comments in `dsl.rs`.
- `tests/integration_aws_allowlist_boundary.rs` — canonical regression
  smoke for AC-M2-6 with two integration tests
  (`aws_s3_sync_blocks_bucket_outside_allowlist` and
  `aws_cloudfront_invalidate_blocks_distribution_outside_allowlist`).
- ~50 net new in-line tests in `src/allowlist/enforcer.rs::tests` —
  bloque A (3 fields previously enforced, but with the canonical MCP
  envelope shape — PAT-KVD-004), bloque B (one happy + one violation
  per new field), bloque D (defense-in-depth edges: missing inner
  args, denylist precedence, malformed regex, envelope-meta keys not
  visible to `fields_allowed`).

### Caveats

- The `url_pattern_regex` and `tag_pattern` regexes are still
  evaluated at every `tools/call`. Pre-compiling them at YAML load
  time is a follow-up perf optimisation; today's cost is acceptable
  (single allowlist load per call already pays an HMAC verify and a
  YAML parse).
- `args_constraints` template matching is **strict-length** (D2): a
  call with fewer or more argv slots than the template is a no-match.
  Use the `*` wildcard token for any-single-slot, or declare multiple
  templates of different lengths to cover variants.
- `accept_broad_scope` is intentionally **not** enforced at runtime
  (D7) — it remains a validator-time signal only. Operators who want
  broad-scope rejection at YAML load are unaffected; the runtime
  enforcer trusts the validator's previous gate.

## [0.1.0-alpha.9] — 2026-05-07

E2E smoke regression fix uncovered while validating the alpha.7+ bundle
on a clean vault with `master_password_cache: os-keychain`. REQ-008
(alpha.7) introduced HMAC verification in `Config::load`, which in turn
caused every pre-unlock load (`Config::load(home, None)`) to return
`Err("cannot verify")` for any signed `config.toml`. Callers swallowed
the error via `unwrap_or_default()`, reverting **every user-set
preference** (most visibly `master_password_cache: os-keychain`) to the
hard-coded default, silently disabling the REQ-005 keychain fast-path
from alpha.7 onwards. The bug went unnoticed because no automated test
exercised the full `kvendra unlock` subprocess against a vault with
non-default preferences.

### Fixed

- `Config::load(home, None)` now parses signed configs without verifying
  the HMAC trailer (a `tracing::debug!` line records the deferral). The
  post-unlock load (`Config::load(home, Some(&vault))`) still enforces
  the HMAC and the `home_canonical` redirect check, so tampering is
  caught the moment the vault becomes available. Pre-unlock callers can
  read user preferences (`master_password_cache`, `idle_timeout_minutes`)
  from the signed config without hitting the soft-error fallback.
- The `home_canonical` redirect check is now gated on `vault.is_some()`
  for the same reason: pre-unlock the signed value cannot be trusted, so
  the check is deferred to the post-unlock load.

### Added

- Slow integration test `unlock_preserves_user_preferences_from_signed_config`
  in `tests/cli.rs` (gated by `#[ignore]`). Drives a full `init` → `config
  keychain enable` → `unlock` → `config keychain status` subprocess chain
  and asserts that the user's `OsKeychain` preference survives the
  bootstrap path. This is the test that would have caught the regression.

### Notes

- All bundle invariants from REQ-005..008 remain intact: tampered configs
  are still rejected at the post-unlock load (E2 of the smoke), and the
  KVENDRA_HOME-redirect attack is still blocked at the same point (E3).
  The pre-unlock window is best-effort for bootstrap settings and does
  not relax the threat model: an attacker who tampers `master_password_cache`
  to `OsKeychain` cannot read the keychain entry without Touch ID, and
  any tampering of `idle_timeout_minutes` is caught at the post-unlock
  verify before the broker accepts traffic.

## [0.1.0-alpha.8] — 2026-05-07

E2E smoke fix uncovered while validating the alpha.7 bundle on a clean
vault. `kvendra secret set-allowlist <profile> --file <yaml>` returned
`KvendraError::VaultLocked` because the dispatcher invoked the helper
without `ensure_unlocked`. Post-REQ-007 the helper needs the
`kvendra/allowlist-hmac/v1` HKDF sub-key (only available while the
vault is unlocked), so any caller that did not happen to pre-unlock
the vault hit the error. Existing tests exercised
`compute_allowlist_hmac` directly, bypassing the CLI dispatcher and
missing the bug.

### Fixed

- `kvendra secret set-allowlist` now unlocks the vault via the same
  helper used by `add` / `rotate` (env var `KVENDRA_PASSWORD` or
  `--password-stdin`) before computing the HMAC. Behaviour matches
  the documented flow in REQ-KVD-007 and the `set-allowlist` examples
  in the README.

### Added

- New `--password-stdin` flag on `kvendra secret set-allowlist`,
  consistent with the other vault-mutating subcommands.
- Slow integration test `secret_set_allowlist_unlocks_vault_via_env_var`
  in `tests/cli.rs` (gated by `#[ignore]` for CI cost — opt-in via
  `cargo test -- --include-ignored`). Drives the full subprocess
  path that the previous unit tests bypassed.

## [0.1.0-alpha.7] — 2026-05-07

REQ-KVD-008 / ISSUE-KVD-CLI-019 — Config.toml HMAC + `home_canonical` +
`rebind-home` triple-barrier (4/4 of the ROAD-KVD-008 bundle). Closes
GAP 5 (config tampering) and GAP 7 (KVENDRA_HOME redirect) of the L1
threat model. Together with REQ-005..007 the four structural barriers
of the L1 surface are complete.

### Changed

- **`Config::save` signature** now requires `&Vault` (the unlocked vault
  provides the HKDF sub-key for the HMAC trailer). Any caller without an
  unlocked vault gets a clear error pointing at `kvendra unlock`.
- **`Config::load` signature** now takes `vault: Option<&Vault>`. A signed
  `config.toml` (any post-REQ-008 file) requires the vault to verify the
  trailer; passing `None` against a signed file returns a soft error so
  pre-unlock callers (`kvendra unlock` itself, `mcp serve` before unlock)
  can degrade gracefully.

### Added

- HKDF sub-key `kvendra/config-hmac/v1` derived from the unlocked session
  key. Triple-domain separated from `audit-hmac/v1` and `allowlist-hmac/v1`
  — a leak of any one sub-key cannot forge HMACs in either of the other
  two namespaces.
- New trailing field `_hmac` in `~/.kvendra/config.toml` (last line). The
  HMAC-SHA256 covers every preceding TOML byte; any change (including
  whitespace) trips the load-time verify.
- New field `[vault] home_canonical: Option<String>` persisted inside the
  signed payload. Verified on load (both sides canonicalized) — a copy
  of `~/.kvendra/` to a different path no longer passes the loader.
- New subcommand `kvendra config rebind-home --new-path <path>` with
  triple-barrier verification: master password unlock, recovery code
  validation (one-shot), TTY confirmation via re-typed path. Strict
  no-TTY policy (D4=A) — non-interactive invocations are rejected.
- New `KvendraError` variants: `RecoveryCodeAlreadyUsed { slot, used_for,
  used_at }`, `RebindRequiresTty`, `RebindConfirmationMismatch`. The
  pre-existing `RecoveryCodeInvalid` keeps its name but the error
  message is now sharper.
- New canonical audit flags emitted by the new flow:
  `config_tampered_detected`, `home_redirect_detected`, `home_rebound`,
  `recovery_code_replay_attempted`, `config_hmac_migrated`. The first
  three are `error`/`warn` severity; the last two are info-level
  tracing lines.
- New `kvendra::audit::PRIMITIVE_SYSTEM = "kvendra.system"` constant.
  The `home_rebound` audit row uses it (paralleling the existing
  `vault_created` bootstrap row).
- Auto-migration on first unlock post-upgrade. Pre-REQ-008 configs (no
  `_hmac` trailer) are silently re-saved with the trailer + canonical
  home — `kvendra::config::auto_migrate_config_if_needed`. Trust
  caveat: the existing config bytes become the signed baseline.
- Helpers `kvendra::vault::recovery::validate_code_unconsumed` and
  `mark_code_consumed` for the rebind triple-barrier flow.

### Tests

- 23 net new tests for REQ-KVD-008 covering: HMAC determinism + triple-way
  domain separation, save/load round-trip, HMAC mismatch rejection, copy
  attack rejection, attacker-owned-vault forge rejection, modified-home
  rejection, auto-migration silent path, all four rebind barriers
  (master password / recovery code / typed path / no-TTY), recovery
  code replay rejection, audit row schema (primitive + severity + slot
  in flags CSV), and a macOS-only canonicalize sanity test.

### Caveats

- **Editing `~/.kvendra/config.toml` by hand invalidates the HMAC.** The
  supported path is `kvendra config <subcommand>`. A recovery from a bad
  edit is to restore the previous file from backup, or to bootstrap a
  fresh config via the subcommands.
- **Auto-migration is trust-on-first-use.** If the alpha.6 config was
  already tampered with, the migration accepts the tampered bytes as the
  signed baseline. Operators with security-sensitive workloads should
  re-bootstrap their config via the subcommands after upgrading.
- **`rebind-home` consumes one recovery code permanently.** The
  `kvendra config recovery-codes regenerate` subcommand does NOT exist
  in this release — a follow-up ISSUE will land post-release. Plan
  ahead: keep a margin of unused recovery codes if you anticipate
  multiple rebinds (laptop migrations, encrypted-volume moves).
- **`rebind-home` strict no-TTY policy** (D4=A) blocks legitimate
  automation. Workaround: invoke the command in an interactive shell
  on the destination machine.
- **`home_canonical` is semipermanent.** Once stamped, the only way to
  change it is `rebind-home` (which consumes a recovery code). Symlink
  changes to the parent path will trip the load-time check.
- **Linux / WSL canonicalize edge-cases** are tracked as
  `pending-automation:linux-ci-matrix` and
  `pending-automation:wsl-ci-matrix` in the KB. The macOS canonicalize
  invariants are covered by `canonicalize_macos_volumes_and_users_paths`.

## [0.1.0-alpha.6] — 2026-05-07

REQ-KVD-007 / ISSUE-KVD-CLI-018 — Allowlist YAML HMAC + TOCTOU cache fix
(3/4 of ROAD-KVD-008 bundle). Closes GAPs 3 and 4 of the L1 threat model:
out-of-band edits of `~/.kvendra/allowlists/<id>.yaml` are now detected on
every `tools/call`, and the `[a]pprove-all-5min` cache is keyed on the
allowlist's HMAC so any file modification invalidates the cached approval
within the TTL window.

### Changed

- **`ApprovalCache::{lookup, approve, revoke}` signature** now takes
  `ApprovalCacheKey { profile_id, allowlist_hmac_hex }` (struct key)
  instead of `&str`. Internal API — no end-user impact, but cache hits
  now require an exact match on both the profile id and the HMAC of the
  allowlist YAML at the moment the entry was inserted.

### Added

- HKDF sub-key `kvendra/allowlist-hmac/v1` derived from the unlocked
  session key (parallel to `kvendra/audit-hmac/v1`). Domain-separated
  from the audit HMAC, so a leak of one cannot forge the other.
- New field `Profile.allowlist_hmac_hex: Option<String>` persisted in
  `~/.kvendra/profiles/<id>.json`. `#[serde(default)]` keeps profiles
  written by older binaries loadable.
- `kvendra::vault::compute_allowlist_hmac(key, raw_yaml)` — single
  source of truth for the HMAC over the YAML's raw bytes (no
  parse / re-serialize, no whitespace normalization).
- `Vault::allowlist_hmac_key()` accessor.
- `enforce_allowlist` re-computes the HMAC of the YAML on disk and
  compares it against the value stored in the profile meta. Mismatch
  returns `KvendraError::AllowlistTampered(profile_id)` and emits a
  structured tracing log with `flag = "allowlist_tampered_detected"`.
- **JSON-RPC `error_type: "allowlist_tampered"`** distinct from the
  existing `allowlist_violation`. The error data includes a hint
  pointing the operator to `kvendra secret set-allowlist <profile>
  --file <yaml>` or a backup restore.
- New canonical audit flags: `allowlist_tampered_detected` (severity
  `error`, recorded when the HMAC verify fails) and
  `allowlist_hmac_migrated` (info-level tracing line emitted on
  first read of a legacy profile).
- **Auto-migration on first read.** Profiles persisted by an older
  binary load with `allowlist_hmac_hex = None`; the first
  `tools/call` against such a profile signs the current YAML with the
  freshly derived sub-key and writes the HMAC back to the meta.
  Silent — no operator action required. Trust caveat: any tampering
  that occurred before the migration is implicitly accepted as the
  signed baseline. Operators with security-sensitive workloads
  should re-run `kvendra secret set-allowlist` after upgrading to
  rebaseline from a known-good YAML.

### Tests

- 13 new tests for REQ-KVD-007 covering the HMAC determinism /
  domain-separation invariants, the verify path (allow / reject /
  auto-migrate / no-op), the TOCTOU cache fix, audit-chain integrity
  in the presence of an `allowlist_tampered_detected` row, and
  backward-compat of the legacy meta JSON shape.

### Caveats

- Manual editing of `~/.kvendra/allowlists/<id>.yaml` is intentionally
  not supported and will trip `enforce_allowlist`. The supported path
  is `kvendra secret set-allowlist <profile> --file <yaml>`.
- The HMAC is over the file's exact raw bytes — comments, trailing
  whitespace, and line-ending differences all change the signature.

## [0.1.0-alpha.5] — 2026-05-07

REQ-KVD-006 / ISSUE-KVD-CLI-020 closure (2/4 of ROAD-KVD-008 bundle).
Closes the TTY hijack pattern documented in PAT-KVD-007 structurally:
the MCP subprocess no longer touches `/dev/tty` for approval prompts.
CLI commands keep the TTY behaviour. macOS only in this release;
Windows / Linux: `KVENDRA_APPROVAL_MODE=silent` workaround. ADR-KVD-021
documents the transport-based separation pattern (sister of ADR-KVD-020,
extends ADR-KVD-016). Implementation uses `osascript` display dialog;
TouchID-native `LAContext.evaluatePolicy` is a future hardening
drop-in replacement.

### Changed (REQ-KVD-006 / ISSUE-KVD-CLI-020)

- **Approval flow now branches on transport.** `kvendra mcp serve` (MCP
  transport) sends approval prompts to an OS-mediated dialog popup —
  never to `/dev/tty`. CLI commands keep the historical TTY behaviour.
  Closes the TTY-hijack pattern documented in **PAT-KVD-007** structurally:
  no env-var heuristic, just the binary's own subcommand. macOS only in
  this release; Windows / Linux: the broker rejects approval prompts with
  a clear error pointing to the `KVENDRA_APPROVAL_MODE=silent` workaround.
- **`approval::policy::requires_tty` signature**: `requires_tty(mode)` →
  `requires_tty(mode, transport)`. Internal API — no end-user impact.

### Added

- New module `src/approval/transport.rs` with `Transport::{Cli, Mcp}` enum,
  threaded through `mcp::ServerContext` (`Transport::Mcp` from
  `serve_with_vault`).
- New module `src/approval/biometric.rs` with `BiometricApprovalBackend`
  implementing the `ApprovalBackend` trait. Run on `tokio::spawn_blocking`
  to keep the reactor responsive while the OS popup is on-screen.
- `keychain_acl::request_user_presence_only(reason)`. macOS implementation
  shells out to `osascript` to display a native modal dialog (TouchID-
  native `LAContext.evaluatePolicy` is a future hardening). Windows /
  Linux return `BiometricError::Unavailable`.
- 3 new `ApprovalDecision` variants: `BiometricGranted` (cache-warming
  success), `BiometricRejected` (user dismissed the popup; blocks
  dispatch with `error_type = "approval_denied"`), and
  `BiometricUnavailable` (platform without OS popup support; blocks
  dispatch with `error_type = "approval_no_biometric"`).
- 3 new canonical audit flags: `mcp_approval_biometric_granted`,
  `mcp_approval_biometric_rejected`, `mcp_approval_biometric_not_available`.
- Test coverage: 8 net new tests across `approval/transport`, `approval/
  biometric`, `approval/policy`, `keychain_acl/macos`, plus 4 contract
  tests in `tests/approval_integration.rs` for the new variants.

## [0.1.0-alpha.4] — 2026-05-07

REQ-KVD-005 / ISSUE-KVD-CLI-017 closure (1/4 of ROAD-KVD-008 bundle).
Closes GAP 1 + GAP 6 of the L1 threat model on macOS by replacing the
exposed `mcp-password fetch` + wrapper-script pattern with an inline
`--use-keychain` flag gated by `kSecAttrAccessControl(.userPresence)`.
Mitigates the TTY-hijack pattern (PAT-KVD-007) when the broker is
spawned by an IDE/Desktop MCP client. macOS only in this release;
Windows / Linux fall back to the legacy `KVENDRA_MCP_PASSWORD` env var
path until cross-platform hardening lands. ADR-KVD-020 documents the
decision orthogonal to ADR-KVD-012.

### Changed (REQ-KVD-005 / ISSUE-KVD-CLI-017)

- **`kvendra mcp serve --use-keychain`** (new flag, **macOS only**): reads
  the master password from the OS keychain (item `kvendra/mcp-password/v1`
  under service `kvendra`) gated by `kSecAttrAccessControl(.userPresence)`.
  Every read triggers a TouchID popup, or — when biometric hardware is
  absent — the OS modal password popup. The prompt is OS-mediated and
  never touches `/dev/tty`, mitigating the TTY-hijack pattern documented
  in **PAT-KVD-007** when the broker is spawned by an IDE/Desktop MCP
  client (Claude Code, Cursor, ...).
- **`kvendra config mcp-password fetch` removed.** The legacy wrapper
  script (`~/.kvendra/wrappers/kvendra-mcp-serve`) is no longer generated
  by `enable`. Together these eliminate the GAP 1 + GAP 6 surfaces
  identified in the L1 threat model (ADR-KVD-010 V2-extension): an L1
  attacker can no longer obtain the password via `kvendra config
  mcp-password fetch` and cannot substitute the wrapper.
- **`kvendra config mcp-password migrate-to-keychain-acl`** (replaces
  `migrate`): rewrites `~/.claude.json` (and other supported clients) to
  use `command: kvendra` + `args: ["mcp", "serve", "--use-keychain"]`,
  re-saves the keychain entry with `userPresence` ACL, removes any
  leftover wrapper script, and writes a `*.bak.<timestamp>` of the
  original config.
- **Compatibility note:** `--use-keychain` and `enable` /
  `migrate-to-keychain-acl` are **macOS only** in this release. On
  Windows / Linux they reject explicitly to avoid creating a false sense
  of biometric protection (a `keyring`-base item without enforced ACL
  would be readable by any L1 process). Workaround on those platforms:
  continue using the legacy `KVENDRA_MCP_PASSWORD` env var path. Cross-
  platform hardening (Windows Hello, Linux PolKit / `pam`) is tracked in
  ROAD-KVD-008 and will land in a follow-up.

### Added

- New module `src/keychain_acl/` (`mod` + `macos` + `other` stubs)
  exposing `save_with_user_presence` / `read_with_user_presence` /
  `delete` over `service: kvendra`. macOS implementation uses
  `core-foundation` + `security-framework` with
  `SecAccessControlCreateWithFlags(USER_PRESENCE)`.
- `KvendraError::BiometricRejected` and `KvendraError::BiometricUnavailable`
  variants for unambiguous error reporting.
- 6 new integration tests in `tests/cli.rs` covering `fetch` removal,
  `--use-keychain` clap surface, and `--password-env` / `--no-unlock`
  conflict semantics; 3 new unit tests in `cli/config_mcp_password.rs`.

## [0.1.0-alpha.3] — 2026-05-07

ROAD-KVD-007 closure: 5-issue hardening + polish bundle gating AWS
profile habilitation, public marketing, and 0.1.0 stable promotion.
No breaking changes to the YAML allowlist surface (new fields are
`Option<bool>` with `#[serde(default)]`); a previously-valid
`accepts_minimum_valid_profile` legacy fixture had to add
`accept_destructive: true` on `kvendra.git.push` to keep semantics.

### Added

- **ISSUE-KVD-CLI-011** (REQ-KVD-003) — Configurable interactive approval
  layer for `tools/call`. New `src/approval/` module (`mod`, `policy`,
  `cache`, `tty`) with three modes (`silent` / `ask` / `ask-destructive`,
  default `ask-destructive`), env > profile-YAML > config.toml > default
  cascade, ASCII-box prompt to `/dev/tty` (Unix) / `CONIN$+CONOUT$`
  (Windows), in-memory `[a]pprove-all-5min` cache, audit flags
  `approval_granted` / `_denied` / `_timeout` / `_no_tty_denied` /
  `_cache_hit`. New CLI subcommand `kvendra config approval get|set|status`.
  ADRs: KVD-013 (prompt format), KVD-014 (cache storage), KVD-015 (timeout
  default 30s), KVD-016 (silent does NOT require TTY). Closes V7 +
  partially mitigates O1.LLM-auto-approve in the threat model
  (ADR-KVD-010). Tests: 28 (26 unit + 8 integration).
- **ISSUE-KVD-CLI-012** (REQ-KVD-004) — Forbidden methods restrictivos en
  allowlist. New `src/allowlist/catalog.rs` with `const CATALOG: &[DestructiveRule]`
  of 14 owner-ratified entries (e.g. `kvendra.aws.s3_sync` with `delete:true`,
  `kvendra.git.push`, `kvendra.unsafe.raw_token`, etc.) + 4 pure
  `fn(&Value) -> bool` predicates. Validator rejects allowlists with
  destructive ops missing `accept_destructive: true`; `secret validate`
  marks each operation `[⚠ DESTRUCTIVE — owner accepted]` /
  `[⚠ ANNOTATED]` inline. `approval::policy::lookup_destructive` now
  consults the catalog (single source of truth with REQ-003). ADRs:
  KVD-017 (const Rust array), KVD-018 (fn pointer signature), KVD-019
  (print format). Tests: 23 unit. Closes the third structural barrier
  for V7.
- **ISSUE-KVD-CLI-010** (last hardening) — `kvendra config mcp-password
  enable | migrate --client claude-code | status | disable | fetch`. The
  master password no longer needs to live in plaintext under
  `~/.claude.json`: it is stored in the OS keychain via the `keyring`
  crate (`service: kvendra`, `label: kvendra/mcp-password/v1`,
  independent of the `derived-key/v1` namespace from ADR-KVD-012),
  and a wrapper script at `~/.kvendra/wrappers/kvendra-mcp-serve`
  (perms 0700) loads it at spawn time. Closes the V2-extension where
  any process of the same user could read the password from the MCP
  client config.
- **ISSUE-KVD-CLI-014** (REQ-KVD-005 fix B+C) — LLM-friendly tool docs:
  `PrimitiveInfo` gains a multi-line `operations_doc` per catalog entry
  (8 primitives) so `tools/list` returns descriptions enumerating each
  operation's expected `args` shape. `tools/call` now intercepts
  `KvendraError::InvalidArgs` and returns a structured JSON-RPC error
  (`code = INVALID_PARAMS`, `data = { error_type, primitive, operation,
  hint, message }`) so the agent can self-correct without retries.
  Diagnosis from `consultancy-v3` Sesion 3 confirmed H2 as the root
  cause of the AC-MCP-4 retry pattern; option A (one tool per
  operation) was deferred post-Beta to avoid breaking existing allowlists.
- **TEST entries** in KB v3: TEST-KVD-CLI-030 (AC-APPROVAL-6 no TTY),
  TEST-KVD-CLI-031 (AC-APPROVAL-4 timeout), TEST-KVD-CLI-032
  (AC-APPROVAL-3 TTY isolation).

### Fixed

- **ISSUE-KVD-CLI-013** — `kvendra.github.add_topics` now appends
  rather than replacing. The previous implementation called
  `PUT /repos/{owner}/{repo}/topics` directly with the new list, which
  GitHub interprets as a replacement; the new flow GETs the existing
  topics, merges by `merge_topics_unique` (preserves order, deduplicates
  by string value), and then PUTs the merged list. Sister-primitive
  audit (`update_repo`, `update_issue`, `release`, `git.tag` without
  `--force`, `aws.s3_sync` with `delete: true` opt-in) confirmed only
  `add_topics` had this issue. Detected during the AC-MCP-4 write smoke
  on 2026-05-07.

### Changed

- `OperationConstraints` (allowlist DSL) gains two `Option<bool>` fields,
  `destructive` (declarative; from REQ-003) and `accept_destructive`
  (opt-in; from REQ-004). Both default to `None`, so existing
  allowlist YAML files keep parsing without changes — a fixture
  reproducing `~/.kvendra/allowlists/github.kvendraai.cli-readonly.yaml`
  is asserted to keep validating in `validator::tests`.
- `Config` gains an `approval: ApprovalConfig` section with
  `mode: ApprovalMode` (default `AskDestructive`),
  `timeout_seconds: u32` (default 30, validated to `[5, 600]`), and
  `cache_ttl_seconds: u32` (default 300). Existing `config.toml`
  files keep loading without changes (all fields default).
- `JsonRpcResponse::error_with_data(...)` constructor added per JSON-RPC
  2.0 §5.1; consumed by the approval block-dispatch path and by the
  new structured `InvalidArgs` response.
- `mcp::server::tools_call` adds the approval hook between the
  allowlist enforcement and the `Started` audit row. Detection layer
  ordering remains: detection → allowlist → approval → audit
  Started → dispatch.
- `approval::policy::lookup_destructive(spec, primitive, operation, args)`
  signature now takes `args: &Value` so it can consult the catalog at
  approval time with the actual runtime arguments.

### Trace

- ROAD-KVD-007: `in-progress` → `done`.
- TXNs (5): TXN-KVD-20260507-002 / 003 / 004 / 005 / 006.
- Commits in main: `db2b0c5` (011), `413a59b` (012), `c761f8f` (013),
  `400ab41` (014), `4ae7d36` (010), and this version bump on top.
- Suite: 78 → **149 passed** (+71 tests), 0 failed, 1 ignored
  (pre-existing slow Argon2id E2E).
- Threat model V7 (ADR-KVD-010) now has four structural barriers
  (allowlist + forbidden methods + approval + audit) plus the keychain
  pattern for `KVENDRA_MCP_PASSWORD`.

### Out of scope (deferred)

- `cargo publish` real to crates.io. The placeholder `kvendra` v0.0.2
  remains the published artifact until `0.1.0` (no `-alpha` suffix) is
  cut.
- GitHub Releases via cargo-dist binaries — deferred to `0.1.0` stable.
- Promotion to `0.1.0` stable — owner decided 2026-05-07 to keep the
  conservative alpha bump until a final smoke E2E with Claude Code
  confirms the bundle in real use.

## [0.1.0-alpha.2] — 2026-05-07

Cleanup release before Sesion 2 (Claude Code MCP integration). Closes
six open ISSUEs from Sesion 1 owner self-validation. No breaking
changes to the CLI surface.

### Fixed

- **ISSUE-KVD-CLI-002** — `kvendra init` now prompts the master password
  twice (entry + confirmation) with constant-time comparison via
  `subtle::ConstantTimeEq` and up to 3 attempts before aborting. Restores
  AC-VAULT-1 from REQ-KVD-002. Standard pattern for Bitwarden / KeePass
  / age — silent typos no longer survive until the first failed unlock.
- **ISSUE-KVD-CLI-003** — `kvendra init` now bootstraps `~/.kvendra/audit.db`
  with a single `kvendra.system / vault_created` event so forensics can
  anchor the audit chain to vault initialisation rather than the
  filesystem mtime of `audit.db`. Implementation lives in the new
  `audit::bootstrap` module.
- **ISSUE-KVD-CLI-004** — `~/.kvendra/sentinel.blob` is created with
  Unix permissions `0600` (was `0644`). Defence-in-depth on top of
  Argon2id — narrows the offline bruteforce surface from local users.
- **ISSUE-KVD-CLI-005** — `~/.kvendra/config.toml` is created with `0600`
  (was `0644`). Protects `vault.master_password_cache`,
  `idle_timeout_minutes`, and `detection.severity` from local-user
  tampering.
- **ISSUE-KVD-CLI-006** — `~/.kvendra/` and its `secrets/`, `allowlists/`,
  `profiles/` subdirectories are created with `0700` (was `0755`).
  Convention shared with `~/.ssh`, `~/.gnupg`, `~/.password-store`,
  `~/.config/sops`. Other local users can no longer enumerate the vault
  layout.
- **ISSUE-KVD-CLI-008** — `kvendra secret validate` enriches its output
  with (a) inline per-operation constraints (`(repos: ...)`,
  `(refs: ...)`, etc. — walker over all 21 `OperationConstraints`
  fields), (b) a unicode `✓` / `✗` mark next to `VALID` / `REJECTED`,
  and (c) an expiration day delta (`(N days remaining)` /
  `(expires today)` / `(expired N days ago)`). Restores AC-ALLOW-2.

### Added

- `kvendra::config::create_dir_secure(path)` — public helper that
  `mkdir -p` plus tightens directory perms to `0700` on Unix.
- `kvendra::config::set_file_mode_secure(path)` — public helper that
  tightens an existing file to `0600` on Unix (no-op elsewhere).
- `kvendra::audit::bootstrap::write_vault_created_event(...)` — emits
  the initial audit row referencing `env!("CARGO_PKG_VERSION")`.
- Unit tests for `cli::init::passwords_match`, `cli::secret::format_constraints`,
  `cli::secret::format_expiration` (5 new tests). Integration test
  `tests/security_and_audit.rs::kvendra_home_perms_are_0700_and_files_are_0600`
  covers home + 3 subdirs + sentinel + config + profile blob + profile
  meta in a single Unix run. Integration test
  `tests/security_and_audit.rs::vault_created_event_persisted_after_init_bootstrap`
  covers the new audit bootstrap.

### Changed

- `cli::init` and `cli::secret::set-allowlist` now route their write
  paths through the new `create_dir_secure` / `set_file_mode_secure`
  helpers; the inline `#[cfg(unix)] PermissionsExt` blocks have been
  removed from the call sites.
- `Vault::create_with_params`, `Vault::reset_password_with_mnemonic`,
  `Vault::save_profile_meta`, and `Vault::put_secret` apply
  `set_file_mode_secure` after every sensitive `fs::write`, so the
  defence-in-depth invariant holds regardless of which entry point
  created the file.

## [0.1.0-alpha.1] — 2026-05-06

Initial Alpha 0.1 MVP release. First real published version of the
Kvendra developer harness CLI.

### Added

- Vault subsystem (`vault/`) with Argon2id KDF, AES-256-GCM AEAD, BIP-39
  mnemonic + 8 numeric one-shot recovery codes, sentinel + session key
  with HKDF-derived audit sub-key.
- 7 canonical MCP primitives + 1 escape hatch (`kvendra.git`,
  `kvendra.github`, `kvendra.npm`, `kvendra.pypi`, `kvendra.aws`,
  `kvendra.http`, `kvendra.shell`, `kvendra.unsafe.raw_token`) wired
  through a sanitising MCP server (`mcp::server::build_sanitized_payload`).
- Allowlist DSL (YAML) + restrictive validator + enforcer.
- Audit log: SQLite (rusqlite bundled, WAL mode) with HMAC-SHA256 chain.
  `audit verify --password-stdin` re-derives the HMAC sub-key
  cross-process from the master password.
- TUI (gated by feature `tui`, default on): dashboard + audit watch.
- Detection layer with `warn` / `error` / `block` severities.
- CLI surface (clap derive): `init`, `unlock`, `lock`, `secret`,
  `primitive`, `mcp serve`, `dashboard`, `audit`, `config`,
  `completion`.
- Cross-platform OS keychain integration (`keyring 3.x`).
- THREAT-MODEL.md (Nivel 2 zero-knowledge target).
- CI matrix workflow.

### Notes

- This release was bundled as `KvendraAI/kvendra-cli` HEAD `9e972dc`.
- The placeholder `kvendra` v0.0.2 on crates.io stays as the published
  artifact until `0.1.0` (no `-alpha` / `-beta`) is cut.
