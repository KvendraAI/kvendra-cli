# Changelog

All notable changes to the `kvendra` crate are documented here. The format
is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/) with
`-alpha.N` / `-beta.N` pre-release suffixes during the pre-1.0 phase.

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
