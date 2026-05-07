# Changelog

All notable changes to the `kvendra` crate are documented here. The format
is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/) with
`-alpha.N` / `-beta.N` pre-release suffixes during the pre-1.0 phase.

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
