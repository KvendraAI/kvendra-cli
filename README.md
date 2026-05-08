# kvendra

[![CI](https://github.com/KvendraAI/kvendra-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/KvendraAI/kvendra-cli/actions/workflows/ci.yml)
[![E2E Smoke](https://github.com/KvendraAI/kvendra-cli/actions/workflows/e2e-smoke.yml/badge.svg)](https://github.com/KvendraAI/kvendra-cli/actions/workflows/e2e-smoke.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/kvendra.svg)](https://crates.io/crates/kvendra)

**The harness for advanced engineering.**

Developer CLI for Kvendra. Manage workspaces, knowledge bases, skills, and pipelines from the terminal.

Built in Rust. Open source under Apache-2.0. Repository: [`KvendraAI/kvendra-cli`](https://github.com/KvendraAI/kvendra-cli).

## Status

Pre-alpha. Placeholder crate — the `kvendra` binary does not yet exist. Namespace reserved on crates.io ahead of the Alpha 0.1 MVP.

## What will live here

- `kvendra` command-line tool for workspace, KB, skills, and pipeline operations.
- MCP capability broker (server stdio) for Claude Code, Cursor, Cline, Continue, and other MCP clients.
- Zero-knowledge credential vault (Argon2id + AES-256-GCM, client-side).
- OAuth device flow plus API token authentication.
- Local-first operations with sync to the platform.

## Install

### From source (`cargo install`) — recommended for v0.1.0

```bash
cargo install --git https://github.com/KvendraAI/kvendra-cli kvendra
kvendra --version
```

Works on **macOS, Linux, and Windows** (msvc). All structural security
features work cross-platform:

- Capability-based MCP broker (7 primitives + escape hatch)
- Zero-knowledge vault (Argon2id + AES-256-GCM)
- Allowlist YAML signed with HMAC sub-key (`kvendra/allowlist-hmac/v1`)
- Audit log HMAC-chained with verification (`kvendra/audit-hmac/v1`)
- Transport separation (CLI=TTY, MCP=approval)
- Catalog destructive ops with consent gate (modal macOS, dialog Windows/Linux)

### Pre-built binaries (GitHub Releases)

Download the unsigned binary for your platform from the [latest release](
https://github.com/KvendraAI/kvendra-cli/releases/latest):

- **macOS**: Gatekeeper may show a warning ("unidentified developer").
  Bypass with `xattr -d com.apple.quarantine kvendra` or via System
  Settings → Privacy & Security → "Open anyway".
- **Windows**: SmartScreen may show "Unknown publisher". Click "More info"
  → "Run anyway".
- **Linux**: `chmod +x kvendra && ./kvendra --version`.

### What's included in v0.1.0

- ✓ Capability-based MCP broker (7 primitives + escape hatch)
- ✓ Zero-knowledge vault (Argon2id + AES-256-GCM)
- ✓ Allowlist YAML signed with HMAC sub-key
- ✓ Audit log HMAC-chained with verification
- ✓ Transport separation (CLI=TTY, MCP=approval)
- ✓ Catalog destructive ops with consent gate
- ✓ 284+ tests, multi-OS CI (Ubuntu / macOS / Windows)

### What's NOT in v0.1.0 (planned for v0.2.0+)

- **Touch ID-protected MCP password storage** — requires signed binary.
  Planned for v0.2.0 "Mac compatible" release. Current default uses
  `master_password_cache = "ram-only"` with consent modal on each
  destructive op (secure in practice, see [`PAT-KVD-CLI-001` in our
  KB](https://github.com/KvendraAI) for the full reasoning).
- **Apple notarization, Homebrew formula** — v0.2.0.
- **Windows Authenticode signing, Linux GPG signing** — v0.3.0+.

For the full install guide and platform-specific notes, see
[`docs/install.md`](docs/install.md). For the security model and trust
narrative, see [`docs/security.md`](docs/security.md).

## Non-interactive use (CI / scripts)

The vault subcommands prompt by default but accept the master password and
related material from environment variables for unattended use. The names
below are the canonical ones honoured by the binary; older drafts of the
docs referenced `KVENDRA_UNLOCK_PASSWORD` / `KVENDRA_RECOVER_MNEMONIC` /
`KVENDRA_RECOVER_NEW_PASSWORD` — those names were never wired and are NOT
recognised. Use the table:

| Subcommand | Env var | Purpose |
|---|---|---|
| `kvendra init` | `KVENDRA_INIT_PASSWORD` | Master password for fresh vault |
| `kvendra init` | `KVENDRA_INIT_CONFIRM_CODE` | Pre-confirmation numeric code |
| `kvendra unlock` | `KVENDRA_PASSWORD` | Master password to unlock the session |
| `kvendra recover` | `KVENDRA_RECOVERY_MNEMONIC` | 12-word BIP-39 phrase |
| `kvendra recover` | `KVENDRA_NEW_PASSWORD` | Replacement master password |
| `kvendra mcp serve` | `KVENDRA_MCP_PASSWORD` | Master password for embedded unlock |
| `kvendra audit --verify` | `KVENDRA_PASSWORD` | Master password for cross-process verify |
| any subcommand | `KVENDRA_HOME` | Override `~/.kvendra/` for testing/sandboxing |

`kvendra audit --verify` also accepts `--password-stdin` (recommended for
scripts: pipe the password on stdin, no env var pollution).

## MCP transport — approval gate (v0.1.0)

When the broker runs under MCP transport (spawned by Claude Code, Cursor,
Cline, ...), every destructive op (write / push / destroy in the catalog)
goes through a consent gate before dispatch. In v0.1.0 the gate uses an
OS-mediated modal dialog on macOS (`osascript display dialog`) and a
native dialog on Windows / Linux — no `/dev/tty` interaction, mitigating
the TTY-hijack pattern documented in `PAT-KVD-007`.

The default `master_password_cache = "ram-only"` keeps the master
password in process memory only after `kvendra unlock` (or the
`KVENDRA_MCP_PASSWORD` env var path used by IDE/Desktop clients today).
No silent automated bypass of the consent gate is possible — see
`PAT-KVD-CLI-001` in the project KB for the full reasoning and audit-log
evidence.

**Touch ID-protected MCP password storage** (every read gated by the OS
biometric prompt) requires a signed binary (Apple Developer ID) and is
**deferred to v0.2.0** (`ROAD-KVD-CLI-002`). v0.1.0 ships unsigned and
uses the consent-modal path on all platforms.

For the full security model, see [`docs/security.md`](docs/security.md).

## Links

- Site: [kvendra.com](https://kvendra.com)
- Org: [github.com/KvendraAI](https://github.com/KvendraAI)
- Contact: hello@kvendra.ai

## License

Apache-2.0 — see [LICENSE](./LICENSE).

Copyright 2026 Kvendra.
