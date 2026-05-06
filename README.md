# kvendra

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

## Install (when released)

```bash
# Cargo (Rust toolchain — canonical)
cargo install kvendra

# Homebrew (macOS / Linux)
brew install KvendraAI/kvendra/kvendra

# npm wrapper (Node)
npm install -g @kvendra/cli

# pip wrapper (Python)
pip install kvendra
```

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

## Links

- Site: [kvendra.com](https://kvendra.com)
- Org: [github.com/KvendraAI](https://github.com/KvendraAI)
- Contact: hello@kvendra.ai

## License

Apache-2.0 — see [LICENSE](./LICENSE).

Copyright 2026 Kvendra.
