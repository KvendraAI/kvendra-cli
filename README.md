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

## MCP auto-unlock with biometric ACL (macOS)

When the broker is launched as an MCP subprocess by an IDE / Desktop client
(Claude Code, Cursor, Cline, ...), passing the master password via the
`KVENDRA_MCP_PASSWORD` env var leaves it in plaintext inside `~/.claude.json`
(and equivalents) — readable by any process running as your user. The
recommended setup on macOS now uses the OS keychain with a `userPresence`
access-control attribute so every read triggers TouchID (or the modal
password popup if biometric hardware is absent), and the prompt is
OS-mediated rather than written to `/dev/tty` (mitigates the TTY-hijack
pattern documented in PAT-KVD-007).

```bash
# 1. Store the master password in the OS keychain (TouchID popup will
#    appear here so the OS can attach the userPresence ACL).
kvendra config mcp-password enable

# 2. Migrate any existing client config (~/.claude.json etc.) to use the
#    new flag. A `*.bak.<timestamp>` of the original is written next to it.
kvendra config mcp-password migrate-to-keychain-acl --client claude-code
```

Post-migration, your MCP client config should look like:

```json
{
  "mcpServers": {
    "kvendra": {
      "command": "kvendra",
      "args": ["mcp", "serve", "--use-keychain"]
    }
  }
}
```

When the client spawns the broker, `--use-keychain` reads the password
from the keychain entry; the OS shows a TouchID / password popup once
per session and the broker proceeds to unlock the vault. No env var, no
wrapper script, no `/dev/tty` interaction.

### Platform support

| Platform | `enable` / `migrate-to-keychain-acl` / `--use-keychain` | Workaround |
|---|---|---|
| macOS (with TouchID) | ✓ TouchID popup | — |
| macOS (no TouchID) | ✓ OS modal password popup | — |
| Windows | ✗ rejects with clear error | continue using `KVENDRA_MCP_PASSWORD` env var |
| Linux | ✗ rejects with clear error | continue using `KVENDRA_MCP_PASSWORD` env var |

The keychain-ACL flow is **macOS only in the current release**. On
Windows and Linux the subcommands reject explicitly so we do not create
a false sense of biometric protection — a `keyring`-base item without
an enforced ACL would still be readable by any user-level process.
Cross-platform hardening (Windows Hello, Linux PolKit / `pam`) is
tracked in ROAD-KVD-008 and will land in a follow-up release.

## Links

- Site: [kvendra.com](https://kvendra.com)
- Org: [github.com/KvendraAI](https://github.com/KvendraAI)
- Contact: hello@kvendra.ai

## License

Apache-2.0 — see [LICENSE](./LICENSE).

Copyright 2026 Kvendra.
