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

## Links

- Site: [kvendra.com](https://kvendra.com)
- Org: [github.com/KvendraAI](https://github.com/KvendraAI)
- Contact: hello@kvendra.ai

## License

Apache-2.0 — see [LICENSE](./LICENSE).

Copyright 2026 Kvendra.
