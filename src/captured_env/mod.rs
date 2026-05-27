//! Anti-captured-env defense for `kvendra unlock` (PAT-KVD-CLI-008).
//!
//! Detects execution inside an MCP client (Claude Code Bash tool, `!`
//! shell escape, Cursor agent, Cline, etc.) and rejects deterministically
//! so the master password never lands in a transcript or process buffer
//! the LLM can read.
//!
//! Three layers, evaluated in order, any failure → reject:
//!   1. **Primary** — open `/dev/tty` (POSIX) / fall back to `IsTerminal`
//!      on stdin/stdout/stderr (Windows). When the parent process captured
//!      stdio there is no controlling terminal for the subprocess.
//!   2. **Defense in depth** — triple `isatty(stdin/stdout/stderr)` plus
//!      `tcgetpgrp == getpgrp` (POSIX). On a captured PTY the foreground
//!      group does not match the subprocess's group.
//!   3. **Error enrichment** — walk the parent ancestry; flag entries that
//!      match known MCP client binaries. Never the primary reject signal
//!      (false positives with tmux/screen launched from a real client are
//!      possible).
//!
//! Validated empirically on 2026-05-18 against Claude Code Bash tool and
//! `!` shell escape (see PAT-KVD-CLI-008 matrix). Windows is shipped at
//! stub level in alpha.1; the physical PoC is tracked separately.

pub mod ancestry;
mod tty;

#[cfg(unix)]
mod tty_unix;

#[cfg(windows)]
mod tty_windows;

pub use ancestry::{
    AncestorInfo, KNOWN_MCP_CLIENT_NAMES, detect_mcp_client_ancestors, walk_ancestors,
};
pub use tty::{TtyHandle, UnlockRejection, ensure_real_terminal};
