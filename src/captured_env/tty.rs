//! Cross-platform façade for the TTY guard. Delegates to `tty_unix` or
//! `tty_windows` and exposes a single `TtyHandle` the caller (`cli::unlock`)
//! reads the master password from.

use crate::captured_env::ancestry::AncestorInfo;
#[cfg(not(any(unix, windows)))]
use crate::captured_env::ancestry::walk_ancestors;
use std::io::Write;

/// Reason `ensure_real_terminal` refused. Each variant maps to one canonical
/// audit flag in `audit::events`.
#[derive(Debug)]
pub enum UnlockRejection {
    /// `/dev/tty` (or `CONIN$`) could not be opened — the process has no
    /// controlling terminal, almost certainly because the parent captured
    /// stdio (Bash tool, `!` escape, CI runner).
    NoControllingTty { ancestors: Vec<AncestorInfo> },
    /// stdin / stdout / stderr is not a terminal, or the foreground pgrp
    /// does not match — strong evidence the stdio was redirected by a
    /// captured environment.
    StdioNotOwned {
        ancestors: Vec<AncestorInfo>,
        detail: &'static str,
    },
}

impl UnlockRejection {
    pub fn ancestors(&self) -> &[AncestorInfo] {
        match self {
            UnlockRejection::NoControllingTty { ancestors } => ancestors,
            UnlockRejection::StdioNotOwned { ancestors, .. } => ancestors,
        }
    }

    /// Canonical audit flag for this rejection (matches `audit::events`).
    pub fn audit_flag(&self) -> &'static str {
        match self {
            UnlockRejection::NoControllingTty { .. } => "unlock_rejected_no_controlling_tty",
            UnlockRejection::StdioNotOwned { .. } => "unlock_rejected_stdio_not_owned",
        }
    }

    /// Render a user-facing error message including detected MCP
    /// ancestors. Caller writes this to stderr; never includes any secret.
    pub fn render(&self) -> String {
        let header = match self {
            UnlockRejection::NoControllingTty { .. } => {
                "kvendra unlock: no controlling terminal detected."
            }
            UnlockRejection::StdioNotOwned { detail, .. } => match *detail {
                "stdin" | "stdout" | "stderr" => {
                    "kvendra unlock: stdio is not an interactive terminal."
                }
                "foreground_group_mismatch" => {
                    "kvendra unlock: terminal foreground group does not match this process."
                }
                _ => "kvendra unlock: stdio not owned by this process.",
            },
        };
        let mut s = String::new();
        s.push_str(header);
        s.push_str("\n\n");
        s.push_str(
            "This command must be executed in YOUR OWN terminal, not inside\n\
             Claude Code (or another MCP client). The master password must\n\
             never appear in the chat or be visible to an AI assistant.\n\n\
             How to proceed:\n  \
             1. Open a terminal application directly (Terminal.app, iTerm,\n     \
                Windows Terminal, gnome-terminal, etc.)\n  \
             2. Run:  kvendra unlock\n  \
             3. Return to your MCP client and retry your operation.\n",
        );
        let mcp_ancestors: Vec<&AncestorInfo> = self
            .ancestors()
            .iter()
            .filter(|a| a.is_known_mcp_client)
            .collect();
        if !mcp_ancestors.is_empty() {
            s.push_str("\nDetected MCP client ancestor(s):\n");
            for a in mcp_ancestors {
                s.push_str(&format!("  L{} pid={} comm='{}'\n", a.level, a.pid, a.comm));
            }
        }
        s.push_str("\nSee https://docs.kvendra.com/cli/unlock-security for details.\n");
        s
    }
}

/// Opaque handle bound to the real controlling terminal. Used to read the
/// master password without going through `stdin` (which may have been
/// captured by the parent).
pub struct TtyHandle {
    #[cfg(unix)]
    inner: TtyHandleInner,
    #[cfg(windows)]
    inner: TtyHandleWindows,
}

#[cfg(unix)]
struct TtyHandleInner {
    file: std::fs::File,
}

#[cfg(windows)]
struct TtyHandleWindows;

impl TtyHandle {
    /// Read a single line from the controlling terminal with the local
    /// echo disabled. Caller-supplied `prompt` is written to the same
    /// terminal (or stderr fallback on Windows) immediately before the
    /// read.
    pub fn read_password(&self, prompt: &str) -> std::io::Result<String> {
        #[cfg(unix)]
        {
            use std::io::{BufRead, BufReader};
            use std::os::unix::io::AsRawFd;

            let fd = self.inner.file.as_raw_fd();

            // Save original termios so we can restore on Drop (including
            // panic / Ctrl-C). `rpassword::read_password()` does this for
            // stdin, but `read_password_from_bufread` does NOT — it just
            // reads bytes, leaving local echo on. Manual `tcsetattr` is
            // required when we feed it `/dev/tty`.
            let mut orig: libc::termios = unsafe { std::mem::zeroed() };
            // SAFETY: `fd` is a valid open file descriptor (we own it).
            let rc = unsafe { libc::tcgetattr(fd, &mut orig) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut quiet = orig;
            quiet.c_lflag &= !(libc::ECHO);
            let rc = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }

            struct TermiosGuard {
                fd: std::os::unix::io::RawFd,
                orig: libc::termios,
            }
            impl Drop for TermiosGuard {
                fn drop(&mut self) {
                    // SAFETY: same fd we got from `tcgetattr` originally.
                    unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig) };
                }
            }
            let _guard = TermiosGuard { fd, orig };

            // Write prompt directly to the tty so it does not pollute
            // stdout (which the parent may have captured).
            let mut writer = self.inner.file.try_clone().map_err(std::io::Error::other)?;
            writer.write_all(prompt.as_bytes())?;
            writer.flush()?;

            // Read a single line from the tty.
            let reader = self.inner.file.try_clone().map_err(std::io::Error::other)?;
            let mut buf = BufReader::new(reader);
            let mut password = String::new();
            buf.read_line(&mut password)?;

            // Echo is off, so the user's Enter was swallowed silently —
            // print a newline so the next prompt does not glue to the cursor.
            writer.write_all(b"\n")?;
            writer.flush().ok();

            // Strip the trailing newline (and the CR if the tty uses CRLF).
            if password.ends_with('\n') {
                password.pop();
            }
            if password.ends_with('\r') {
                password.pop();
            }
            Ok(password)
        }
        #[cfg(windows)]
        {
            let _ = &self.inner;
            // alpha.1 stub — falls back to stdin prompt. The Windows
            // physical PoC will replace this with CONIN$ access.
            rpassword::prompt_password(prompt)
        }
    }
}

/// Run the 3-layer defense and return a `TtyHandle` on success. The caller
/// (`cli::unlock`) reads the password from the handle, not from `stdin`.
pub fn ensure_real_terminal() -> Result<TtyHandle, UnlockRejection> {
    #[cfg(unix)]
    {
        crate::captured_env::tty_unix::ensure_real_terminal_unix()
    }
    #[cfg(windows)]
    {
        crate::captured_env::tty_windows::ensure_real_terminal_windows()
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(UnlockRejection::NoControllingTty {
            ancestors: walk_ancestors(6),
        })
    }
}

/// Constructor used by the platform-specific modules to wrap a successful
/// TTY open.
#[cfg(unix)]
pub(super) fn new_unix_handle(file: std::fs::File) -> TtyHandle {
    TtyHandle {
        inner: TtyHandleInner { file },
    }
}

#[cfg(windows)]
pub(super) fn new_windows_handle() -> TtyHandle {
    TtyHandle {
        inner: TtyHandleWindows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_actionable_instructions() {
        let rej = UnlockRejection::NoControllingTty {
            ancestors: Vec::new(),
        };
        let text = rej.render();
        assert!(text.contains("kvendra unlock"));
        assert!(text.contains("YOUR OWN terminal"));
        assert!(text.contains("https://docs.kvendra.com/cli/unlock-security"));
    }

    #[test]
    fn render_lists_known_mcp_ancestors() {
        let rej = UnlockRejection::NoControllingTty {
            ancestors: vec![
                AncestorInfo {
                    level: 0,
                    pid: 42,
                    comm: "bash".into(),
                    is_known_mcp_client: false,
                },
                AncestorInfo {
                    level: 1,
                    pid: 100,
                    comm: "claude".into(),
                    is_known_mcp_client: true,
                },
            ],
        };
        let text = rej.render();
        assert!(text.contains("claude"));
        assert!(text.contains("pid=100"));
    }

    #[test]
    fn audit_flag_is_canonical() {
        let r1 = UnlockRejection::NoControllingTty {
            ancestors: Vec::new(),
        };
        let r2 = UnlockRejection::StdioNotOwned {
            ancestors: Vec::new(),
            detail: "stdin",
        };
        assert_eq!(r1.audit_flag(), "unlock_rejected_no_controlling_tty");
        assert_eq!(r2.audit_flag(), "unlock_rejected_stdio_not_owned");
    }
}
