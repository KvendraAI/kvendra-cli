//! POSIX implementation of the TTY guard (PAT-KVD-CLI-008 layers 1+2).

#![cfg(unix)]

use crate::captured_env::ancestry::walk_ancestors;
use crate::captured_env::tty::{TtyHandle, UnlockRejection, new_unix_handle};
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;

/// Pure, syscall-free classification of the layer-2 (isatty + foreground
/// pgrp) checks. Extracted so the decision logic is hermetically testable
/// without depending on the test process's real controlling terminal
/// (ISSUE-KVD-CLI-6EA6D4). `ensure_real_terminal_unix` gathers the real probe
/// values and delegates here — production behaviour is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TerminalClass {
    Ok,
    /// stdin/stdout/stderr not owned, or foreground process group mismatch.
    StdioNotOwned(&'static str),
}

pub(crate) fn classify_terminal(
    stdin_tty: bool,
    stdout_tty: bool,
    stderr_tty: bool,
    fg_pgrp: i32,
    our_pgrp: i32,
) -> TerminalClass {
    if !stdin_tty {
        return TerminalClass::StdioNotOwned("stdin");
    }
    if !stdout_tty {
        return TerminalClass::StdioNotOwned("stdout");
    }
    if !stderr_tty {
        return TerminalClass::StdioNotOwned("stderr");
    }
    if fg_pgrp < 0 || fg_pgrp != our_pgrp {
        return TerminalClass::StdioNotOwned("foreground_group_mismatch");
    }
    TerminalClass::Ok
}

pub fn ensure_real_terminal_unix() -> Result<TtyHandle, UnlockRejection> {
    // Capa 1 — open /dev/tty. ENXIO when the process has no controlling
    // terminal (the canonical signal for "captured environment").
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| UnlockRejection::NoControllingTty {
            ancestors: walk_ancestors(6),
        })?;

    // Capa 2 — triple isatty + tcgetpgrp ownership.
    // SAFETY: file descriptors are valid for the duration of the call;
    // we only read process-table state from libc.
    let class = unsafe {
        classify_terminal(
            libc::isatty(libc::STDIN_FILENO) == 1,
            libc::isatty(libc::STDOUT_FILENO) == 1,
            libc::isatty(libc::STDERR_FILENO) == 1,
            libc::tcgetpgrp(file.as_raw_fd()),
            libc::getpgrp(),
        )
    };

    match class {
        TerminalClass::Ok => Ok(new_unix_handle(file)),
        TerminalClass::StdioNotOwned(detail) => Err(UnlockRejection::StdioNotOwned {
            ancestors: walk_ancestors(6),
            detail,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests exercise the pure `classify_terminal` core with synthetic
    // probe values, so they are HERMETIC: deterministic regardless of whether
    // the test process has a real controlling terminal (ISSUE-KVD-CLI-6EA6D4).
    // The previous tests called `ensure_real_terminal_unix()` directly and
    // depended on `cargo test` running without a real terminal — which is false
    // in an interactive shell, where the libc probes succeed and the function
    // returned `Ok`, flaking the assertion.

    /// A captured environment (any stdio fd not a TTY) must reject — the same
    /// signal the Claude Code Bash tool / CI produces.
    #[test]
    fn captured_env_rejects_when_stdio_not_a_tty() {
        assert_eq!(
            classify_terminal(false, true, true, 100, 100),
            TerminalClass::StdioNotOwned("stdin")
        );
        assert_eq!(
            classify_terminal(true, false, true, 100, 100),
            TerminalClass::StdioNotOwned("stdout")
        );
        assert_eq!(
            classify_terminal(true, true, false, 100, 100),
            TerminalClass::StdioNotOwned("stderr")
        );
    }

    /// Foreground process-group mismatch (or unavailable) must reject.
    #[test]
    fn foreground_group_mismatch_rejects() {
        assert_eq!(
            classify_terminal(true, true, true, 200, 100),
            TerminalClass::StdioNotOwned("foreground_group_mismatch")
        );
        assert_eq!(
            classify_terminal(true, true, true, -1, 100),
            TerminalClass::StdioNotOwned("foreground_group_mismatch")
        );
    }

    /// A genuine interactive terminal (all stdio TTYs + foreground group owned)
    /// must be accepted.
    #[test]
    fn real_terminal_is_accepted() {
        assert_eq!(classify_terminal(true, true, true, 100, 100), TerminalClass::Ok);
    }

    /// AC-CAPTURED-ENV-1/-2 (PAT-KVD-CLI-008): classification is deterministic
    /// for the same inputs.
    #[test]
    fn classification_is_deterministic() {
        let inputs = (true, false, true, 100, 100);
        let a = classify_terminal(inputs.0, inputs.1, inputs.2, inputs.3, inputs.4);
        let b = classify_terminal(inputs.0, inputs.1, inputs.2, inputs.3, inputs.4);
        assert_eq!(a, b, "same inputs must yield the same classification");
        assert_ne!(a, TerminalClass::Ok, "a captured env must not classify as Ok");
    }
}
