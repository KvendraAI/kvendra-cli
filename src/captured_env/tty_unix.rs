//! POSIX implementation of the TTY guard (PAT-KVD-CLI-008 layers 1+2).

#![cfg(unix)]

use crate::captured_env::ancestry::walk_ancestors;
use crate::captured_env::tty::{TtyHandle, UnlockRejection, new_unix_handle};
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;

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
    unsafe {
        if libc::isatty(libc::STDIN_FILENO) == 0 {
            return Err(UnlockRejection::StdioNotOwned {
                ancestors: walk_ancestors(6),
                detail: "stdin",
            });
        }
        if libc::isatty(libc::STDOUT_FILENO) == 0 {
            return Err(UnlockRejection::StdioNotOwned {
                ancestors: walk_ancestors(6),
                detail: "stdout",
            });
        }
        if libc::isatty(libc::STDERR_FILENO) == 0 {
            return Err(UnlockRejection::StdioNotOwned {
                ancestors: walk_ancestors(6),
                detail: "stderr",
            });
        }
        let fg = libc::tcgetpgrp(file.as_raw_fd());
        let ours = libc::getpgrp();
        if fg < 0 || fg != ours {
            return Err(UnlockRejection::StdioNotOwned {
                ancestors: walk_ancestors(6),
                detail: "foreground_group_mismatch",
            });
        }
    }

    Ok(new_unix_handle(file))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Under `cargo test`, the test harness redirects stdio (no controlling
    /// terminal in the captured rig). The defense must reject — this is
    /// the same signal Claude Code Bash tool produces.
    #[test]
    fn rejects_under_cargo_test_harness() {
        let r = ensure_real_terminal_unix();
        assert!(
            r.is_err(),
            "cargo test runs without a controlling terminal — must reject"
        );
    }

    /// AC-CAPTURED-ENV-1 and -2 (PAT-KVD-CLI-008): the rejection in a
    /// captured environment must be deterministic. Same context, same
    /// reject variant (modulo whether `/dev/tty` exists at all).
    #[test]
    fn rejection_is_deterministic_under_cargo_test() {
        fn variant_tag(r: &Result<TtyHandle, UnlockRejection>) -> &'static str {
            match r {
                Ok(_) => "ok",
                Err(UnlockRejection::NoControllingTty { .. }) => "no_controlling_tty",
                Err(UnlockRejection::StdioNotOwned { .. }) => "stdio_not_owned",
            }
        }
        let r1 = ensure_real_terminal_unix();
        let r2 = ensure_real_terminal_unix();
        let t1 = variant_tag(&r1);
        let t2 = variant_tag(&r2);
        assert_eq!(
            t1, t2,
            "rejection variant must be deterministic across repeated calls"
        );
        assert_ne!(t1, "ok", "cargo test must NOT be a real terminal");
    }
}
