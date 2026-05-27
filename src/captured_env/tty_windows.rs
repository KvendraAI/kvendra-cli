//! Windows stub for the TTY guard (D1 = B per ADR-KVD-029 / FASE 0
//! decisions). Full `CONIN$` + `GetConsoleProcessList` enforcement lands
//! with the physical PoC tracked in ISSUE-IMPL-WINDOWS-POC.
//!
//! In alpha.1 we ship a best-effort detection using `std::io::IsTerminal`
//! (stable since Rust 1.70, zero new crate dependency). When stdio is a
//! terminal we proceed; otherwise we reject with the same canonical
//! `StdioNotOwned` variant the POSIX path uses, so the error UX and the
//! audit flag match across platforms.

#![cfg(windows)]

use crate::captured_env::ancestry::walk_ancestors;
use crate::captured_env::tty::{TtyHandle, UnlockRejection, new_windows_handle};
use std::io::IsTerminal;

pub fn ensure_real_terminal_windows() -> Result<TtyHandle, UnlockRejection> {
    let stdin_tty = std::io::stdin().is_terminal();
    let stdout_tty = std::io::stdout().is_terminal();
    let stderr_tty = std::io::stderr().is_terminal();
    if !stdin_tty {
        return Err(UnlockRejection::StdioNotOwned {
            ancestors: walk_ancestors(6),
            detail: "stdin",
        });
    }
    if !stdout_tty {
        return Err(UnlockRejection::StdioNotOwned {
            ancestors: walk_ancestors(6),
            detail: "stdout",
        });
    }
    if !stderr_tty {
        return Err(UnlockRejection::StdioNotOwned {
            ancestors: walk_ancestors(6),
            detail: "stderr",
        });
    }
    Ok(new_windows_handle())
}
