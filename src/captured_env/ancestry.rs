//! Parent-process ancestry walk. Cross-platform implementation without
//! adding `sysinfo` to the dependency tree (per ADR-KVD-029 / FASE 0
//! decision D2 = ad-hoc per platform).
//!
//! POSIX: start from `getppid()`, then read each parent's `comm` via
//! `ps -p <pid> -o comm=` (works identically on macOS and Linux without
//! `/proc` parsing) and follow `ps -p <pid> -o ppid=`.
//!
//! Windows: stub — returns an empty vector in alpha.1. Full
//! `CreateToolhelp32Snapshot` walk lands with the physical PoC.
//!
//! **Used only for error enrichment, never as a primary reject signal.**
//! `tmux`/`screen` launched from a real MCP client would put `claude` on
//! the chain even though the inner shell is a perfectly legitimate
//! terminal — the tty layers handle the real decision.

use serde::Serialize;

/// Known MCP client binary names (process `comm`). Lower-case match, the
/// walker compares case-insensitively because macOS sometimes capitalises
/// the bundle name (`Cursor`).
pub const KNOWN_MCP_CLIENT_NAMES: &[&str] = &[
    "claude",
    "claude-code",
    "cursor",
    "cursor.app",
    "cline",
    "continue",
];

/// One entry of the parent chain.
#[derive(Debug, Clone, Serialize)]
pub struct AncestorInfo {
    pub level: u8,
    pub pid: u32,
    pub comm: String,
    pub is_known_mcp_client: bool,
}

/// Walk up the parent chain, capping at `max_depth` levels. Level 0 is
/// the immediate parent of the current process. Failures (PID missing,
/// `ps` not available, depth exhausted) stop the walk silently rather
/// than escalating — the function is best-effort enrichment.
pub fn walk_ancestors(max_depth: u8) -> Vec<AncestorInfo> {
    #[cfg(unix)]
    {
        let mut out: Vec<AncestorInfo> = Vec::new();
        let mut current = unsafe { libc::getppid() };
        for level in 0..max_depth {
            if current <= 1 {
                break;
            }
            let pid_u = current as u32;
            let Some(comm) = read_comm_unix(current) else {
                break;
            };
            let is_mcp = is_known_mcp_client(&comm);
            out.push(AncestorInfo {
                level,
                pid: pid_u,
                comm,
                is_known_mcp_client: is_mcp,
            });
            let Some(ppid) = read_ppid_unix(current) else {
                break;
            };
            if ppid <= 1 {
                break;
            }
            current = ppid;
        }
        out
    }
    #[cfg(windows)]
    {
        // alpha.1 stub — see ISSUE-IMPL-WINDOWS-POC.
        let _ = max_depth;
        Vec::new()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = max_depth;
        Vec::new()
    }
}

/// Return only the ancestors that look like an MCP client. Convenience
/// wrapper used by `print_unlock_rejection` to keep error messages short.
pub fn detect_mcp_client_ancestors() -> Vec<AncestorInfo> {
    walk_ancestors(6)
        .into_iter()
        .filter(|a| a.is_known_mcp_client)
        .collect()
}

#[cfg(any(unix, test))]
fn is_known_mcp_client(comm: &str) -> bool {
    let lower = comm.to_ascii_lowercase();
    KNOWN_MCP_CLIENT_NAMES.iter().any(|name| lower == *name)
}

#[cfg(unix)]
fn read_comm_unix(pid: libc::pid_t) -> Option<String> {
    use std::process::Command;
    let out = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

#[cfg(unix)]
fn read_ppid_unix(pid: libc::pid_t) -> Option<libc::pid_t> {
    use std::process::Command;
    let out = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "ppid="])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&out.stdout).trim().to_string();
    raw.parse::<libc::pid_t>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_mcp_clients_match_case_insensitive() {
        assert!(is_known_mcp_client("claude"));
        assert!(is_known_mcp_client("CLAUDE"));
        assert!(is_known_mcp_client("Cursor"));
        assert!(is_known_mcp_client("cursor.app"));
        assert!(!is_known_mcp_client("bash"));
        assert!(!is_known_mcp_client("nodejs"));
    }

    #[test]
    fn walk_ancestors_returns_some_chain_when_run_under_cargo_test() {
        // We cannot assert specific contents (depends on how the test runs)
        // but the walk must terminate and return at most max_depth entries
        // without panicking.
        let chain = walk_ancestors(6);
        assert!(chain.len() <= 6);
        // levels are monotonically increasing from 0
        for (i, a) in chain.iter().enumerate() {
            assert_eq!(a.level as usize, i);
        }
    }

    #[test]
    fn walk_ancestors_terminates_at_zero_depth() {
        let chain = walk_ancestors(0);
        assert!(chain.is_empty());
    }
}
