//! `kvendra lock` — terminate the local session.
//!
//! Two-part teardown (REQ-KVD-CLI-011):
//!   1. Zeroize the in-memory `SessionKey` of any vault instance that
//!      happens to be alive in this process.
//!   2. Delete `~/.kvendra/sessions/active.blob` + sidecar so the
//!      subprocess `kvendra mcp serve` cannot start a fresh MCP session
//!      from a cached blob until the user runs `kvendra unlock` again.
//!
//! Does **not** require a TTY — by design `lock` is callable from CI
//! scripts, logout hooks, or system shutdown handlers. It does not affect
//! MCP subprocesses already running with the derived key in their own
//! RAM — those keep operating until their session's TTL expires (or the
//! user kills them); `lock` only blocks future starts.

use crate::audit::FLAG_UNLOCK_LOCKED_MANUAL;
use crate::config::kvendra_home;
use crate::error::KvendraResult;
use crate::session::local::delete as session_delete;
use crate::vault::Vault;

pub async fn run() -> KvendraResult<()> {
    let home = kvendra_home()?;
    let vault = Vault::new(home.clone());
    vault.lock();
    let existed = session_delete(&home)?;
    // Audit row persistence is intentionally skipped: `lock` runs without
    // a master password, so no HMAC sub-key is available. Same gap pattern
    // as ADR-KVD-020 AC-USE-KEYCHAIN-8 — surface the flag via tracing so
    // log aggregators still see the event.
    tracing::info!(
        target: "kvendra::lock",
        flag = FLAG_UNLOCK_LOCKED_MANUAL,
        blob_existed = existed,
        "session blob removal complete"
    );
    if existed {
        println!("Session terminated. Active blob removed.");
    } else {
        println!("Vault locked. (No active session blob to remove.)");
    }
    Ok(())
}
