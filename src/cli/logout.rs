//! `kvendra logout [--workspace <id>]` — REQ-KVD-CLI-004 AC-RESOLVER-5.
//!
//! - Without `--workspace`: clears every active workspace session, then
//!   locks the local vault (zeroize derived key).
//! - With `--workspace <id>`: deletes `~/.kvendra/sessions/<id>.token`
//!   plus the sidecar `.lock` file. Idempotent.

use crate::config::kvendra_home;
use crate::error::KvendraResult;
use crate::session::{SessionState, list_active_sessions};
use clap::Args;

#[derive(Debug, Args)]
pub struct LogoutArgs {
    /// Workspace id to forget. Without this flag, every active workspace
    /// session is cleared and the local vault is locked.
    #[arg(long)]
    pub workspace: Option<String>,
}

pub async fn run(args: LogoutArgs) -> KvendraResult<()> {
    let home = kvendra_home()?;
    match args.workspace {
        Some(ws_id) => {
            SessionState::delete(&home, &ws_id)?;
            eprintln!("Workspace session '{ws_id}' cleared.");
            Ok(())
        }
        None => {
            let active = list_active_sessions(&home).unwrap_or_default();
            for ws_id in &active {
                if let Err(e) = SessionState::delete(&home, ws_id) {
                    eprintln!("Warning: failed to clear session '{ws_id}': {e}");
                } else {
                    eprintln!("Workspace session '{ws_id}' cleared.");
                }
            }
            // Best-effort clear of the Pro tier id_token sidecar (added in
            // 0.4.0-alpha.4 for ISSUE-KVD-CLI-940018). `pro.token` itself is
            // not deleted here — it was never deleted by `logout` historically
            // and the operator may want to keep the backup bearer alive; only
            // the id_token sidecar (UX-only) is cleaned up to avoid leaving
            // stale email/issuer claims behind after a session clear.
            let id_token_path = home.join("sessions/pro.id_token");
            let _ = std::fs::remove_file(&id_token_path);
            crate::cli::lock::run().await
        }
    }
}
