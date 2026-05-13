//! `kvendra logout [--workspace <id>]` — REQ-KVD-CLI-004 AC-RESOLVER-5.
//!
//! - Without `--workspace`: locks the local vault (zeroize derived key).
//! - With `--workspace <id>`: deletes `~/.kvendra/sessions/<id>.token`
//!   plus the sidecar `.lock` file. Idempotent.

use crate::config::kvendra_home;
use crate::error::KvendraResult;
use crate::session::SessionState;
use clap::Args;

#[derive(Debug, Args)]
pub struct LogoutArgs {
    /// Workspace id to forget. Without this flag, falls back to vault lock.
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
            // Local-mode logout is the existing vault lock.
            crate::cli::lock::run().await
        }
    }
}
