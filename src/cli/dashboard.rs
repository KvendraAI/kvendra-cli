//! `kvendra dashboard` — global TUI overview entrypoint.

use crate::config::kvendra_home;
use crate::error::KvendraResult;

pub async fn run() -> KvendraResult<()> {
    let home = kvendra_home()?;
    crate::tui::dashboard::run(home).await
}
