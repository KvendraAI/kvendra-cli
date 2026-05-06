//! `kvendra lock` — explicit zeroize of the in-memory session.

use crate::config::kvendra_home;
use crate::error::KvendraResult;
use crate::vault::Vault;

pub async fn run() -> KvendraResult<()> {
    let home = kvendra_home()?;
    let vault = Vault::new(home);
    vault.lock();
    println!("Vault locked. Session key zeroized.");
    Ok(())
}
