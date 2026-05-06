//! `kvendra unlock` — placeholder Pase A.

use crate::error::KvendraResult;
use clap::Args;

#[derive(Debug, Args)]
pub struct UnlockArgs {
    /// Recover via mnemonic (Pase B full flow).
    #[arg(long)]
    pub recover: bool,
}

pub async fn run(_args: UnlockArgs) -> KvendraResult<()> {
    println!("kvendra unlock — Pase A scaffold (full session flow lands in Pase B)");
    Ok(())
}
