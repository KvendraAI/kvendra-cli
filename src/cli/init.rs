//! `kvendra init` — vault bootstrap.

use crate::config::{Config, ensure_layout, kvendra_home};
use crate::error::KvendraResult;
use crate::vault::recovery::{generate_codes, generate_mnemonic};
use clap::Args;

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Skip the interactive verification step (testing only).
    #[arg(long)]
    pub no_verify: bool,
}

pub async fn run(_args: InitArgs) -> KvendraResult<()> {
    let home = kvendra_home()?;
    ensure_layout(&home)?;
    let cfg = Config::default();
    cfg.save(&home)?;

    println!("kvendra init");
    println!("  Pase A scaffold: master-password prompt and full Argon2id derive flow are");
    println!("  Pase B work. The vault layout has been created at: ~/.kvendra/");
    println!();
    println!("Generating recovery material (preview):");
    let mnemonic = generate_mnemonic()?;
    println!("  Recovery phrase (12 words):");
    println!("    {mnemonic}");
    println!("  Recovery codes (8 single-use):");
    for code in generate_codes() {
        println!("    {code}");
    }
    println!();
    println!("WARNING: this is a Pase A scaffold. Do not use these values for real secrets.");
    Ok(())
}
