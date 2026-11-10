//! `kvendra recover` — recover access with the 12-word phrase bound to this
//! vault by `kvendra init` (REQ-KVD-CLI-CFB449 F3, ADR-KVD-CLI-4810AF).
//!
//! The phrase opens `recovery.blob`, which wraps the vault key; the new
//! password re-wraps that same key in `sentinel.blob`. Nothing else on disk
//! changes, so secrets, local variables, allowlists, grants, backups and the
//! audit chain keep working. See [`crate::rekey`].

use crate::config::kvendra_home;
use crate::error::{KvendraError, KvendraResult};
use crate::rekey::{caches_for_process, recover_with_phrase};
use crate::vault::Vault;
use clap::Args;
use zeroize::Zeroizing;

#[derive(Debug, Args)]
pub struct RecoverArgs {
    /// Read the mnemonic from this env var instead of prompting (testing/CI).
    #[arg(long, env = "KVENDRA_RECOVERY_MNEMONIC", hide_env_values = true)]
    pub mnemonic_env: Option<String>,
    /// Read the new master password from this env var (testing/CI).
    #[arg(long, env = "KVENDRA_NEW_PASSWORD", hide_env_values = true)]
    pub new_password_env: Option<String>,
}

pub async fn run(args: RecoverArgs) -> KvendraResult<()> {
    let home = kvendra_home()?;
    let vault = Vault::new(home);
    let caches = caches_for_process()?;
    let RecoverArgs {
        mnemonic_env,
        new_password_env,
    } = args;

    let report = recover_with_phrase(
        &vault,
        move || match mnemonic_env {
            Some(s) => Ok(Zeroizing::new(s)),
            None => {
                println!("Enter the 12-word recovery phrase (will not echo):");
                rpassword::read_password()
                    .map(Zeroizing::new)
                    .map_err(|e| KvendraError::Vault(format!("read mnemonic: {e}")))
            }
        },
        move || match new_password_env {
            Some(s) => Ok(Zeroizing::new(s)),
            None => crate::cli::init::prompt_password_with_confirmation(3),
        },
        caches.as_ref(),
    )
    .await?;
    // Says exactly what was cleared and what was left (M1).
    println!(
        "{}",
        crate::rekey::success_message(crate::rekey::RekeyAction::Recover, &report)
    );
    Ok(())
}
