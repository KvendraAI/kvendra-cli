//! `kvendra recover` — reset the master password using a BIP-39 mnemonic
//! (ADR-KVD-011 / AC-VAULT-5).

use crate::config::{Config, ensure_layout, kvendra_home};
use crate::error::{KvendraError, KvendraResult};
use crate::vault::Vault;
use clap::Args;

#[derive(Debug, Args)]
pub struct RecoverArgs {
    /// Read the mnemonic from this env var instead of prompting (testing/CI).
    #[arg(long, env = "KVENDRA_RECOVERY_MNEMONIC")]
    pub mnemonic_env: Option<String>,
    /// Read the new master password from this env var (testing/CI).
    #[arg(long, env = "KVENDRA_NEW_PASSWORD")]
    pub new_password_env: Option<String>,
}

pub async fn run(args: RecoverArgs) -> KvendraResult<()> {
    let home = kvendra_home()?;
    ensure_layout(&home)?;
    // Pre-unlock load: signed-config verification will run on the next
    // unlock, since `recover` rotates the master password and therefore the
    // HKDF sub-keys. The cfg here is only used for legacy compat fields.
    let cfg = Config::load(&home, None).unwrap_or_default();
    let vault = Vault::new(home.clone());

    let mnemonic = match args.mnemonic_env {
        Some(s) => s,
        None => {
            println!("Enter the 12-word BIP-39 recovery phrase:");
            rpassword::read_password()
                .map_err(|e| KvendraError::Vault(format!("read mnemonic: {e}")))?
        }
    };
    let new_password = match args.new_password_env {
        Some(s) => s,
        None => {
            println!("Enter the new master password:");
            rpassword::read_password()
                .map_err(|e| KvendraError::Vault(format!("read password: {e}")))?
        }
    };

    vault.reset_password_with_mnemonic(mnemonic.trim(), new_password.as_bytes())?;
    println!("Master password reset OK. Run `kvendra unlock` to start a new session.");
    let _ = cfg;
    Ok(())
}
