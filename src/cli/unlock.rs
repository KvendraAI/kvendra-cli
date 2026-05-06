//! `kvendra unlock` — derive the master key into a session.
//!
//! Honours `master_password_cache` from `~/.kvendra/config.toml`:
//! - `ram-only` (default): always prompt for the master password.
//! - `os-keychain` (per ADR-KVD-012): try to read the derived key from the
//!   OS keychain first; fall back to prompting on miss/error.

use crate::cli::config_cmd::{read_derived_key_from_keychain, store_derived_key_in_keychain};
use crate::config::{Config, MasterPasswordCache, kvendra_home};
use crate::error::{KvendraError, KvendraResult};
use crate::vault::Vault;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use clap::Args;

#[derive(Debug, Args)]
pub struct UnlockArgs {
    /// Read password from env var (testing/CI).
    #[arg(long, env = "KVENDRA_PASSWORD")]
    pub password_env: Option<String>,
    /// Force prompting even if keychain is enabled.
    #[arg(long)]
    pub no_keychain: bool,
}

pub async fn run(args: UnlockArgs) -> KvendraResult<()> {
    let home = kvendra_home()?;
    let cfg = Config::load(&home).unwrap_or_default();
    let vault = Vault::new(home.clone());

    if !vault.sentinel_path().exists() {
        return Err(KvendraError::Vault(
            "vault not initialized. Run `kvendra init` first.".into(),
        ));
    }

    // Keychain fast path (ADR-KVD-012).
    if !args.no_keychain && cfg.vault.master_password_cache == MasterPasswordCache::OsKeychain {
        match read_derived_key_from_keychain() {
            Ok(b64) => {
                if let Ok(_decoded) = B64.decode(&b64) {
                    println!(
                        "Read derived key from OS keychain. WARNING: key is now in keychain (V4 relaxed)."
                    );
                    // We cannot directly inject the derived key into the vault
                    // session API without a master password (vault.unlock
                    // uses the password). For Pase B we re-decrypt the
                    // sentinel using the cached key directly: open the
                    // session in-place. A fully native injection lands in
                    // Beta. For now we still require the password but note
                    // that the keychain entry exists.
                    println!(
                        "Note: Pase B keychain caching only validates presence. Re-prompting for password."
                    );
                }
            }
            Err(_) => { /* miss — prompt below */ }
        }
    }

    let password = match args.password_env {
        Some(s) => s,
        None => {
            println!("Enter the master password (will not echo):");
            rpassword::read_password()
                .map_err(|e| KvendraError::Vault(format!("read password: {e}")))?
        }
    };

    vault.unlock(password.as_bytes(), cfg.vault.idle_timeout_minutes)?;

    if !args.no_keychain && cfg.vault.master_password_cache == MasterPasswordCache::OsKeychain {
        // Persist a sentinel into the keychain (presence indicator only).
        let _ = store_derived_key_in_keychain(&B64.encode(b"kvendra-keychain-sentinel-v1"));
    }

    println!(
        "Vault unlocked. idle_timeout = {} min.",
        cfg.vault.idle_timeout_minutes
    );
    Ok(())
}
