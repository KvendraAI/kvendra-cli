//! `kvendra config <subcommand>` — runtime configuration management.
//!
//! Pase B implements `keychain enable | disable | status` per ADR-KVD-012:
//! - When `enable`d, the derived key is written to the OS keychain after
//!   each `unlock`, so subsequent unlocks can read from the keychain (with
//!   biometric prompt on supported platforms) instead of re-prompting for
//!   the master password.
//! - When `disable`d, the keychain entry is wiped and unlocks fall back to
//!   the master password prompt.

use crate::cli::config_approval::{ApprovalCommand, run as run_approval};
use crate::config::{Config, MasterPasswordCache, ensure_layout, kvendra_home};
use crate::error::{KvendraError, KvendraResult};
use clap::Subcommand;

const KEYCHAIN_SERVICE: &str = "kvendra";
const KEYCHAIN_LABEL: &str = "kvendra/derived-key/v1";

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Manage OS keychain integration (ADR-KVD-012).
    #[command(subcommand)]
    Keychain(KeychainCommand),
    /// Manage approval layer (REQ-KVD-003 / ROAD-KVD-007).
    #[command(subcommand)]
    Approval(ApprovalCommand),
}

#[derive(Debug, Subcommand)]
pub enum KeychainCommand {
    /// Enable OS keychain caching.
    Enable,
    /// Disable OS keychain caching and wipe stored entry.
    Disable,
    /// Show keychain configuration status.
    Status,
}

pub async fn run(cmd: ConfigCommand) -> KvendraResult<()> {
    let home = kvendra_home()?;
    ensure_layout(&home)?;
    let mut cfg = Config::load(&home).unwrap_or_default();
    match cmd {
        ConfigCommand::Keychain(KeychainCommand::Enable) => {
            cfg.vault.master_password_cache = MasterPasswordCache::OsKeychain;
            cfg.save(&home)?;
            println!("OS keychain integration enabled.");
            println!(
                "WARNING: the derived key will be stored in the OS keychain on the next unlock."
            );
            println!("This relaxes the strict RAM-only invariant of the threat model (V4).");
            println!("Disable at any time with `kvendra config keychain disable`.");
        }
        ConfigCommand::Keychain(KeychainCommand::Disable) => {
            cfg.vault.master_password_cache = MasterPasswordCache::RamOnly;
            cfg.save(&home)?;
            // Best-effort delete of any stored entry.
            if let Ok(entry) = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_LABEL) {
                let _ = entry.delete_credential();
            }
            println!("OS keychain integration disabled. Stored entry wiped.");
        }
        ConfigCommand::Keychain(KeychainCommand::Status) => {
            println!(
                "master_password_cache: {:?}",
                cfg.vault.master_password_cache
            );
            match keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_LABEL) {
                Ok(entry) => match entry.get_password() {
                    Ok(_) => println!("keychain entry: present"),
                    Err(_) => println!("keychain entry: absent"),
                },
                Err(e) => println!("keychain backend: {e}"),
            }
        }
        ConfigCommand::Approval(c) => return run_approval(c).await,
    }
    Ok(())
}

/// Helper used by `kvendra unlock`: persist derived key in OS keychain.
pub fn store_derived_key_in_keychain(key_b64: &str) -> KvendraResult<()> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_LABEL)
        .map_err(|e| KvendraError::Keychain(e.to_string()))?;
    entry
        .set_password(key_b64)
        .map_err(|e| KvendraError::Keychain(e.to_string()))?;
    Ok(())
}

/// Helper used by `kvendra unlock`: try to read derived key from OS keychain.
pub fn read_derived_key_from_keychain() -> KvendraResult<String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_LABEL)
        .map_err(|e| KvendraError::Keychain(e.to_string()))?;
    entry
        .get_password()
        .map_err(|e| KvendraError::Keychain(e.to_string()))
}
