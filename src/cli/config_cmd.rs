//! `kvendra config <subcommand>` — runtime configuration management.
//!
//! Pase B implements `keychain enable | disable | status` per ADR-KVD-012:
//! - When `enable`d, `kvendra unlock` writes a constant presence flag to the
//!   OS keychain entry `kvendra/derived-key/v1` after each successful unlock.
//!   The flag is never key material and nothing reads it back to skip the
//!   password: every unlock still asks for the master password.
//! - When `disable`d, the keychain entry is wiped.
//!
//! Keeping the master password in the keychain for `kvendra mcp serve` is a
//! separate, presence-gated feature: `kvendra config mcp-password enable`.

use crate::cli::config_approval::{ApprovalCommand, run as run_approval};
use crate::cli::config_mcp_password::{McpPasswordCommand, run as run_mcp_password};
use crate::cli::config_rebind::RebindHomeArgs;
use crate::cli::config_recovery_codes::{RecoveryCodesCommand, run as run_recovery_codes};
use crate::cli::config_telemetry::{TelemetryArgs, run as run_telemetry};
use crate::config::{Config, MasterPasswordCache, ensure_layout, kvendra_home};
use crate::error::{KvendraError, KvendraResult};
use crate::vault::Vault;
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
    /// Manage MCP password keychain pattern (REQ-KVD-005 / ISSUE-KVD-CLI-017).
    #[command(subcommand, name = "mcp-password")]
    McpPassword(McpPasswordCommand),
    /// Rebind the vault to a new `KVENDRA_HOME` location with triple-barrier
    /// verification (master password + recovery code + TTY confirmation).
    /// Required after a legitimate move of `~/.kvendra/` (REQ-KVD-008).
    #[command(name = "rebind-home")]
    RebindHome(RebindHomeArgs),
    /// Manage recovery codes (regenerate the 8 numeric one-time codes).
    /// REQ-KVD-CLI-003 — double-barrier (master password + TTY re-typed
    /// acknowledge `REGENERATE-RECOVERY-CODES`).
    #[command(subcommand, name = "recovery-codes")]
    RecoveryCodes(RecoveryCodesCommand),
    /// Toggle telemetry opt-in (M2.5 D9 / ROAD-KVD-007).
    Telemetry(TelemetryArgs),
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
    // Dispatch `mcp-password` BEFORE touching `kvendra_home()` — its
    // `enable` subcommand has its own platform-gating (macOS-only) and must
    // not be blocked by `kvendra_home()` failing on CI runners without HOME
    // set (Windows CI).
    let cmd = match cmd {
        ConfigCommand::McpPassword(c) => return run_mcp_password(c).await,
        other => other,
    };
    let home = kvendra_home()?;
    ensure_layout(&home)?;

    // Mutating subcommands need an unlocked vault to derive the config-HMAC
    // sub-key (REQ-KVD-008). We unlock once at the dispatcher level.
    match cmd {
        ConfigCommand::Keychain(sub) => {
            let vault = unlock_for_config(&home)?;
            let mut cfg = Config::load_for_update(&home, &vault, "keychain")?;
            match sub {
                KeychainCommand::Enable => {
                    cfg.vault.master_password_cache = MasterPasswordCache::OsKeychain;
                    cfg.save(&home, &vault)?;
                    print!("{}", keychain_enable_notice());
                }
                KeychainCommand::Disable => {
                    cfg.vault.master_password_cache = MasterPasswordCache::RamOnly;
                    cfg.save(&home, &vault)?;
                    if let Ok(entry) = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_LABEL) {
                        let _ = entry.delete_credential();
                    }
                    crate::rekey::unbind_keychain_owner(KEYCHAIN_LABEL);
                    println!("OS keychain integration disabled. Stored entry wiped.");
                }
                KeychainCommand::Status => {
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
            }
        }
        ConfigCommand::Approval(c) => return run_approval(c).await,
        ConfigCommand::McpPassword(_) => unreachable!("dispatched before kvendra_home() above"),
        ConfigCommand::RebindHome(args) => {
            return crate::cli::config_rebind::run(args).await;
        }
        ConfigCommand::RecoveryCodes(c) => return run_recovery_codes(c).await,
        ConfigCommand::Telemetry(args) => return run_telemetry(args).await,
    }
    Ok(())
}

/// Unlock the vault for a `kvendra config <...>` subcommand that mutates
/// `~/.kvendra/config.toml`. The HKDF sub-key for HMAC signing only exists
/// while the session is unlocked. `KVENDRA_PASSWORD` env var honoured for
/// non-interactive use; otherwise prompts via `rpassword`.
fn unlock_for_config(home: &std::path::Path) -> KvendraResult<Vault> {
    let vault = Vault::new(home.to_path_buf());
    if !vault.sentinel_path().exists() {
        return Err(KvendraError::Vault(
            "vault not initialized. Run `kvendra init` first.".into(),
        ));
    }
    let password = match std::env::var("KVENDRA_PASSWORD") {
        Ok(s) => s,
        Err(_) => {
            println!("Enter the master password (will not echo):");
            rpassword::read_password()
                .map_err(|e| KvendraError::Vault(format!("read password: {e}")))?
        }
    };
    vault.unlock(password.as_bytes(), 30)?;
    Ok(vault)
}

/// What `kvendra config keychain enable` prints. It must describe what the
/// code stores (a presence flag, never key material): see ISSUE-KVD-CLI-426DD0.
pub fn keychain_enable_notice() -> &'static str {
    "OS keychain integration enabled.\n\
     After each successful `kvendra unlock`, a presence flag (no key material) is written\n\
     to the OS keychain entry `kvendra/derived-key/v1`.\n\
     The master password is still required at every unlock: neither the vault key nor the\n\
     password is cached by this setting.\n\
     To keep the master password in the keychain for `kvendra mcp serve`, use\n\
     `kvendra config mcp-password enable` (presence-gated).\n\
     Disable at any time with `kvendra config keychain disable`.\n"
}

/// Helper used by `kvendra unlock`: write the value it is given (today the
/// constant presence flag) to the OS keychain entry. The caller decides what
/// is stored; `unlock` never passes key material.
pub fn store_derived_key_in_keychain(key_b64: &str) -> KvendraResult<()> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_LABEL)
        .map_err(|e| KvendraError::Keychain(e.to_string()))?;
    entry
        .set_password(key_b64)
        .map_err(|e| KvendraError::Keychain(e.to_string()))?;
    Ok(())
}

/// Read the value stored in the OS keychain entry (the presence flag).
pub fn read_derived_key_from_keychain() -> KvendraResult<String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_LABEL)
        .map_err(|e| KvendraError::Keychain(e.to_string()))?;
    entry
        .get_password()
        .map_err(|e| KvendraError::Keychain(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::keychain_enable_notice;

    /// ISSUE-KVD-CLI-426DD0: the notice must describe what is stored (a
    /// presence flag) and must not claim the key or the password is cached.
    #[test]
    fn keychain_enable_notice_says_what_is_really_stored() {
        let n = keychain_enable_notice();
        assert!(n.contains("presence flag (no key material)"));
        assert!(n.contains("still required at every unlock"));
        assert!(n.contains("kvendra config mcp-password enable"));
        assert!(!n.contains(concat!("derived key ", "will be stored")));
        assert!(!n.contains("RAM-only invariant"));
    }
}
