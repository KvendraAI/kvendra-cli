//! `kvendra config approval <get|set|status>` (REQ-KVD-003 AC-APPROVAL-7).
//!
//! El subcomando opera sobre `~/.kvendra/config.toml` `[approval]`. No hay
//! handle al `ServerContext` desde el CLI standalone, por lo que `status`
//! refleja configuración estática + cascade resolution. Para actividad
//! runtime (cache hits, decisiones recientes) usar `kvendra audit`.

use crate::approval::policy;
use crate::config::{Config, ensure_layout, kvendra_home};
use crate::error::{KvendraError, KvendraResult};
use crate::vault::Vault;
use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum ApprovalCommand {
    /// Show active approval mode + cascade resolution.
    Get,
    /// Set global approval mode in `~/.kvendra/config.toml` (silent | ask | ask-destructive).
    Set { mode: String },
    /// Show approval configuration + cascade diagnostics.
    Status,
}

pub async fn run(cmd: ApprovalCommand) -> KvendraResult<()> {
    let home = kvendra_home()?;
    ensure_layout(&home)?;

    match cmd {
        ApprovalCommand::Get => {
            // Read-only — vault is optional. If a signed config is on disk
            // we still try to verify if the vault happens to be unlockable
            // via env, but for `get` the cheap path is enough.
            let cfg = Config::load(&home, None).unwrap_or_default();
            print_resolved_mode(&cfg);
        }
        ApprovalCommand::Set { mode } => {
            let parsed = policy::parse_mode(&mode).ok_or_else(|| {
                KvendraError::Config(format!(
                    "invalid mode '{mode}' (expected: silent | ask | ask-destructive)"
                ))
            })?;
            // Mutating — requires unlocked vault for HMAC signing.
            let vault = unlock_for_approval(&home)?;
            let mut cfg = Config::load(&home, Some(&vault)).unwrap_or_default();
            cfg.approval.mode = parsed;
            cfg.validate()?;
            cfg.save(&home, &vault)?;
            println!(
                "global approval mode set to '{}' in ~/.kvendra/config.toml",
                policy::mode_name(parsed)
            );
            if std::env::var("KVENDRA_APPROVAL_MODE").is_ok() {
                println!(
                    "note: KVENDRA_APPROVAL_MODE is set in the current shell and overrides the global value."
                );
            }
        }
        ApprovalCommand::Status => {
            let cfg = Config::load(&home, None).unwrap_or_default();
            print_status(&cfg);
        }
    }
    Ok(())
}

/// Unlock the vault for an approval-config mutation. Mirrors `unlock_for_config`
/// in `config_cmd.rs` (kept private here to avoid module-level cycles).
fn unlock_for_approval(home: &std::path::Path) -> KvendraResult<Vault> {
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

fn print_resolved_mode(cfg: &Config) {
    let env = std::env::var("KVENDRA_APPROVAL_MODE")
        .ok()
        .and_then(|s| policy::parse_mode(&s));
    let resolved = policy::resolve_mode(env, None, cfg.approval.mode);
    println!("approval.mode (resolved): {}", policy::mode_name(resolved));
    println!(
        "  global (config.toml):   {}",
        policy::mode_name(cfg.approval.mode)
    );
    if let Some(m) = env {
        println!(
            "  env KVENDRA_APPROVAL_MODE: {} (overrides global)",
            policy::mode_name(m)
        );
    } else {
        println!("  env KVENDRA_APPROVAL_MODE: (unset)");
    }
    println!("  per-profile override:   evaluated at tools/call against profile YAML");
}

fn print_status(cfg: &Config) {
    print_resolved_mode(cfg);
    println!(
        "approval.timeout_seconds:    {}",
        cfg.approval.timeout_seconds
    );
    println!(
        "approval.cache_ttl_seconds:  {}",
        cfg.approval.cache_ttl_seconds
    );
    println!();
    println!("Notes:");
    println!("  - silent mode does NOT require a TTY (CI/automation safe).");
    println!(
        "  - ask / ask-destructive REQUIRE a TTY; otherwise tools/call fails with error_type=approval_no_tty."
    );
    println!("  - approve-all-5min cache is in-memory and resets on `kvendra mcp serve` restart.");
    println!("  - For runtime activity (recent approvals/denials) inspect the audit log:");
    println!("      kvendra audit --json | jq '.events[] | select(.flags | test(\"approval_\"))'");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::ApprovalMode;
    use tempfile::TempDir;

    fn build_cfg(mode: ApprovalMode) -> Config {
        let mut cfg = Config::default();
        cfg.approval.mode = mode;
        cfg
    }

    #[tokio::test]
    async fn set_persists_and_round_trips() {
        let tmp = TempDir::new().unwrap();
        // REQ-KVD-008: `Set` requires an unlocked vault to sign config.toml.
        // Bootstrap with fast Argon2id params (real `kvendra init` uses
        // `high_cost` which is >1s in CI).
        crate::config::ensure_layout(tmp.path()).unwrap();
        let v = Vault::new(tmp.path().to_path_buf());
        v.create_with_params(
            b"hunter2-test",
            crate::vault::kdf::KdfParams {
                m_cost_kib: 19_456,
                t_cost: 2,
                p_cost: 1,
                salt: vec![1u8; 16],
            },
        )
        .unwrap();

        // Take the env-var lock for the env-var-mutating section only.
        // `tokio::sync::Mutex` is async-aware so holding it across an await
        // is permitted (clippy::await_holding_lock only fires on std::sync).
        let _guard = crate::test_env_lock().lock().await;
        let result = {
            unsafe {
                std::env::set_var("KVENDRA_HOME", tmp.path());
                std::env::remove_var("KVENDRA_APPROVAL_MODE");
                std::env::set_var("KVENDRA_PASSWORD", "hunter2-test");
            }
            let r = run(ApprovalCommand::Set {
                mode: "silent".into(),
            })
            .await;
            unsafe {
                std::env::remove_var("KVENDRA_HOME");
                std::env::remove_var("KVENDRA_PASSWORD");
            }
            r
        };
        assert!(result.is_ok(), "set returned {result:?}");

        // Re-load directly via the path (env vars no longer set).
        let v2 = Vault::new(tmp.path().to_path_buf());
        v2.unlock(b"hunter2-test", 30).unwrap();
        let reloaded = Config::load(tmp.path(), Some(&v2)).unwrap();
        assert_eq!(reloaded.approval.mode, ApprovalMode::Silent);
    }

    #[test]
    fn print_resolved_mode_does_not_panic_for_each_mode() {
        for m in [
            ApprovalMode::Silent,
            ApprovalMode::Ask,
            ApprovalMode::AskDestructive,
        ] {
            print_resolved_mode(&build_cfg(m));
        }
    }

    #[test]
    fn invalid_mode_string_rejected() {
        assert!(policy::parse_mode("nope").is_none());
    }
}
