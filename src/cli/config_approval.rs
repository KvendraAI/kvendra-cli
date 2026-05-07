//! `kvendra config approval <get|set|status>` (REQ-KVD-003 AC-APPROVAL-7).
//!
//! El subcomando opera sobre `~/.kvendra/config.toml` `[approval]`. No hay
//! handle al `ServerContext` desde el CLI standalone, por lo que `status`
//! refleja configuración estática + cascade resolution. Para actividad
//! runtime (cache hits, decisiones recientes) usar `kvendra audit`.

use crate::approval::policy;
use crate::config::{Config, ensure_layout, kvendra_home};
use crate::error::{KvendraError, KvendraResult};
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
    let mut cfg = Config::load(&home).unwrap_or_default();

    match cmd {
        ApprovalCommand::Get => {
            print_resolved_mode(&cfg);
        }
        ApprovalCommand::Set { mode } => {
            let parsed = policy::parse_mode(&mode).ok_or_else(|| {
                KvendraError::Config(format!(
                    "invalid mode '{mode}' (expected: silent | ask | ask-destructive)"
                ))
            })?;
            cfg.approval.mode = parsed;
            cfg.validate()?;
            cfg.save(&home)?;
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
            print_status(&cfg);
        }
    }
    Ok(())
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
        unsafe {
            std::env::set_var("KVENDRA_HOME", tmp.path());
        }
        // Clear any inherited override that would obscure cascade diagnostics
        // in the test process.
        unsafe {
            std::env::remove_var("KVENDRA_APPROVAL_MODE");
        }

        let result = run(ApprovalCommand::Set {
            mode: "silent".into(),
        })
        .await;
        assert!(result.is_ok(), "set returned {result:?}");

        let home = kvendra_home().unwrap();
        let reloaded = Config::load(&home).unwrap();
        assert_eq!(reloaded.approval.mode, ApprovalMode::Silent);

        unsafe {
            std::env::remove_var("KVENDRA_HOME");
        }
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
