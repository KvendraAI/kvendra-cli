//! `kvendra config telemetry --enable | --disable | --status` — M2.5 D9.
//!
//! Persists `[telemetry] enabled` in `~/.kvendra/config.toml`. The collector
//! itself (POST to `https://api.kvendra.cloud/v1/telemetry`) is a follow-up
//! milestone; in M2.5 we only persist the user choice so future binaries
//! honour it.

use crate::config::{Config, ensure_layout, kvendra_home};
use crate::error::{KvendraError, KvendraResult};
use crate::vault::Vault;
use clap::Args;

#[derive(Debug, Args)]
pub struct TelemetryArgs {
    /// Enable telemetry (opt-in).
    #[arg(long, conflicts_with_all = ["disable", "status"])]
    pub enable: bool,
    /// Disable telemetry (default).
    #[arg(long, conflicts_with_all = ["enable", "status"])]
    pub disable: bool,
    /// Show the current toggle value without changing it.
    #[arg(long, conflicts_with_all = ["enable", "disable"])]
    pub status: bool,
}

pub async fn run(args: TelemetryArgs) -> KvendraResult<()> {
    let home = kvendra_home()?;
    ensure_layout(&home)?;

    if args.status || (!args.enable && !args.disable) {
        let cfg = Config::load(&home, None).unwrap_or_default();
        println!(
            "telemetry.enabled: {}",
            if cfg.telemetry.enabled {
                "true"
            } else {
                "false"
            }
        );
        return Ok(());
    }

    let vault = unlock_for_config(&home)?;
    let mut cfg = Config::load_for_update(&home, &vault, "telemetry")?;
    cfg.telemetry.enabled = args.enable;
    cfg.save(&home, &vault)?;
    println!(
        "telemetry.enabled set to {}",
        if cfg.telemetry.enabled {
            "true"
        } else {
            "false"
        }
    );
    if cfg.telemetry.enabled {
        println!(
            "Note: the telemetry collector endpoint is not yet active. Your\n\
             opt-in will be honoured once the collector ships (M3+)."
        );
    }
    Ok(())
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// SA6 / ISSUE-KVD-CLI-BFACC4 — `config telemetry --enable` on a config
    /// with content appended after the `_hmac` trailer must fail and leave
    /// the file byte-identical (no re-sign as compiled defaults).
    #[tokio::test]
    async fn sa6_tampered_config_not_laundered_by_telemetry_enable() {
        let tmp = TempDir::new().unwrap();
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
        v.unlock(b"hunter2-test", 30).unwrap();
        let mut cfg = Config::default();
        cfg.detection.severity = crate::config::DetectionSeverity::Block;
        cfg.save(tmp.path(), &v).unwrap();
        let path = tmp.path().join("config.toml");
        let signed = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, format!("{signed}appended_by_attacker = true\n")).unwrap();
        let before = std::fs::read(&path).unwrap();

        let result = {
            let _guard = crate::test_env_lock().lock().await;
            unsafe {
                std::env::set_var("KVENDRA_HOME", tmp.path());
                std::env::set_var("KVENDRA_PASSWORD", "hunter2-test");
            }
            let r = run(TelemetryArgs {
                enable: true,
                disable: false,
                status: false,
            })
            .await;
            unsafe {
                std::env::remove_var("KVENDRA_HOME");
                std::env::remove_var("KVENDRA_PASSWORD");
            }
            r
        };
        assert_eq!(before, std::fs::read(&path).unwrap());
        assert!(
            matches!(&result, Err(KvendraError::Config(m)) if m.contains("config_tampered_detected")),
            "{result:?}"
        );
    }
}
