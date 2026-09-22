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
    /// Signed opt-in (on | off) letting `KVENDRA_APPROVAL_MODE` LOOSEN the
    /// signed mode. Off by default: the env var may only tighten it.
    AllowEnvDowngrade { value: String },
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
            let mut cfg = Config::load_for_update(&home, &vault, "approval set")?;
            cfg.approval.mode = parsed;
            cfg.validate()?;
            cfg.save(&home, &vault)?;
            println!(
                "global approval mode set to '{}' in ~/.kvendra/config.toml",
                policy::mode_name(parsed)
            );
            if std::env::var("KVENDRA_APPROVAL_MODE").is_ok() {
                println!(
                    "note: KVENDRA_APPROVAL_MODE is set in the current shell; it can only tighten the signed mode unless `allow-env-downgrade on`."
                );
            }
        }
        ApprovalCommand::AllowEnvDowngrade { value } => {
            let enabled = match value.trim().to_ascii_lowercase().as_str() {
                "on" | "true" => true,
                "off" | "false" => false,
                _ => {
                    return Err(KvendraError::Config(format!(
                        "invalid value '{value}' (expected: on | off)"
                    )));
                }
            };
            let vault = unlock_for_approval(&home)?;
            let mut cfg = Config::load_for_update(&home, &vault, "approval allow-env-downgrade")?;
            cfg.approval.allow_env_downgrade = enabled;
            cfg.validate()?;
            cfg.save(&home, &vault)?;
            println!("approval.allow_env_downgrade set to {enabled} in ~/.kvendra/config.toml");
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
    let outcome = policy::resolve_mode_ratcheted(
        env,
        None,
        cfg.approval.mode,
        cfg.approval.allow_env_downgrade,
    );
    println!(
        "approval.mode (resolved): {}",
        policy::mode_name(outcome.mode)
    );
    println!(
        "  global (config.toml):   {}",
        policy::mode_name(cfg.approval.mode)
    );
    println!(
        "  allow_env_downgrade:    {}",
        cfg.approval.allow_env_downgrade
    );
    if let Some(m) = env {
        let effect = match outcome.env_override {
            Some(policy::EnvOverride::DowngradeIgnored) => {
                "IGNORED — looser than the signed mode (no allow_env_downgrade)"
            }
            Some(policy::EnvOverride::DowngradeApplied) => {
                "APPLIED — loosens the signed mode (allow_env_downgrade = true)"
            }
            Some(policy::EnvOverride::Tightened) => "APPLIED — tightens the signed mode",
            None => "same as the signed mode",
        };
        println!(
            "  env KVENDRA_APPROVAL_MODE: {} ({effect})",
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

    // ───────────────────────────────────────────────────────────────────
    // SA6 — ISSUE-KVD-CLI-BFACC4 (RUN-KVD-CLI-190069).
    //
    // `Config::load` returns defaults ONLY for an ABSENT file
    // (src/config.rs:172-174); every other `Err` is an INTEGRITY failure
    // (HMAC mismatch, missing/displaced `_hmac` trailer, home redirect).
    // Every config-mutating subcommand nevertheless does
    // `Config::load(..).unwrap_or_default()` and then `save()` a few lines
    // later (config_cmd.rs:76, config_telemetry.rs:44, config_approval.rs:44,
    // config_rebind.rs:285 and :291), so a tampered document is LAUNDERED into
    // a freshly-signed set of compiled defaults — the owner's `severity=block`
    // and `mode=ask` silently revert, the attacker's edit disappears, and the
    // process exits 0. A5 (ISSUE-KVD-CLI-74808A) only covered the reader and
    // `mcp serve`.
    //
    // These live in-crate because `run()` reads `KVENDRA_HOME` /
    // `KVENDRA_PASSWORD` from the PROCESS environment, which can only be
    // mutated under `crate::test_env_lock()` (pub(crate), src/lib.rs:41).
    // Mould: `set_persists_and_round_trips` above.
    // RED at e41b652: `run` returns Ok and the file is rewritten.
    // ───────────────────────────────────────────────────────────────────

    /// Bootstrap a temp KVENDRA_HOME with a fast-Argon2id vault and a SIGNED,
    /// deliberately NON-default policy (the state a tamper would revert).
    fn sa6_bootstrap_signed_policy(tmp: &TempDir) -> Vault {
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
        cfg.approval.mode = ApprovalMode::Ask;
        cfg.save(tmp.path(), &v).unwrap();
        v
    }

    /// Run `kvendra config approval set <mode>` against `home` with the env
    /// lock held. Returns the subcommand's result.
    async fn sa6_run_set(home: &std::path::Path, mode: &str) -> KvendraResult<()> {
        let _guard = crate::test_env_lock().lock().await;
        unsafe {
            std::env::set_var("KVENDRA_HOME", home);
            std::env::remove_var("KVENDRA_APPROVAL_MODE");
            std::env::set_var("KVENDRA_PASSWORD", "hunter2-test");
        }
        let r = run(ApprovalCommand::Set {
            mode: mode.to_string(),
        })
        .await;
        unsafe {
            std::env::remove_var("KVENDRA_HOME");
            std::env::remove_var("KVENDRA_PASSWORD");
        }
        r
    }

    /// Tamper shape (i) — content APPENDED after the `_hmac` trailer. The
    /// signature is no longer the last line, so the document is unsigned
    /// (config.rs:216-243).
    #[tokio::test]
    async fn sa6_appended_tamper_must_not_be_laundered_by_approval_set() {
        let tmp = TempDir::new().unwrap();
        let _v = sa6_bootstrap_signed_policy(&tmp);
        let path = tmp.path().join("config.toml");
        let signed = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, format!("{signed}appended_by_attacker = true\n")).unwrap();
        let bytes_before = std::fs::read(&path).unwrap();

        let result = sa6_run_set(tmp.path(), "ask-destructive").await;
        let bytes_after = std::fs::read(&path).unwrap();

        assert!(
            bytes_before == bytes_after,
            "`config approval set` REWROTE an integrity-refused config.toml: \
             the tampered document was laundered into freshly-signed compiled \
             defaults (the owner's policy is gone and the attacker's edit is \
             erased along with the evidence). File must be byte-identical.\n\
             before:\n{}\nafter:\n{}",
            String::from_utf8_lossy(&bytes_before),
            String::from_utf8_lossy(&bytes_after)
        );
        assert!(
            result.is_err(),
            "`config approval set` must FAIL (non-zero exit) on an \
             integrity-refused config; got {result:?}"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("config_tampered_detected"),
            "the failure must surface the integrity diagnosis, got: {msg}"
        );
    }

    /// Tamper shape (ii) — a byte flipped INSIDE the `_hmac` trailer. The
    /// trailer still parses, so this exercises the HMAC-mismatch branch
    /// (config.rs:196-213) rather than the unsigned one.
    #[tokio::test]
    async fn sa6_flipped_hmac_trailer_must_not_be_laundered_by_approval_set() {
        let tmp = TempDir::new().unwrap();
        let _v = sa6_bootstrap_signed_policy(&tmp);
        let path = tmp.path().join("config.toml");
        let signed = std::fs::read_to_string(&path).unwrap();
        // Flip the first hex digit of the signature.
        let idx = signed.rfind("_hmac = \"").unwrap() + "_hmac = \"".len();
        let mut bytes = signed.into_bytes();
        bytes[idx] = if bytes[idx] == b'a' { b'b' } else { b'a' };
        std::fs::write(&path, &bytes).unwrap();
        let bytes_before = std::fs::read(&path).unwrap();

        let result = sa6_run_set(tmp.path(), "ask-destructive").await;
        let bytes_after = std::fs::read(&path).unwrap();

        assert!(
            bytes_before == bytes_after,
            "`config approval set` RE-SIGNED a config whose HMAC does not \
             verify — the file must be left byte-identical.\nbefore:\n{}\nafter:\n{}",
            String::from_utf8_lossy(&bytes_before),
            String::from_utf8_lossy(&bytes_after)
        );
        assert!(
            result.is_err(),
            "`config approval set` must FAIL on an HMAC mismatch; got {result:?}"
        );
    }

    /// ANTI-REGRESSION GUARD (green before AND after) — the most important one:
    /// an ABSENT config.toml is NOT an integrity failure. Propagating the error
    /// with `?` at the writer sites must not break first run.
    #[tokio::test]
    async fn sa6_guard_absent_config_first_run_still_signs() {
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
        let path = tmp.path().join("config.toml");
        assert!(!path.exists(), "precondition: no config.toml yet");

        let result = sa6_run_set(tmp.path(), "ask").await;
        assert!(
            result.is_ok(),
            "first run with NO config.toml must still succeed; got {result:?}"
        );
        assert!(path.exists(), "the subcommand must create config.toml");
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            raw.trim_end()
                .lines()
                .last()
                .unwrap()
                .starts_with("_hmac = \""),
            "the created config must be signed (trailer last), got:\n{raw}"
        );

        let v2 = Vault::new(tmp.path().to_path_buf());
        v2.unlock(b"hunter2-test", 30).unwrap();
        let reloaded = Config::load(tmp.path(), Some(&v2)).unwrap();
        assert_eq!(reloaded.approval.mode, ApprovalMode::Ask);
    }
}
