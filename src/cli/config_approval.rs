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
            // Read-only (ISSUE-KVD-CLI-705EF0): verify when the vault can be
            // unlocked non-interactively; otherwise label the output UNVERIFIED.
            let (cfg, trust) = load_for_display(&home, "approval get")?;
            print_trust_banner(trust);
            print_resolved_mode(&cfg, trust);
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
            let (cfg, trust) = load_for_display(&home, "approval status")?;
            print_trust_banner(trust);
            print_status(&cfg, trust);
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

/// Whether the config shown by a read-only subcommand was HMAC-verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigTrust {
    /// Loaded through the verifying loader with an unlocked vault.
    Verified,
    /// The vault could not be unlocked non-interactively: the values were read
    /// WITHOUT signature verification and may be tampered.
    Unverified,
}

const UNVERIFIED_BANNER: &str = "UNVERIFIED (vault locked): values shown may be tampered; \
     the broker enforces only a verified config. Run `kvendra unlock` to verify.";

/// Try to unlock the vault WITHOUT prompting: `KVENDRA_PASSWORD` first (an
/// explicit, wrong password is an error), then the local session blob
/// written by `kvendra unlock`. `Ok(None)` = locked / not initialized.
fn unlock_non_interactive(home: &std::path::Path) -> KvendraResult<Option<Vault>> {
    let vault = Vault::new(home.to_path_buf());
    if !vault.sentinel_path().exists() {
        return Ok(None);
    }
    if let Ok(password) = std::env::var("KVENDRA_PASSWORD") {
        vault.unlock(password.as_bytes(), 30)?;
        return Ok(Some(vault));
    }
    if let Ok(state) = crate::session::local::load(home)
        && vault
            .unlock_from_derived_key(&state.derived_key, 30)
            .is_ok()
    {
        return Ok(Some(vault));
    }
    Ok(None)
}

/// Load the config for a read-only subcommand (ISSUE-KVD-CLI-705EF0).
///
/// With an unlockable vault the config goes through the verifying loader and
/// every integrity error (`config_tampered_detected`, unsigned, redirected)
/// propagates → non-zero exit. With a locked vault the values are read
/// unverified and tagged [`ConfigTrust::Unverified`] so the caller never
/// presents them as authoritative. Never swallows an error into defaults.
fn load_for_display(
    home: &std::path::Path,
    subcommand: &str,
) -> KvendraResult<(Config, ConfigTrust)> {
    match unlock_non_interactive(home)? {
        Some(vault) => {
            let cfg = Config::load_for_update(home, &vault, subcommand)?;
            Ok((cfg, ConfigTrust::Verified))
        }
        None => {
            let cfg = Config::load(home, None)?;
            Ok((cfg, ConfigTrust::Unverified))
        }
    }
}

fn print_trust_banner(trust: ConfigTrust) {
    match trust {
        ConfigTrust::Verified => println!("config.toml: VERIFIED (HMAC ok)"),
        ConfigTrust::Unverified => println!("{UNVERIFIED_BANNER}"),
    }
}

/// Human description of the env-override outcome. Only a VERIFIED config may
/// be described as fact; an unverified one is phrased conditionally.
fn env_effect_text(outcome: Option<policy::EnvOverride>, trust: ConfigTrust) -> String {
    let fact = match outcome {
        Some(policy::EnvOverride::DowngradeIgnored) => {
            "IGNORED — looser than the signed mode (no allow_env_downgrade)"
        }
        Some(policy::EnvOverride::DowngradeApplied) => {
            "APPLIED — loosens the signed mode (allow_env_downgrade = true)"
        }
        Some(policy::EnvOverride::Tightened) => "APPLIED — tightens the signed mode",
        None => "same as the signed mode",
    };
    match trust {
        ConfigTrust::Verified => fact.to_string(),
        ConfigTrust::Unverified => {
            let cond = match outcome {
                Some(policy::EnvOverride::DowngradeIgnored) => {
                    "would be ignored (looser than the signed mode, no allow_env_downgrade)"
                }
                Some(policy::EnvOverride::DowngradeApplied) => {
                    "would loosen the signed mode (allow_env_downgrade = true)"
                }
                Some(policy::EnvOverride::Tightened) => "would tighten the signed mode",
                None => "would match the signed mode",
            };
            format!("{cond} — if this config verifies")
        }
    }
}

fn print_resolved_mode(cfg: &Config, trust: ConfigTrust) {
    let env = std::env::var("KVENDRA_APPROVAL_MODE")
        .ok()
        .and_then(|s| policy::parse_mode(&s));
    let outcome = policy::resolve_mode_ratcheted(
        env,
        None,
        cfg.approval.mode,
        cfg.approval.allow_env_downgrade,
    );
    let resolved_label = match trust {
        ConfigTrust::Verified => "approval.mode (resolved):",
        ConfigTrust::Unverified => "approval.mode (would resolve to, UNVERIFIED):",
    };
    println!("{resolved_label} {}", policy::mode_name(outcome.mode));
    println!(
        "  global (config.toml):   {}",
        policy::mode_name(cfg.approval.mode)
    );
    println!(
        "  allow_env_downgrade:    {}",
        cfg.approval.allow_env_downgrade
    );
    if let Some(m) = env {
        let effect = env_effect_text(outcome.env_override, trust);
        println!(
            "  env KVENDRA_APPROVAL_MODE: {} ({effect})",
            policy::mode_name(m)
        );
    } else {
        println!("  env KVENDRA_APPROVAL_MODE: (unset)");
    }
    println!("  per-profile override:   evaluated at tools/call against profile YAML");
}

fn print_status(cfg: &Config, trust: ConfigTrust) {
    print_resolved_mode(cfg, trust);
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
            print_resolved_mode(&build_cfg(m), ConfigTrust::Verified);
            print_resolved_mode(&build_cfg(m), ConfigTrust::Unverified);
        }
    }

    // ───────────────────────────────────────────────────────────────────
    // V06 — ISSUE-KVD-CLI-705EF0. `config approval get|status` must not
    // present a ratchet resolution computed from an UNVERIFIED config as
    // authoritative.
    // ───────────────────────────────────────────────────────────────────

    #[test]
    fn v06_unverified_effect_text_is_never_stated_as_fact() {
        use policy::EnvOverride::*;
        for o in [
            Some(DowngradeIgnored),
            Some(DowngradeApplied),
            Some(Tightened),
            None,
        ] {
            let t = env_effect_text(o, ConfigTrust::Unverified);
            assert!(
                !t.contains("APPLIED") && !t.contains("IGNORED"),
                "unverified output stated as fact: {t}"
            );
            assert!(t.contains("if this config verifies"), "{t}");
        }
        assert!(
            env_effect_text(Some(DowngradeApplied), ConfigTrust::Verified).starts_with("APPLIED")
        );
        assert!(UNVERIFIED_BANNER.starts_with("UNVERIFIED (vault locked)"));
        assert!(UNVERIFIED_BANNER.contains("the broker enforces only a verified config"));
    }

    /// Run a read-only approval subcommand with the env lock held.
    async fn v06_run_readonly(
        home: &std::path::Path,
        password: Option<&str>,
        cmd: ApprovalCommand,
    ) -> KvendraResult<()> {
        let _guard = crate::test_env_lock().lock().await;
        unsafe {
            std::env::set_var("KVENDRA_HOME", home);
            std::env::remove_var("KVENDRA_APPROVAL_MODE");
            match password {
                Some(p) => std::env::set_var("KVENDRA_PASSWORD", p),
                None => std::env::remove_var("KVENDRA_PASSWORD"),
            }
        }
        let r = run(cmd).await;
        unsafe {
            std::env::remove_var("KVENDRA_HOME");
            std::env::remove_var("KVENDRA_PASSWORD");
        }
        r
    }

    fn v06_flip_hmac(home: &std::path::Path) {
        let path = home.join("config.toml");
        let signed = std::fs::read_to_string(&path).unwrap();
        let idx = signed.rfind("_hmac = \"").unwrap() + "_hmac = \"".len();
        let mut bytes = signed.into_bytes();
        bytes[idx] = if bytes[idx] == b'a' { b'b' } else { b'a' };
        std::fs::write(&path, &bytes).unwrap();
    }

    #[tokio::test]
    async fn v06_get_and_status_fail_closed_on_tampered_config_when_unlockable() {
        let tmp = TempDir::new().unwrap();
        let _v = sa6_bootstrap_signed_policy(&tmp);
        v06_flip_hmac(tmp.path());
        let before = std::fs::read(tmp.path().join("config.toml")).unwrap();
        for cmd in [ApprovalCommand::Get, ApprovalCommand::Status] {
            let r = v06_run_readonly(tmp.path(), Some("hunter2-test"), cmd).await;
            let msg = r
                .expect_err("tampered config must exit non-zero")
                .to_string();
            assert!(msg.contains("config_tampered_detected"), "{msg}");
        }
        assert_eq!(
            before,
            std::fs::read(tmp.path().join("config.toml")).unwrap(),
            "read-only commands must never modify config.toml"
        );
    }

    #[tokio::test]
    async fn v06_get_verified_ok_on_genuine_config() {
        let tmp = TempDir::new().unwrap();
        let _v = sa6_bootstrap_signed_policy(&tmp);
        let r = v06_run_readonly(tmp.path(), Some("hunter2-test"), ApprovalCommand::Get).await;
        assert!(r.is_ok(), "{r:?}");
        let _guard = crate::test_env_lock().lock().await;
        unsafe { std::env::set_var("KVENDRA_PASSWORD", "hunter2-test") };
        let got = load_for_display(tmp.path(), "approval get");
        unsafe { std::env::remove_var("KVENDRA_PASSWORD") };
        let (cfg, trust) = got.unwrap();
        assert_eq!(trust, ConfigTrust::Verified);
        assert_eq!(cfg.approval.mode, ApprovalMode::Ask);
    }

    #[tokio::test]
    async fn v06_locked_vault_is_labelled_unverified() {
        let tmp = TempDir::new().unwrap();
        let _v = sa6_bootstrap_signed_policy(&tmp);
        v06_flip_hmac(tmp.path());
        // No KVENDRA_PASSWORD and no session blob → cannot verify: the command
        // still answers, but tagged UNVERIFIED.
        let r = v06_run_readonly(tmp.path(), None, ApprovalCommand::Status).await;
        assert!(r.is_ok(), "{r:?}");
        let _guard = crate::test_env_lock().lock().await;
        unsafe { std::env::remove_var("KVENDRA_PASSWORD") };
        let (_cfg, trust) = load_for_display(tmp.path(), "approval get").unwrap();
        assert_eq!(trust, ConfigTrust::Unverified);
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
