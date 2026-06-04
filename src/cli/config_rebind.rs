//! `kvendra config rebind-home --new-path <path>` — triple-barrier home rebind.
//!
//! REQ-KVD-008 / ISSUE-019 closes the home_redirect_detected gap by allowing
//! a legitimate move of `~/.kvendra/` (e.g. user reorganises their home, moves
//! to an encrypted volume, copies the laptop). The flow is intentionally
//! expensive — three independent barriers must all succeed before the rebind
//! is committed:
//!
//! 1. **Master password** unlock (standard `Vault::unlock`).
//! 2. **Recovery code** validation. The code is *validated* (Argon2id verify,
//!    unconsumed) but NOT marked at this stage — a wrong-target re-typed path
//!    in step 3 must not burn a slot.
//! 3. **TTY confirmation**. The user re-types the destination path verbatim
//!    (no `[y/N]` shortcut). The typed path is canonicalized and compared to
//!    the `--new-path` target. Only on success do we (a) consume the recovery
//!    slot atomically, (b) re-save `config.toml` with the new `home_canonical`,
//!    (c) emit the `home_rebound` audit row at severity `warn`.
//!
//! Strict no-TTY policy (D4=A): if `stdin` is not a terminal, the command
//! rejects with [`KvendraError::RebindRequiresTty`]. This blocks legitimate
//! automation; the workaround is to invoke the command in an interactive
//! shell on the destination machine.

use crate::audit::{AuditEvent, AuditWriter, PRIMITIVE_SYSTEM, Severity, Status};
use crate::config::{Config, ensure_layout, kvendra_home, set_file_mode_secure};
use crate::error::{KvendraError, KvendraResult};
use crate::vault::Vault;
use crate::vault::recovery::{RecoveryCodesFile, mark_code_consumed, validate_code_unconsumed};
use clap::Args;
use sha2::{Digest, Sha256};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

#[derive(Debug, Args)]
pub struct RebindHomeArgs {
    /// Destination path that the vault will be re-anchored to. Must exist
    /// and contain the moved `~/.kvendra/` layout (sentinel.blob, etc.).
    #[arg(long = "new-path")]
    pub new_path: PathBuf,
    /// Skip the interactive TTY confirmation step. Reserved for tests; the
    /// production CLI rejects non-TTY invocations regardless of this flag.
    #[cfg(test)]
    #[arg(long, hide = true)]
    pub test_assume_tty: bool,
}

#[cfg(not(test))]
impl RebindHomeArgs {
    fn assume_tty_override(&self) -> bool {
        false
    }
}

#[cfg(test)]
impl RebindHomeArgs {
    fn assume_tty_override(&self) -> bool {
        self.test_assume_tty
    }
}

pub async fn run(args: RebindHomeArgs) -> KvendraResult<()> {
    let prev_home = kvendra_home()?;
    ensure_layout(&prev_home)?;

    let new_home = &args.new_path;
    if !new_home.exists() {
        return Err(KvendraError::Config(format!(
            "rebind-home: destination '{}' does not exist",
            new_home.display()
        )));
    }

    // Strict no-TTY policy (D4=A).
    if !args.assume_tty_override() && !std::io::stdin().is_terminal() {
        return Err(KvendraError::RebindRequiresTty);
    }

    // Read inputs from env vars / TTY before delegating to the testable core.
    let password = match std::env::var("KVENDRA_PASSWORD") {
        Ok(s) => s,
        Err(_) => {
            println!("[1/3] Master password (will not echo):");
            rpassword::read_password()
                .map_err(|e| KvendraError::Vault(format!("read password: {e}")))?
        }
    };
    let code_input = match std::env::var("KVENDRA_REBIND_RECOVERY_CODE") {
        Ok(s) => s,
        Err(_) => {
            println!("[2/3] Recovery code (will not echo):");
            rpassword::read_password()
                .map_err(|e| KvendraError::Vault(format!("read recovery code: {e}")))?
        }
    };

    // D9 UX banner BEFORE the typed-path prompt.
    let new_canon_preview = std::fs::canonicalize(new_home)
        .map_err(|e| KvendraError::Config(format!("canonicalize {}: {e}", new_home.display())))?;
    let prev_canon_preview = std::fs::canonicalize(&prev_home)
        .map_err(|e| KvendraError::Config(format!("canonicalize prev home: {e}")))?;
    let cfg_sha256 =
        sha256_of_path(&prev_home.join("config.toml")).unwrap_or_else(|_| "<unavailable>".into());
    println!();
    println!("[3/3] Confirm rebind. The following side-effects WILL be applied:");
    println!("      - config.toml re-signed with new home_canonical");
    println!("      - recovery slot will be marked CONSUMED for 'home_rebound' (one-shot)");
    println!("      - audit row 'home_rebound' (severity=warn) appended");
    println!();
    println!("      Diff:");
    println!(
        "        prev_home_canonical: {}",
        prev_canon_preview.display()
    );
    println!(
        "        new_home_canonical:  {}",
        new_canon_preview.display()
    );
    println!("        config.toml SHA-256: {cfg_sha256}");
    println!();
    println!("Re-type the FULL destination path to confirm:");
    let mut typed = String::new();
    std::io::stdin()
        .read_line(&mut typed)
        .map_err(|e| KvendraError::Config(format!("read confirmation: {e}")))?;

    let outcome = rebind_inner(
        &prev_home,
        new_home,
        password.as_bytes(),
        code_input.trim(),
        typed.trim(),
    )
    .await?;

    println!();
    println!("OK. Vault re-anchored to {}.", outcome.new_canon.display());
    println!(
        "Recovery slot #{} is now consumed (one-shot).",
        outcome.consumed_slot
    );
    println!(
        "Note: `kvendra config recovery-codes regenerate` is not yet \
         available; track the follow-up ISSUE in the KB v3."
    );
    Ok(())
}

/// Outcome of a successful `rebind_inner` call. Surfaced to the CLI shell
/// for stdout messaging and consumed by integration tests.
#[derive(Debug)]
pub struct RebindOutcome {
    pub new_canon: PathBuf,
    pub consumed_slot: usize,
}

/// Testable core of the triple-barrier rebind flow. Side-effects are
/// committed in this exact order:
/// 1. `Vault::unlock` (master password barrier).
/// 2. `validate_code_unconsumed` (recovery code barrier — NO mutation yet).
/// 3. typed-path canonicalize + compare to `new_path` canonicalized
///    (typed-confirmation barrier).
/// 4. `mark_code_consumed` + atomic write of `recovery_codes.json` (0600).
/// 5. `Config::save` at the NEW home (or fall back to re-saving at the
///    previous home with the new canonical path).
/// 6. `home_rebound` audit row at severity `warn`.
pub async fn rebind_inner(
    prev_home: &Path,
    new_path: &Path,
    master_password: &[u8],
    recovery_code: &str,
    typed_path: &str,
) -> KvendraResult<RebindOutcome> {
    let new_canon = std::fs::canonicalize(new_path)
        .map_err(|e| KvendraError::Config(format!("canonicalize {}: {e}", new_path.display())))?;
    let prev_canon = std::fs::canonicalize(prev_home)
        .map_err(|e| KvendraError::Config(format!("canonicalize prev home: {e}")))?;

    // Barrier 1 — master password unlock.
    let vault = Vault::new(prev_home.to_path_buf());
    if !vault.sentinel_path().exists() {
        return Err(KvendraError::Vault(
            "vault not initialized at current KVENDRA_HOME — run `kvendra init` first".into(),
        ));
    }
    vault.unlock(master_password, 30)?;

    // Barrier 2 — recovery code validate-but-not-consume.
    let codes_path = vault.recovery_codes_path();
    if !codes_path.exists() {
        return Err(KvendraError::Vault(
            "recovery_codes.json missing — vault was not initialized with REQ-008 binary".into(),
        ));
    }
    let mut codes_file: RecoveryCodesFile =
        serde_json::from_str(&std::fs::read_to_string(&codes_path)?)?;
    let slot_idx = match validate_code_unconsumed(&codes_file, recovery_code) {
        Ok(idx) => idx,
        Err(KvendraError::RecoveryCodeAlreadyUsed {
            slot,
            used_for,
            used_at,
        }) => {
            // REQ-KVD-CLI-002 / ISSUE-026 — emit a DEDICATED audit row tagged
            // `recovery_code_replay_attempted` BEFORE returning the error to
            // the caller. The audit log is the only place where forensic
            // tooling can spot a replay attempt, so the row must be written
            // even though the rebind itself aborts.
            //
            // AC-3 of ISSUE-026: the raw recovery code MUST NOT appear in any
            // field of the audit row. We hash `prev_canon | slot` only.
            let writer = AuditWriter::spawn(vault.audit_db_path(), vault.audit_hmac_key()?)?;
            let args_hash = sha256_hex(format!("{}|{}", prev_canon.display(), slot));
            let event = AuditEvent {
                ts_unix_ms: time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64
                    / 1_000_000,
                profile_id: String::new(),
                primitive: PRIMITIVE_SYSTEM.to_string(),
                action: "home_rebound_attempt".to_string(),
                args_hash_hex: args_hash,
                status: Status::Error,
                severity: Severity::Warn,
                flags: format!("recovery_code_replay_attempted,slot_{slot}"),
                remote_audit_id: None,
                // System replay-detection row — the forensic signal is the
                // flag; the primitive error taxonomy does not apply here.
                error_code: None,
                error_message: None,
            };
            writer.record(event).await?;
            writer.shutdown().await;
            return Err(KvendraError::RecoveryCodeAlreadyUsed {
                slot,
                used_for,
                used_at,
            });
        }
        Err(e) => return Err(e),
    };

    // Barrier 3 — typed-path confirmation.
    let typed_canon = std::fs::canonicalize(PathBuf::from(typed_path)).map_err(|e| {
        KvendraError::Config(format!("canonicalize typed path '{typed_path}': {e}"))
    })?;
    if typed_canon != new_canon {
        // Recovery slot was NOT consumed yet — we abort cleanly.
        return Err(KvendraError::RebindConfirmationMismatch);
    }

    // ───────────────────────────────────────────────────────────────────
    // Post-confirmation: commit side effects.
    // ───────────────────────────────────────────────────────────────────

    // 1. Mark the recovery slot consumed and write the file with 0600 perms.
    mark_code_consumed(&mut codes_file, slot_idx, "home_rebound");
    let tmp = codes_path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(&codes_file)?)?;
    set_file_mode_secure(&tmp)?;
    std::fs::rename(&tmp, &codes_path)?;
    set_file_mode_secure(&codes_path)?;

    // 2. Re-save the config at the NEW home with the new canonical path.
    //    The new_home directory must already contain a usable vault layout
    //    (the user is expected to have moved `~/.kvendra/` already).
    let new_vault = Vault::new(new_canon.clone());
    if new_vault.sentinel_path().exists() {
        new_vault.unlock(master_password, 30)?;
        let cfg_at_new = Config::load(&new_canon, Some(&new_vault)).unwrap_or_default();
        cfg_at_new.save(&new_canon, &new_vault)?;
    } else {
        // Fall back to re-saving at the previous (still-active) home with
        // the new canonical path encoded — useful in tests where the user
        // is rebinding without physically moving the directory yet.
        let mut cfg = Config::load(prev_home, Some(&vault)).unwrap_or_default();
        cfg.vault.home_canonical = Some(new_canon.to_string_lossy().into_owned());
        cfg.save(prev_home, &vault)?;
    }

    // 3. Audit row (D8 schema).
    let writer = AuditWriter::spawn(vault.audit_db_path(), vault.audit_hmac_key()?)?;
    let args_hash = sha256_hex(format!(
        "{}|{}|{}",
        prev_canon.display(),
        new_canon.display(),
        slot_idx
    ));
    let event = AuditEvent {
        ts_unix_ms: time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64 / 1_000_000,
        profile_id: String::new(),
        primitive: PRIMITIVE_SYSTEM.to_string(),
        action: "home_rebound".into(),
        args_hash_hex: args_hash,
        status: Status::Ok,
        severity: Severity::Warn,
        flags: format!("home_rebound,recovery_code_consumed:slot_{slot_idx}"),
        remote_audit_id: None,
        error_code: None,
        error_message: None,
    };
    writer.record(event).await?;
    writer.shutdown().await;

    Ok(RebindOutcome {
        new_canon,
        consumed_slot: slot_idx,
    })
}

fn sha256_hex(s: impl AsRef<[u8]>) -> String {
    let mut h = Sha256::new();
    h.update(s.as_ref());
    hex::encode(h.finalize())
}

fn sha256_of_path(path: &Path) -> KvendraResult<String> {
    let bytes = std::fs::read(path)?;
    Ok(sha256_hex(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::kdf::KdfParams;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use tempfile::TempDir;

    fn fast_params() -> KdfParams {
        KdfParams {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: vec![1u8; 16],
        }
    }

    fn bootstrap_vault(home: &Path) -> Vault {
        ensure_layout(home).unwrap();
        let v = Vault::new(home.to_path_buf());
        v.create_with_params(b"hunter2-test", fast_params())
            .unwrap();
        v.unlock(b"hunter2-test", 30).unwrap();
        // Persist a single recovery code with fast Argon2id params.
        let code = "1111-2222-33";
        let salt = vec![0x42u8; 16];
        let params = KdfParams {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: salt.clone(),
        };
        let h = crate::vault::kdf::derive(code.as_bytes(), &params).unwrap();
        let stored = RecoveryCodesFile {
            codes: vec![crate::vault::recovery::StoredCode {
                hash_b64: B64.encode(h.as_bytes()),
                salt_b64: B64.encode(&salt),
                used_at: None,
                used_for: None,
            }],
        };
        std::fs::write(
            v.recovery_codes_path(),
            serde_json::to_string_pretty(&stored).unwrap(),
        )
        .unwrap();
        // Persist a signed config so the load side has something to verify.
        Config::default().save(home, &v).unwrap();
        v
    }

    /// REQ-KVD-008 AC-REBIND-4 — strict reject when stdin is not a TTY (D4=A).
    /// Test-only flag `--test-assume-tty=false` keeps the production policy.
    #[tokio::test]
    async fn rebind_home_no_tty_rejects_strict() {
        // We exercise the production path: `assume_tty_override()` returns
        // false unless `--test-assume-tty` is passed. In the cargo test
        // harness `stdin` is typically not a TTY, so the strict reject hits.
        let tmp = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        let _v = bootstrap_vault(tmp.path());
        // `tokio::sync::Mutex` is async-aware so holding it across the
        // single await inside the block is permitted.
        let _guard = crate::test_env_lock().lock().await;
        let r = {
            unsafe {
                std::env::set_var("KVENDRA_HOME", tmp.path());
            }
            let args = RebindHomeArgs {
                new_path: dest.path().to_path_buf(),
                test_assume_tty: false,
            };
            // `run` short-circuits on the no-TTY check before the first
            // await — running it as a future and polling once would also
            // work, but a sync block_on inside a tokio test is awkward.
            // We accept the lock-across-await for this single test and
            // silence clippy locally if needed.
            let result = run(args).await;
            unsafe {
                std::env::remove_var("KVENDRA_HOME");
            }
            result
        };
        assert!(
            matches!(r, Err(KvendraError::RebindRequiresTty)),
            "expected RebindRequiresTty, got {r:?}"
        );
    }

    /// REQ-KVD-008 AC-REBIND-1 — barrier 1 wrong master password rejects
    /// before either the recovery code or the typed-path are evaluated.
    #[tokio::test]
    async fn rebind_home_requires_master_password_unlock() {
        let tmp = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        let _v = bootstrap_vault(tmp.path());
        let r = rebind_inner(
            tmp.path(),
            dest.path(),
            b"WRONG-PASSWORD",
            "1111-2222-33",
            dest.path().to_string_lossy().as_ref(),
        )
        .await;
        assert!(
            matches!(r, Err(KvendraError::InvalidMasterPassword)),
            "expected InvalidMasterPassword, got {r:?}"
        );
    }

    /// REQ-KVD-008 AC-REBIND-2 — barrier 2 wrong recovery code rejects after
    /// password unlock but BEFORE the typed-path is evaluated. The slot stays
    /// unconsumed.
    #[tokio::test]
    async fn rebind_home_requires_recovery_code_match() {
        let tmp = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        let _v = bootstrap_vault(tmp.path());
        let r = rebind_inner(
            tmp.path(),
            dest.path(),
            b"hunter2-test",
            "0000-0000-00",
            dest.path().to_string_lossy().as_ref(),
        )
        .await;
        assert!(
            matches!(r, Err(KvendraError::RecoveryCodeInvalid)),
            "expected RecoveryCodeInvalid, got {r:?}"
        );
        let codes_raw = std::fs::read_to_string(tmp.path().join("recovery_codes.json")).unwrap();
        assert!(
            !codes_raw.contains("home_rebound"),
            "slot must NOT be marked consumed"
        );
    }

    /// REQ-KVD-008 AC-REBIND-3 — happy path: all three barriers pass and the
    /// slot is marked CONSUMED with `used_for = "home_rebound"`.
    #[tokio::test]
    async fn rebind_home_consume_marks_slot_used_for_home_rebound() {
        let tmp = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        let _v = bootstrap_vault(tmp.path());
        let outcome = rebind_inner(
            tmp.path(),
            dest.path(),
            b"hunter2-test",
            "1111-2222-33",
            dest.path().to_string_lossy().as_ref(),
        )
        .await
        .unwrap();
        assert_eq!(outcome.consumed_slot, 0);
        let codes_raw = std::fs::read_to_string(tmp.path().join("recovery_codes.json")).unwrap();
        assert!(codes_raw.contains("home_rebound"));
    }

    /// REQ-KVD-008 — happy path also re-signs the config at the previous home
    /// with `home_canonical` pointing at the new canonicalized path.
    #[tokio::test]
    async fn rebind_home_re_signs_config_with_new_home_canonical() {
        let tmp = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        let _v = bootstrap_vault(tmp.path());
        let _ = rebind_inner(
            tmp.path(),
            dest.path(),
            b"hunter2-test",
            "1111-2222-33",
            dest.path().to_string_lossy().as_ref(),
        )
        .await
        .unwrap();
        let raw = std::fs::read_to_string(tmp.path().join("config.toml")).unwrap();
        let dest_canon = std::fs::canonicalize(dest.path()).unwrap();
        assert!(
            raw.contains(&*dest_canon.to_string_lossy()),
            "re-signed config must reference the new canonical home"
        );
        assert!(
            raw.contains("_hmac = \""),
            "re-signed config must carry an HMAC trailer"
        );
    }

    /// REQ-KVD-008 — replay attempt: after the slot is consumed, a second
    /// rebind with the same recovery code is rejected with
    /// `RecoveryCodeAlreadyUsed`.
    #[tokio::test]
    async fn rebind_home_replay_recovery_code_rejected() {
        let tmp = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        let dest2 = TempDir::new().unwrap();
        let _v = bootstrap_vault(tmp.path());
        let _ = rebind_inner(
            tmp.path(),
            dest.path(),
            b"hunter2-test",
            "1111-2222-33",
            dest.path().to_string_lossy().as_ref(),
        )
        .await
        .unwrap();
        let r = rebind_inner(
            tmp.path(),
            dest2.path(),
            b"hunter2-test",
            "1111-2222-33",
            dest2.path().to_string_lossy().as_ref(),
        )
        .await;
        assert!(
            matches!(
                r,
                Err(KvendraError::RecoveryCodeAlreadyUsed { slot: 0, .. })
            ),
            "expected RecoveryCodeAlreadyUsed{{slot:0}}, got {r:?}"
        );
    }

    /// REQ-KVD-008 D8 — happy path emits an audit row with `severity = warn`,
    /// `primitive = kvendra.system`, `action = home_rebound`, and the slot id
    /// in the flags CSV.
    #[tokio::test]
    async fn rebind_home_audit_row_severity_warn_with_slot_id() {
        let tmp = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        let _v = bootstrap_vault(tmp.path());
        let _ = rebind_inner(
            tmp.path(),
            dest.path(),
            b"hunter2-test",
            "1111-2222-33",
            dest.path().to_string_lossy().as_ref(),
        )
        .await
        .unwrap();
        let conn = rusqlite::Connection::open(tmp.path().join("audit.db")).unwrap();
        let (action, severity, flags, primitive): (String, String, String, String) = conn
            .query_row(
                "SELECT action, severity, flags, primitive FROM audit_events \
                 WHERE action = 'home_rebound' ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(action, "home_rebound");
        assert_eq!(severity, "warn");
        assert_eq!(primitive, "kvendra.system");
        assert!(flags.contains("recovery_code_consumed:slot_0"));
        assert!(flags.contains("home_rebound"));
    }

    /// REQ-KVD-008 — typed-path mismatch rejects without consuming the slot.
    #[tokio::test]
    async fn rebind_home_typed_mismatch_rejects_without_consuming_slot() {
        let tmp = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        let other = TempDir::new().unwrap();
        let _v = bootstrap_vault(tmp.path());
        let r = rebind_inner(
            tmp.path(),
            dest.path(),
            b"hunter2-test",
            "1111-2222-33",
            other.path().to_string_lossy().as_ref(),
        )
        .await;
        assert!(
            matches!(r, Err(KvendraError::RebindConfirmationMismatch)),
            "expected RebindConfirmationMismatch, got {r:?}"
        );
        let codes_raw = std::fs::read_to_string(tmp.path().join("recovery_codes.json")).unwrap();
        assert!(
            !codes_raw.contains("home_rebound"),
            "slot must NOT be marked consumed when the typed path mismatches"
        );
    }

    // ----------------------------------------------------------------------
    // REQ-KVD-CLI-002 / ISSUE-026 — recovery-code replay attempts emit a
    // dedicated `recovery_code_replay_attempted` audit row BEFORE the error
    // is propagated to the caller. The raw code MUST NOT appear in any field.
    // ----------------------------------------------------------------------

    /// AC-1 — a second rebind with an already-consumed code emits a row
    /// with action `home_rebound_attempt`, primitive `kvendra.system`, status
    /// `error`, severity `warn`, and the canonical flag
    /// `recovery_code_replay_attempted` (plus the slot id).
    #[tokio::test]
    async fn replay_attempt_emits_recovery_code_replay_attempted_flag() {
        let tmp = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        let dest2 = TempDir::new().unwrap();
        let _v = bootstrap_vault(tmp.path());

        // First call consumes slot 0.
        let _ = rebind_inner(
            tmp.path(),
            dest.path(),
            b"hunter2-test",
            "1111-2222-33",
            dest.path().to_string_lossy().as_ref(),
        )
        .await
        .unwrap();
        // Second call replays the same code — must be rejected AND emit the
        // dedicated audit row.
        let r = rebind_inner(
            tmp.path(),
            dest2.path(),
            b"hunter2-test",
            "1111-2222-33",
            dest2.path().to_string_lossy().as_ref(),
        )
        .await;
        assert!(matches!(
            r,
            Err(KvendraError::RecoveryCodeAlreadyUsed { slot: 0, .. })
        ));
        // Allow the writer thread to flush the row.
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        let conn = rusqlite::Connection::open(tmp.path().join("audit.db")).unwrap();
        let (action, severity, status, flags, primitive): (String, String, String, String, String) =
            conn.query_row(
                "SELECT action, severity, status, flags, primitive FROM audit_events \
                 WHERE action = 'home_rebound_attempt' ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(action, "home_rebound_attempt");
        assert_eq!(severity, "warn");
        assert_eq!(status, "error");
        assert_eq!(primitive, "kvendra.system");
        assert!(
            flags.contains("recovery_code_replay_attempted"),
            "flags must contain the canonical replay flag: {flags}"
        );
        assert!(
            flags.contains("slot_0"),
            "flags must encode the slot id: {flags}"
        );
    }

    /// AC-2 — three replay attempts produce three distinct audit rows so
    /// forensic counts reflect the actual attempt count.
    #[tokio::test]
    async fn replay_three_attempts_produce_three_rows() {
        let tmp = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        let _v = bootstrap_vault(tmp.path());
        // Consume slot 0 first.
        let _ = rebind_inner(
            tmp.path(),
            dest.path(),
            b"hunter2-test",
            "1111-2222-33",
            dest.path().to_string_lossy().as_ref(),
        )
        .await
        .unwrap();
        // Three replay attempts.
        for _ in 0..3 {
            let dest_n = TempDir::new().unwrap();
            let _ = rebind_inner(
                tmp.path(),
                dest_n.path(),
                b"hunter2-test",
                "1111-2222-33",
                dest_n.path().to_string_lossy().as_ref(),
            )
            .await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;

        let conn = rusqlite::Connection::open(tmp.path().join("audit.db")).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_events WHERE action = 'home_rebound_attempt' \
                 AND flags LIKE '%recovery_code_replay_attempted%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 3, "expected 3 replay rows, got {count}");
    }

    /// AC-3 — the raw recovery code MUST NOT appear in any audit-row column,
    /// including `args_hash_hex` (which we derive from `prev_canon | slot`).
    #[tokio::test]
    async fn replay_args_hash_does_not_contain_plain_code() {
        let tmp = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        let dest2 = TempDir::new().unwrap();
        let _v = bootstrap_vault(tmp.path());
        let _ = rebind_inner(
            tmp.path(),
            dest.path(),
            b"hunter2-test",
            "1111-2222-33",
            dest.path().to_string_lossy().as_ref(),
        )
        .await
        .unwrap();
        let _ = rebind_inner(
            tmp.path(),
            dest2.path(),
            b"hunter2-test",
            "1111-2222-33",
            dest2.path().to_string_lossy().as_ref(),
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        let conn = rusqlite::Connection::open(tmp.path().join("audit.db")).unwrap();
        let (args_hash, flags, action): (String, String, String) = conn
            .query_row(
                "SELECT args_hash_hex, flags, action FROM audit_events \
                 WHERE action = 'home_rebound_attempt' ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(action, "home_rebound_attempt");
        // Nothing in the row may equal or contain the literal code.
        let code = "1111-2222-33";
        assert!(
            !args_hash.contains(code),
            "args_hash leaked code: {args_hash}"
        );
        assert!(!flags.contains(code), "flags leaked code: {flags}");
    }
}
