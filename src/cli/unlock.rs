//! `kvendra unlock` — derive the master key into a session and persist a
//! cross-platform session blob (REQ-KVD-CLI-011 / ADR-KVD-029) so the
//! subprocess `kvendra mcp serve` can operate without re-prompting.
//!
//! Three behaviours:
//! - default: full unlock — anti-captured-env defense, password from TTY,
//!   write `~/.kvendra/sessions/active.blob`.
//! - `--extend`: refresh the TTL of an existing active session. Since v0.6.4
//!   this RE-AUTHENTICATES with the master password (finding A1): extending a
//!   privileged session is a privileged action, so it can no longer be looped
//!   to keep a session alive forever without the password.
//! - `KVENDRA_PASSWORD` env var: legacy CI path. Skips the TTY guard
//!   because there is no terminal to begin with — caller is responsible
//!   for the captured-env risk in that case.
//!
//! Also honours `master_password_cache` from `~/.kvendra/config.toml`:
//! - `ram-only` (default): always prompt for the master password.
//! - `os-keychain` (per ADR-KVD-012): sentinel-presence flag is updated
//!   after a successful unlock for the legacy interactive path.

use crate::audit::{
    AuditEvent, AuditWriter, FLAG_UNLOCK_EXTENDED, FLAG_UNLOCK_SUCCEEDED, PRIMITIVE_SYSTEM,
    Severity, Status, reader::args_hash_hex,
};
use crate::captured_env::ensure_real_terminal;
use crate::cli::config_cmd::store_derived_key_in_keychain;
use crate::config::{Config, MasterPasswordCache, kvendra_home};
use crate::error::{KvendraError, KvendraResult};
use crate::session::local::{
    build_state_for_current_machine, extend_ttl as session_extend_ttl, persist_atomic,
};
use crate::session::ttl::{cap_ttl, format_ttl, parse_ttl};
use crate::vault::Vault;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use clap::Args;
use std::path::Path;
use std::time::Duration;
use time::OffsetDateTime;
use zeroize::Zeroize;

#[derive(Debug, Args)]
pub struct UnlockArgs {
    /// Read password from env var (testing/CI). Skips the anti-captured-env
    /// TTY guard because non-interactive environments have no TTY by
    /// definition.
    #[arg(long, env = "KVENDRA_PASSWORD")]
    pub password_env: Option<String>,
    /// Refresh the TTL of the existing session. Re-authenticates with the
    /// master password (v0.6.4, finding A1) — reads it from the TTY, or from
    /// `KVENDRA_PASSWORD` for unattended automation. Fails if there is no
    /// active session or if it has expired (run `kvendra unlock` without
    /// `--extend` instead). No longer conflicts with `KVENDRA_PASSWORD`, since
    /// extension now needs the password like a full unlock.
    #[arg(long)]
    pub extend: bool,
    /// Override the TTL (e.g. `30m`, `4h`, `8h`, `1d`). Default `4h`.
    /// Subject to `session.max_ttl` cap once configurable (Turn 5).
    #[arg(long, value_name = "DURATION")]
    pub ttl: Option<String>,
    /// Force prompting even if keychain caching is enabled (legacy
    /// REQ-KVD-005 path).
    #[arg(long)]
    pub no_keychain: bool,
}

pub async fn run(args: UnlockArgs) -> KvendraResult<()> {
    let home = kvendra_home()?;
    let cfg = Config::load(&home, None).unwrap_or_default();
    let vault = Vault::new(home.clone());

    if !vault.sentinel_path().exists() {
        return Err(KvendraError::Vault(
            "vault not initialized. Run `kvendra init` first.".into(),
        ));
    }

    let ttl = resolve_ttl(args.ttl.as_deref(), &cfg.session)?;

    // Anti-captured-env defense (PAT-KVD-CLI-008). Skipped only when the
    // caller passed `KVENDRA_PASSWORD` — non-interactive by definition.
    //
    // Hoisted above the `--extend` branch in v0.6.4: extending a session's
    // TTL now re-authenticates too (finding A1 below), so BOTH a full unlock
    // and an extend read the master password here, TTY-guarded when
    // interactive.
    let tty_handle = if args.password_env.is_none() {
        match ensure_real_terminal() {
            Ok(h) => Some(h),
            Err(rejection) => {
                // Pre-unlock: the HMAC sub-key is not yet available, so we
                // cannot persist this row in `audit.db`. Surface the flag
                // via tracing so it lands in stderr / log aggregators —
                // same gap pattern as ADR-KVD-020 AC-USE-KEYCHAIN-8.
                tracing::warn!(
                    target: "kvendra::unlock",
                    flag = rejection.audit_flag(),
                    "unlock rejected (pre-unlock audit gap)"
                );
                eprintln!("{}", rejection.render());
                return Err(KvendraError::Vault(format!(
                    "unlock refused: {}",
                    rejection.audit_flag()
                )));
            }
        }
    } else {
        None
    };

    let mut password = match args.password_env {
        Some(s) => s,
        None => {
            let handle = tty_handle.as_ref().expect("set when password_env is None");
            handle
                .read_password("Enter the master password (will not echo): ")
                .map_err(|e| KvendraError::Vault(format!("read password: {e}")))?
        }
    };

    if args.extend {
        // ISSUE-KVD-CLI-B78ED5 cycle-3 finding A1 — RE-AUTHENTICATE on extend.
        // Pre-0.6.4 `--extend` bumped the session TTL straight from the
        // on-disk blob with NO password, no presence, no anti-captured-env
        // guard. So any process running as the owner could keep a session —
        // and therefore the broker's credential access — alive indefinitely
        // by looping `kvendra unlock --extend --ttl <max>`, defeating the
        // absolute-TTL gate the design advertises, all without ever knowing
        // the master password.
        //
        // Extension is a privileged action, so it now proves knowledge of the
        // master password, exactly like `kvendra bypass` (whose own comment
        // reads "never extends a live session"). We verify in a TRANSIENT
        // vault that we lock immediately, so no new live session is created
        // by the check itself.
        let transient = Vault::new(home.clone());
        let mut pw = password;
        let unlock_result = transient.unlock(pw.as_bytes(), cfg.vault.idle_timeout_minutes);
        pw.zeroize();
        unlock_result?; // InvalidMasterPassword bubbles up cleanly.
        transient.lock();

        let new_expires = session_extend_ttl(&home, ttl)?;
        // Audit FLAG_UNLOCK_EXTENDED — the transient unlock above gives us the
        // HMAC sub-key so this row persists to audit.db.
        let _ = audit_session_event(
            &home,
            cfg.vault.idle_timeout_minutes,
            FLAG_UNLOCK_EXTENDED,
            Severity::Info,
            "session_extended",
        )
        .await;
        println!(
            "Session extended. New TTL: {} (expires {}).",
            format_ttl(ttl),
            format_human_iso(new_expires)
        );
        return Ok(());
    }

    // Zeroize the plaintext master password after use, on both success and
    // error paths (mirrors the `--extend` path hardened for A1; `String::drop`
    // frees but does not wipe the heap buffer).
    let unlock_res = vault.unlock(password.as_bytes(), cfg.vault.idle_timeout_minutes);
    password.zeroize();
    unlock_res?;

    // REQ-KVD-008 + finding A5: re-load the config with the vault attached so
    // the HMAC verification + home_canonical check run. A config that is not
    // validly signed (tampered: trailer removed or content appended after it)
    // is now REJECTED here rather than silently adopted and re-signed — the
    // pre-0.6.4 `auto_migrate_config_if_needed` re-sign was the launderer that
    // made the config-integrity bypass invisible, so it is no longer invoked
    // on unlock.
    let _signed_cfg = Config::load(&home, Some(&vault))?;

    // Persist the local session blob so `kvendra mcp serve` can unlock the
    // vault on its own. The derived key is consumed by
    // `LocalSessionState`, which zeroizes it on `Drop` after `persist_atomic`
    // serialises it under the machine-bound wrap key.
    let derived = vault.peek_session_derived_key()?;
    let state = build_state_for_current_machine(derived, ttl, &home)?;
    let expires_at = state.expires_at;
    persist_atomic(&state, &home)?;

    // Legacy ADR-KVD-012 sentinel: update the OS keychain "presence flag"
    // if the user opted in. Does not store the derived key itself.
    if !args.no_keychain && cfg.vault.master_password_cache == MasterPasswordCache::OsKeychain {
        let _ = store_derived_key_in_keychain(&B64.encode(b"kvendra-keychain-sentinel-v1"));
    }

    // Audit FLAG_UNLOCK_SUCCEEDED. We have a live SessionKey, so we can
    // pull the audit HMAC sub-key directly from the vault we just unlocked.
    if let Ok(hmac_key) = vault.audit_hmac_key() {
        let _ = record_event(
            &home,
            hmac_key,
            FLAG_UNLOCK_SUCCEEDED,
            Severity::Info,
            "unlock",
        )
        .await;
    }

    println!(
        "Vault unlocked. Session TTL: {} (expires {}).",
        format_ttl(ttl),
        format_human_iso(expires_at)
    );
    Ok(())
}

/// Bring up a short-lived `AuditWriter`, append a single row tagged with
/// `flag`, and shut down cleanly. Mirrors the pattern in
/// `audit::bootstrap::write_vault_created_event` so the flushed `.db` /
/// `.db-wal` files stay coherent.
async fn record_event(
    home: &Path,
    hmac_key: Vec<u8>,
    flag: &str,
    severity: Severity,
    action: &str,
) -> KvendraResult<()> {
    let writer = AuditWriter::spawn(home.join("audit.db"), hmac_key)?;
    let event = AuditEvent {
        ts_unix_ms: OffsetDateTime::now_utc().unix_timestamp_nanos() as i64 / 1_000_000,
        profile_id: PRIMITIVE_SYSTEM.into(),
        primitive: PRIMITIVE_SYSTEM.into(),
        action: action.into(),
        args_hash_hex: args_hash_hex(&serde_json::json!({})),
        status: Status::Ok,
        severity,
        flags: flag.into(),
        remote_audit_id: None,
        error_code: None,
        error_message: None,
    };
    writer.record(event).await?;
    writer.shutdown().await;
    Ok(())
}

/// `--extend` cannot reuse the `record_event` path directly because the
/// vault was never unlocked in this process — we only touched the on-disk
/// blob. Take a short-lived unlock from the same blob to fetch the HMAC
/// sub-key, write the row, and let the vault Drop wipe the in-RAM copy.
async fn audit_session_event(
    home: &Path,
    idle_timeout_minutes: u32,
    flag: &str,
    severity: Severity,
    action: &str,
) -> KvendraResult<()> {
    let vault = Vault::new(home.to_path_buf());
    let state =
        crate::session::local::load(home).map_err(crate::session::local::map_reject_to_error)?;
    vault.unlock_from_derived_key(&state.derived_key, idle_timeout_minutes)?;
    if let Ok(hmac_key) = vault.audit_hmac_key() {
        record_event(home, hmac_key, flag, severity, action).await?;
    }
    vault.lock();
    Ok(())
}

fn resolve_ttl(
    flag: Option<&str>,
    session_cfg: &crate::config::SessionConfig,
) -> KvendraResult<Duration> {
    let max = Duration::from_secs(session_cfg.max_ttl_seconds);
    match flag {
        Some(raw) => cap_ttl(parse_ttl(raw)?, max),
        None => Ok(Duration::from_secs(session_cfg.default_ttl_seconds)),
    }
}

fn format_human_iso(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::local::{
        build_state_for_current_machine, persist_atomic, status as local_status,
    };
    use crate::vault::kdf::KdfParams;
    use std::time::Duration as StdDuration;

    fn fast_params() -> KdfParams {
        KdfParams {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: vec![1u8; 16],
        }
    }

    /// Seed a vault + a live session blob (TTL 1h) in `home`, then leave the
    /// vault locked (fresh-process shape).
    fn seed_vault_and_session(home: &std::path::Path, password: &[u8]) {
        crate::config::ensure_layout(home).unwrap();
        let v = Vault::new(home.to_path_buf());
        v.create_with_params(password, fast_params()).unwrap();
        v.unlock(password, 30).unwrap();
        let derived = v.peek_session_derived_key().unwrap();
        let state =
            build_state_for_current_machine(derived, StdDuration::from_secs(3600), home).unwrap();
        persist_atomic(&state, home).unwrap();
        v.lock();
    }

    /// ISSUE-KVD-CLI-B78ED5 cycle-3 finding A1 — `kvendra unlock --extend`
    /// must re-authenticate: a wrong password is rejected and leaves the
    /// session TTL untouched; the correct password extends it. Pre-0.6.4 the
    /// extend path took NO password at all.
    #[tokio::test]
    async fn extend_requires_master_password() {
        let _guard = crate::test_env_lock().lock().await;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        seed_vault_and_session(home, b"hunter2-extend");

        let expires_before = local_status(home).expires_at.expect("session active");

        unsafe {
            std::env::set_var("KVENDRA_HOME", home);
            std::env::remove_var("KVENDRA_APPROVAL_MODE");
        }

        // Wrong password → rejected, blob untouched.
        let wrong = run(UnlockArgs {
            password_env: Some("wrong-password".into()),
            extend: true,
            ttl: Some("2h".into()),
            no_keychain: true,
        })
        .await;
        assert!(
            matches!(wrong, Err(KvendraError::InvalidMasterPassword)),
            "extend with a wrong password must be rejected, got {wrong:?}"
        );
        let expires_after_wrong = local_status(home).expires_at.expect("still active");
        assert_eq!(
            expires_before, expires_after_wrong,
            "a rejected extend must NOT change the session TTL"
        );

        // Correct password → extends.
        let ok = run(UnlockArgs {
            password_env: Some("hunter2-extend".into()),
            extend: true,
            ttl: Some("2h".into()),
            no_keychain: true,
        })
        .await;
        assert!(
            ok.is_ok(),
            "extend with the correct password must succeed: {ok:?}"
        );
        let expires_after_ok = local_status(home).expires_at.expect("still active");
        assert!(
            expires_after_ok > expires_before,
            "a correct extend must push expires_at out (was {expires_before}, now {expires_after_ok})"
        );

        unsafe {
            std::env::remove_var("KVENDRA_HOME");
        }
    }
}
