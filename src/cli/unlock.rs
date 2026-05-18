//! `kvendra unlock` — derive the master key into a session and persist a
//! cross-platform session blob (REQ-KVD-CLI-011 / ADR-KVD-029) so the
//! subprocess `kvendra mcp serve` can operate without re-prompting.
//!
//! Three behaviours:
//! - default: full unlock — anti-captured-env defense, password from TTY,
//!   write `~/.kvendra/sessions/active.blob`.
//! - `--extend`: refresh the TTL of an existing active session without
//!   asking for the password again.
//! - `KVENDRA_PASSWORD` env var: legacy CI path. Skips the TTY guard
//!   because there is no terminal to begin with — caller is responsible
//!   for the captured-env risk in that case.
//!
//! Also honours `master_password_cache` from `~/.kvendra/config.toml`:
//! - `ram-only` (default): always prompt for the master password.
//! - `os-keychain` (per ADR-KVD-012): sentinel-presence flag is updated
//!   after a successful unlock for the legacy interactive path.

use crate::captured_env::ensure_real_terminal;
use crate::cli::config_cmd::store_derived_key_in_keychain;
use crate::config::{Config, MasterPasswordCache, kvendra_home};
use crate::error::{KvendraError, KvendraResult};
use crate::session::local::{
    build_state_for_current_machine, extend_ttl as session_extend_ttl, persist_atomic,
};
use crate::session::ttl::{DEFAULT_TTL_SECONDS, format_ttl, parse_ttl};
use crate::vault::Vault;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use clap::Args;
use std::time::Duration;

#[derive(Debug, Args)]
pub struct UnlockArgs {
    /// Read password from env var (testing/CI). Skips the anti-captured-env
    /// TTY guard because non-interactive environments have no TTY by
    /// definition.
    #[arg(long, env = "KVENDRA_PASSWORD")]
    pub password_env: Option<String>,
    /// Refresh the TTL of the existing session without re-prompting. Fails
    /// if there is no active session or if it has expired (run `kvendra
    /// unlock` without `--extend` instead).
    #[arg(long, conflicts_with = "password_env")]
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

    let ttl = resolve_ttl(args.ttl.as_deref())?;

    if args.extend {
        let new_expires = session_extend_ttl(&home, ttl)?;
        println!(
            "Session extended. New TTL: {} (expires {}).",
            format_ttl(ttl),
            format_human_iso(new_expires)
        );
        return Ok(());
    }

    // Anti-captured-env defense (PAT-KVD-CLI-008). Skipped only when the
    // caller passed `KVENDRA_PASSWORD` — non-interactive by definition.
    let tty_handle = if args.password_env.is_none() {
        match ensure_real_terminal() {
            Ok(h) => Some(h),
            Err(rejection) => {
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

    let password = match args.password_env {
        Some(s) => s,
        None => {
            let handle = tty_handle.as_ref().expect("set when password_env is None");
            handle
                .read_password("Enter the master password (will not echo): ")
                .map_err(|e| KvendraError::Vault(format!("read password: {e}")))?
        }
    };

    vault.unlock(password.as_bytes(), cfg.vault.idle_timeout_minutes)?;

    // REQ-KVD-008: auto-migrate a pre-REQ-008 config.toml on first unlock
    // post-upgrade (silent if already signed). Then re-load with the vault
    // attached so the HMAC verification + home_canonical check run.
    crate::config::auto_migrate_config_if_needed(&home, &vault)?;
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

    println!(
        "Vault unlocked. Session TTL: {} (expires {}).",
        format_ttl(ttl),
        format_human_iso(expires_at)
    );
    Ok(())
}

fn resolve_ttl(flag: Option<&str>) -> KvendraResult<Duration> {
    match flag {
        Some(raw) => parse_ttl(raw),
        None => Ok(Duration::from_secs(DEFAULT_TTL_SECONDS)),
    }
}

fn format_human_iso(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}
