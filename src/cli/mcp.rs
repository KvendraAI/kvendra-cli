//! `kvendra mcp serve` — start the JSON-RPC MCP server on stdio.
//!
//! The MCP server runs in the same process as the unlocked vault session
//! (the Argon2id-derived key is RAM-only per ADR-KVD-012). Order of
//! preference for obtaining that key, in this release:
//!
//! 1. **Local session blob** (REQ-KVD-CLI-011 / ADR-KVD-029) — the
//!    canonical cross-platform path. The derived key is read directly
//!    from `~/.kvendra/sessions/active.blob` (machine-bound wrap key +
//!    HMAC + TTL). `kvendra unlock` writes it from the user's own
//!    terminal, so the MCP subprocess never needs a password.
//! 2. `--use-keychain` (REQ-KVD-005, macOS only) — legacy keychain ACL
//!    path. Feature-preserved off-by-default until Apple Developer ID
//!    is available (ROAD-KVD-CLI-002 v0.3.0+ nice-to-have).
//! 3. `--password-env` (also reads `KVENDRA_MCP_PASSWORD`) — plaintext
//!    env var. Legacy CI workaround.
//!
//! No interactive TTY prompt fallback: the MCP server is spawned as a
//! subprocess of a client (Claude Code, Cursor, ...) that captures stdio,
//! so prompting would either deadlock or leak the password to the LLM.
//! If none of the three sources above is available, the server refuses
//! to start with an actionable error pointing to `kvendra unlock`.

use crate::audit::{
    FLAG_SESSION_BLOB_MACHINE_MISMATCH, FLAG_SESSION_BLOB_TAMPERED, FLAG_SESSION_EXPIRED_AT_READ,
};
use crate::config::{Config, kvendra_home};
use crate::error::{KvendraError, KvendraResult};
use crate::keychain_acl::{self, BiometricError};
use crate::session::local::{SessionLoadReject, load as load_local_session};
use crate::vault::Vault;
use clap::{Args, Subcommand};
use std::path::Path;

const MCP_PASSWORD_LABEL: &str = "kvendra/mcp-password/v1";

#[derive(Debug, Subcommand)]
pub enum McpCommand {
    /// Start the MCP server on stdio (JSON-RPC 2.0).
    Serve(ServeArgs),
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Read master password from this env var (CI/non-interactive, legacy path).
    #[arg(
        long,
        env = "KVENDRA_MCP_PASSWORD",
        conflicts_with_all = ["use_keychain", "no_unlock"]
    )]
    pub password_env: Option<String>,
    /// Read master password from the OS keychain with biometric/presence ACL
    /// (macOS only in this release — see REQ-KVD-005 / PAT-KVD-007).
    #[arg(long, conflicts_with_all = ["password_env", "no_unlock"])]
    pub use_keychain: bool,
    /// Skip the unlock step (audit log will be disabled — V4 relaxed).
    #[arg(long)]
    pub no_unlock: bool,
}

pub async fn run(cmd: McpCommand) -> KvendraResult<()> {
    match cmd {
        McpCommand::Serve(args) => {
            let home = kvendra_home()?;
            crate::config::ensure_layout(&home)?;
            // Pre-unlock load: vault is locked here. Signed-config invariants
            // are re-verified inside `serve_with_vault` once the vault is
            // unlocked (REQ-KVD-008).
            let cfg = Config::load(&home, None).unwrap_or_default();
            let vault = Vault::new(home.clone());
            if !args.no_unlock && vault.sentinel_path().exists() {
                attach_session_key(&vault, &home, &args, cfg.vault.idle_timeout_minutes).await?;
            }
            // TTL re-check on every tool call is intentionally deferred
            // post-alpha.1: the derived key already lives in this process's
            // RAM, so killing the session mid-flight requires teardown +
            // client notification design that is out of scope for v0.2.0.
            // The blob TTL gates the *next* `mcp serve` start, not the
            // current one — matching `aws sso` / `gcloud` semantics.
            crate::mcp::server::serve_with_vault(vault).await
        }
    }
}

/// Attempt every supported unlock path in priority order. Mutates `vault`
/// in place on success. Returns a clear error pointing the user at
/// `kvendra unlock` when nothing works.
async fn attach_session_key(
    vault: &Vault,
    home: &Path,
    args: &ServeArgs,
    idle_timeout_minutes: u32,
) -> KvendraResult<()> {
    // 1) Local session blob — canonical cross-platform path.
    match load_local_session(home) {
        Ok(state) => {
            // `state` carries the derived key (zeroized on Drop). We feed it
            // into the vault and let `state` go out of scope at the end of
            // this function so the local copy is wiped from the stack.
            if vault
                .unlock_from_derived_key(&state.derived_key, idle_timeout_minutes)
                .is_ok()
            {
                return Ok(());
            }
            // Sentinel mismatch means the blob is from a different vault —
            // fall through to the legacy paths so the user can still recover
            // with --password-env / --use-keychain.
        }
        // Map each reject variant to its canonical audit flag (REQ-KVD-CLI-011
        // AC-SESSION-14). Pre-unlock: no HMAC sub-key available, so the flag
        // surfaces via tracing — same gap pattern as ADR-KVD-020.
        Err(SessionLoadReject::NotInitialized) => { /* no blob → just fall through */ }
        Err(SessionLoadReject::Expired { expired_at }) => {
            tracing::warn!(
                target: "kvendra::mcp",
                flag = FLAG_SESSION_EXPIRED_AT_READ,
                %expired_at,
                "session blob TTL elapsed"
            );
        }
        Err(SessionLoadReject::HmacMismatch) => {
            tracing::error!(
                target: "kvendra::mcp",
                flag = FLAG_SESSION_BLOB_TAMPERED,
                "session blob HMAC mismatch — possible tamper"
            );
        }
        Err(SessionLoadReject::MachineMismatch { field }) => {
            tracing::warn!(
                target: "kvendra::mcp",
                flag = FLAG_SESSION_BLOB_MACHINE_MISMATCH,
                mismatched_field = field,
                "session blob from a different machine"
            );
        }
        Err(other) => {
            tracing::warn!(
                target: "kvendra::mcp",
                "session blob unreadable: {other:?}"
            );
        }
    }

    // 2) Legacy explicit unlock paths (REQ-KVD-005 / mcp-password env var).
    if args.use_keychain || args.password_env.is_some() {
        let password = resolve_password(args).await?;
        return vault.unlock(password.as_bytes(), idle_timeout_minutes);
    }

    // 3) REQ-KVD-CLI-42CB74 — tolerant boot. Nothing available, but we no
    // longer refuse to start: the MCP server boots in `LockedPendingUnlock`
    // state. `whoami` / `help` / `config_get` (when present) keep working;
    // every vault-dependent tool call returns JSON-RPC `-32002` with
    // `help.topic:"vault-locked-pending-unlock"` until the user runs
    // `kvendra unlock` in their own terminal. The dispatcher's self-heal
    // loop transitions the vault to `Unlocked` on the next tool call once
    // the session blob lands on disk — no Claude Code restart needed.
    // Supersedes the partial PAT-KVD-009 fix ("restart Claude Code").
    eprintln!("[kvendra mcp serve] Started in locked-pending-unlock state.");
    eprintln!(
        "[kvendra mcp serve] Vault-dependent tool calls will fail until 'kvendra unlock' is executed."
    );
    eprintln!(
        "[kvendra mcp serve] The MCP server will auto-recover transparently — no restart needed."
    );

    tracing::warn!(
        target: "kvendra::mcp",
        flag = "mcp_boot_locked_pending_unlock",
        "MCP server booted without active session"
    );

    vault.mark_pending_unlock();
    Ok(())
}

async fn resolve_password(args: &ServeArgs) -> KvendraResult<String> {
    if args.use_keychain {
        return read_keychain_password();
    }
    match &args.password_env {
        Some(s) => Ok(s.clone()),
        None => {
            eprintln!("Enter the master password (will not echo):");
            rpassword::read_password()
                .map_err(|e| KvendraError::Vault(format!("read password: {e}")))
        }
    }
}

fn read_keychain_password() -> KvendraResult<String> {
    match keychain_acl::read_with_user_presence(MCP_PASSWORD_LABEL) {
        Ok(p) => {
            tracing::info!(
                target: "kvendra::mcp",
                flag = "mcp_password_keychain_acl_unlock",
                "MCP password retrieved from keychain via presence ACL"
            );
            Ok(p)
        }
        Err(BiometricError::Rejected) => {
            tracing::warn!(
                target: "kvendra::mcp",
                flag = "mcp_password_keychain_acl_rejected",
                "User rejected biometric/presence prompt"
            );
            Err(KvendraError::BiometricRejected)
        }
        Err(BiometricError::NotFound(label)) => {
            tracing::error!(
                target: "kvendra::mcp",
                flag = "mcp_password_keychain_item_missing",
                %label,
                "No keychain entry — run `kvendra config mcp-password enable` first"
            );
            Err(KvendraError::Vault(format!(
                "keychain item '{label}' not found — run `kvendra config mcp-password enable`"
            )))
        }
        Err(BiometricError::Unavailable(msg)) => {
            tracing::error!(
                target: "kvendra::mcp",
                flag = "mcp_password_keychain_unavailable",
                "{msg}"
            );
            Err(KvendraError::BiometricUnavailable(msg))
        }
        Err(BiometricError::Backend(msg)) => {
            tracing::error!(
                target: "kvendra::mcp",
                flag = "mcp_password_keychain_unavailable",
                "{msg}"
            );
            Err(KvendraError::Keychain(msg))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::kdf::KdfParams;
    use crate::vault::session::VaultStateKind;

    fn fast_params() -> KdfParams {
        KdfParams {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: vec![1u8; 16],
        }
    }

    /// REQ-KVD-CLI-42CB74 AC-BOOT-1 + AC-UX-2 — when `attach_session_key`
    /// is invoked without ANY credential material (no session blob, no
    /// env var, no keychain), it MUST return `Ok(())` and leave the
    /// vault in `LockedPendingUnlock` state, instead of failing the
    /// boot. This is the core behavioural change of REQ-KVD-CLI-42CB74.
    ///
    /// We do not assert on the stderr lines here — capturing stderr from
    /// within an async test requires gag/serial_test or process-level
    /// redirection that adds fragility for marginal benefit. The
    /// behaviour-observable outcome is the vault state + Ok return.
    #[tokio::test]
    async fn attach_session_key_returns_ok_without_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        crate::config::ensure_layout(home).unwrap();
        let v = Vault::new(home.to_path_buf());
        // Initialise sentinel so attach_session_key reaches the real branches.
        v.create_with_params(b"hunter2-pending-boot", fast_params())
            .unwrap();

        let args = ServeArgs {
            password_env: None,
            use_keychain: false,
            no_unlock: false,
        };
        // No session blob, no env var, no keychain → path #4.
        let res = super::attach_session_key(&v, home, &args, 30).await;
        assert!(
            res.is_ok(),
            "attach_session_key must Ok(()) when no creds available — got {res:?}"
        );
        assert_eq!(
            v.state(),
            VaultStateKind::LockedPendingUnlock,
            "vault must end in LockedPendingUnlock after tolerant boot"
        );
    }

    /// REQ-KVD-CLI-42CB74 AC-REGRESSION-1 — boot path #1 (local session
    /// blob) must continue to fully unlock the vault, NOT leave it in
    /// pending state. Mirrors the canonical `kvendra unlock` flow from
    /// REQ-KVD-CLI-011.
    #[tokio::test]
    async fn boot_path_1_active_blob_unchanged_regression() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        crate::config::ensure_layout(home).unwrap();
        let v = Vault::new(home.to_path_buf());
        v.create_with_params(b"hunter2-path1", fast_params())
            .unwrap();

        // Write a valid session blob using the canonical helpers.
        v.unlock(b"hunter2-path1", 30).unwrap();
        let derived = v.peek_session_derived_key().unwrap();
        let state = crate::session::local::build_state_for_current_machine(
            derived,
            std::time::Duration::from_secs(3600),
            home,
        )
        .unwrap();
        crate::session::local::persist_atomic(&state, home).unwrap();
        v.lock();
        assert_eq!(v.state(), VaultStateKind::Locked);

        let args = ServeArgs {
            password_env: None,
            use_keychain: false,
            no_unlock: false,
        };
        let res = super::attach_session_key(&v, home, &args, 30).await;
        assert!(res.is_ok());
        assert_eq!(
            v.state(),
            VaultStateKind::Unlocked,
            "boot path #1 must fully unlock from active.blob (no pending state)"
        );
    }

    /// REQ-KVD-CLI-42CB74 AC-REGRESSION-1 — boot path #2 (env var) must
    /// continue to fully unlock the vault using the master password
    /// supplied via `KVENDRA_MCP_PASSWORD` / `--password-env`.
    #[tokio::test]
    async fn boot_path_2_password_env_unchanged_regression() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        crate::config::ensure_layout(home).unwrap();
        let v = Vault::new(home.to_path_buf());
        v.create_with_params(b"hunter2-path2", fast_params())
            .unwrap();
        // No session blob on disk — path #1 falls through to #2.
        assert_eq!(v.state(), VaultStateKind::Locked);

        let args = ServeArgs {
            password_env: Some("hunter2-path2".to_string()),
            use_keychain: false,
            no_unlock: false,
        };
        let res = super::attach_session_key(&v, home, &args, 30).await;
        assert!(
            res.is_ok(),
            "env-var boot path must succeed with correct password, got {res:?}"
        );
        assert_eq!(
            v.state(),
            VaultStateKind::Unlocked,
            "boot path #2 (env var) must fully unlock — no pending state"
        );
    }

    // Boot path #3 (`--use-keychain`) is NOT covered here: it requires
    // macOS keychain ACL hardware that is unavailable in CI / non-Apple
    // builds. Validator FASE 5 (winking-owl-skills:validator) MUST exercise
    // path #3 manually on a Mac box, asserting the vault transitions to
    // Unlocked (no pending) when biometric/presence ACL succeeds.
}
