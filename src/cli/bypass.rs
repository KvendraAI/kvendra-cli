//! `kvendra bypass` / `protect` / `grant-pubkey` / `verify-grant` — the
//! break-glass CLI surface (REQ-KVD-SKILLS-41032D / ISSUE-KVD-CLI-238B54).
//!
//! - `kvendra bypass --ttl <dur> --ops <prim.op>[,...] [--password-stdin]
//!   [--rotate-key]` — grant a signed, scoped, TTL-bounded bypass for the
//!   current workspace. Requires a master password EVERY time (re-auth):
//!   the password is re-derived against the sentinel in a transient vault
//!   that is locked immediately after signing, so a live session is never
//!   extended or reused (AC-CLI-1). `--ops` is mandatory — a grant with no
//!   scope is rejected (OQ-3 secure default).
//! - `kvendra protect` — revoke the current workspace's grant immediately,
//!   idempotently, without any credential (mirror of `kvendra lock`,
//!   AC-CLI-2).
//! - `kvendra grant-pubkey` — print the pinned ed25519 public key (base64).
//!   Auth-less, read-only, no vault unlock (mirror of `kvendra
//!   capabilities`; consumed by `sync-claudemd` / the hook, AC-HOOK-3).
//! - `kvendra verify-grant` — internal verb consumed by the hook. Reads a
//!   JSON request on stdin, evaluates the grant fail-closed, prints a JSON
//!   verdict and exits 0 (applies) / 2 (fail-closed).
//!
//! TTL is mandatory and capped at the vault idle timeout — a grant must
//! never outlive the session that backs it (R-2 mitigation + TOCTOU
//! defence in `grant::verify`).

use crate::audit::{
    AuditEvent, AuditWriter, FLAG_BYPASS_GRANTED, FLAG_BYPASS_REVOKED, FLAG_BYPASS_SIG_INVALID,
    FLAG_BYPASS_USED, PRIMITIVE_SYSTEM, Severity, Status, reader::args_hash_hex,
};
use crate::config::{Config, kvendra_home};
use crate::error::{KvendraError, KvendraResult};
use crate::grant::verify::GrantDecision;
use crate::grant::{GrantPayload, SCHEMA_VERSION, key_id_for_pubkey};
use crate::session::ttl::{format_ttl, parse_ttl};
use crate::vault::Vault;
use base64::Engine;
use chrono::{Duration as ChronoDuration, Utc};
use clap::Args;
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroize;

#[derive(Debug, Args)]
pub struct BypassArgs {
    /// Grant TTL (mandatory): `15m`, `1h`, `2h`, ... Capped at the vault
    /// idle timeout — a grant cannot outlive its backing session.
    #[arg(long, value_name = "DURATION")]
    pub ttl: String,
    /// Comma-separated `primitive.op` tokens to relax, e.g.
    /// `kvendra.git.push,kvendra.aws.s3_sync`. MANDATORY — omitting it
    /// rejects the grant (no blind "off").
    #[arg(long, value_name = "PRIM.OP[,...]")]
    pub ops: Option<String>,
    /// Workspace root the grant applies to. Defaults to the current
    /// directory (the workspace the operator is sitting in).
    #[arg(long, value_name = "PATH")]
    pub workspace_root: Option<String>,
    /// Read the master password from stdin (recommended for scripts).
    #[arg(long)]
    pub password_stdin: bool,
    /// Rotate the grant-signing keypair before issuing this grant. Any
    /// previously pinned public key stops verifying.
    #[arg(long)]
    pub rotate_key: bool,
}

/// `kvendra bypass` entrypoint.
pub async fn run_bypass(args: BypassArgs) -> KvendraResult<()> {
    let home = kvendra_home()?;
    let cfg = Config::load(&home, None).unwrap_or_default();

    // --- Scope (AC-SCOPE-1 / OQ-3): mandatory, non-empty. ---
    let ops = parse_ops(args.ops.as_deref())?;

    // --- TTL (mandatory), capped at the vault idle timeout. ---
    let requested = parse_ttl(&args.ttl)?;
    let idle_cap = Duration::from_secs(u64::from(cfg.vault.idle_timeout_minutes) * 60);
    let ttl = cap_to_idle(requested, idle_cap)?;

    // --- Workspace resolution. ---
    let workspace_root = resolve_workspace_root(args.workspace_root.as_deref())?;
    let workspace_id = crate::grant::workspace_id_from_root(&workspace_root);

    // --- Re-auth: ALWAYS re-derive the vault key from a freshly typed
    //     password against the sentinel, in a transient vault we lock right
    //     after signing. This enforces re-auth uniformly whether the live
    //     vault is locked or unlocked, and never extends a live session
    //     (AC-CLI-1). ---
    let transient = Vault::new(home.clone());
    if !transient.sentinel_path().exists() {
        return Err(KvendraError::Vault(
            "vault not initialized. Run `kvendra init` first.".into(),
        ));
    }
    let mut password = read_master_password(args.password_stdin)?;
    let unlock_result = transient.unlock(password.as_bytes(), cfg.vault.idle_timeout_minutes);
    password.zeroize();
    unlock_result?; // InvalidMasterPassword bubbles up cleanly.

    // --- Signing key: load (or lazily generate / rotate). ---
    let signing = if args.rotate_key {
        crate::grant::keypair::generate(&home, &transient)?
    } else {
        crate::grant::keypair::load_or_generate(&home, &transient)?
    };
    let pubkey = signing.verifying_key();
    let key_id = key_id_for_pubkey(pubkey.to_bytes().as_slice());

    // --- Build + sign the grant payload. ---
    let now = Utc::now();
    let expires_at = now + ChronoDuration::seconds(ttl.as_secs() as i64);
    let payload = GrantPayload {
        schema_version: SCHEMA_VERSION,
        workspace_root: workspace_root.clone(),
        workspace_id: workspace_id.clone(),
        ops: ops.clone(),
        issued_at: now,
        expires_at,
        key_id,
        nonce: random_nonce_b64(),
    };
    let grant = crate::grant::sign::sign_grant(payload, &signing)?;
    crate::grant::store::persist_atomic(&grant, &home)?;

    // --- Audit (AC-CLI-5 / AC-AUDIT-1): a live unlocked transient vault
    //     gives us the HMAC sub-key, so this row persists to audit.db. ---
    if let Ok(hmac_key) = transient.audit_hmac_key() {
        let detail = serde_json::json!({
            "workspace_id": workspace_id,
            "ops": ops,
            "ttl_seconds": ttl.as_secs(),
            "expires_at": expires_at.to_rfc3339(),
        });
        let _ = record_event(
            &home,
            hmac_key,
            FLAG_BYPASS_GRANTED,
            Severity::Warn,
            "bypass_granted",
            &detail,
        )
        .await;
    }

    // Transient vault locked immediately — no live session is left behind.
    transient.lock();

    println!(
        "Bypass granted for '{}' — ops: [{}], TTL {} (expires {}).",
        workspace_id,
        ops.join(", "),
        format_ttl(ttl),
        expires_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!(
        "Revoke any time with `kvendra protect` (auto-revokes on `kvendra lock` / TTL expiry)."
    );
    Ok(())
}

/// `kvendra protect` — revoke the current workspace's grant. No credential.
pub async fn run_protect(workspace_root: Option<String>) -> KvendraResult<()> {
    let home = kvendra_home()?;
    let root = resolve_workspace_root(workspace_root.as_deref())?;
    let workspace_id = crate::grant::workspace_id_from_root(&root);
    let existed = crate::grant::store::revoke(&home, &workspace_id)?;

    // Same audit gap as `kvendra lock`: no master password here, so no HMAC
    // sub-key — surface the flag via tracing (OQ-7).
    tracing::info!(
        target: "kvendra::bypass",
        flag = FLAG_BYPASS_REVOKED,
        workspace_id = %workspace_id,
        grant_existed = existed,
        "bypass grant revoked"
    );
    if existed {
        println!("Protection restored for '{workspace_id}'. Grant revoked.");
    } else {
        println!("Protection already in effect for '{workspace_id}'. (No grant to revoke.)");
    }
    Ok(())
}

/// `kvendra grant-pubkey` — print the pinned ed25519 public key (base64).
/// Auth-less, read-only, no unlock (AC-HOOK-3).
pub fn run_grant_pubkey() -> KvendraResult<()> {
    let home = kvendra_home()?;
    let pubkey = crate::grant::keypair::load_public_key(&home)?;
    println!(
        "{}",
        base64::engine::general_purpose::STANDARD.encode(pubkey.to_bytes())
    );
    Ok(())
}

/// stdin request shape for `verify-grant` (IF-GRANT-VERIFY).
#[derive(serde::Deserialize)]
struct VerifyRequest {
    workspace_root: String,
    op: String,
    /// Base64 ed25519 public key the hook pins.
    pubkey: String,
}

/// stdout verdict shape for `verify-grant`.
#[derive(serde::Serialize)]
struct VerifyResponse {
    applies: bool,
    reason: &'static str,
}

/// `kvendra verify-grant` — internal, consumed by the hook. Reads a JSON
/// request on stdin, evaluates the grant fail-closed WITHOUT unlocking the
/// vault, prints the verdict, and exits 0 (applies) / 2 (fail-closed). Any
/// error in parsing / IO maps to exit 2 — never fail-open.
pub async fn run_verify_grant() -> KvendraResult<()> {
    let home = kvendra_home()?;
    let mut buf = String::new();
    use std::io::Read;
    if std::io::stdin().read_to_string(&mut buf).is_err() {
        emit_verdict_and_exit(GrantDecision::Malformed, &home, None).await;
    }
    let req: VerifyRequest = match serde_json::from_str(&buf) {
        Ok(r) => r,
        Err(_) => emit_verdict_and_exit(GrantDecision::Malformed, &home, None).await,
    };
    let verifying = match crate::grant::keypair::parse_public_key_b64(&req.pubkey) {
        Ok(v) => v,
        Err(_) => emit_verdict_and_exit(GrantDecision::SignatureInvalid, &home, None).await,
    };
    let decision = crate::grant::verify::verify_grant_applies(
        &home,
        &req.workspace_root,
        &req.op,
        &verifying,
        Utc::now(),
    );
    emit_verdict_and_exit(decision, &home, Some(&req)).await
}

/// Emit the JSON verdict, fire a best-effort tracing audit line, and exit
/// with the decision's code. Never returns.
async fn emit_verdict_and_exit(
    decision: GrantDecision,
    _home: &Path,
    req: Option<&VerifyRequest>,
) -> ! {
    let resp = VerifyResponse {
        applies: decision.applies(),
        reason: decision.reason(),
    };
    if let Ok(s) = serde_json::to_string(&resp) {
        println!("{s}");
    }
    // Audit the verification outcome. verify-grant runs without a password
    // (no HMAC sub-key), so — like `kvendra lock` — we surface the flag via
    // tracing rather than persisting to audit.db (OQ-7).
    let flag = match decision {
        GrantDecision::Apply => FLAG_BYPASS_USED,
        GrantDecision::Expired => crate::audit::FLAG_BYPASS_EXPIRED,
        GrantDecision::SignatureInvalid | GrantDecision::KeyIdMismatch => FLAG_BYPASS_SIG_INVALID,
        _ => "bypass_denied",
    };
    let op = req.map(|r| r.op.as_str()).unwrap_or("");
    let ws = req.map(|r| r.workspace_root.as_str()).unwrap_or("");
    tracing::info!(
        target: "kvendra::verify_grant",
        flag = flag,
        reason = decision.reason(),
        op = %op,
        workspace_root = %ws,
        "grant verification verdict"
    );
    std::process::exit(decision.exit_code());
}

// ───────────────────────── helpers ─────────────────────────

/// Parse + validate the `--ops` list. Mandatory and non-empty; each token
/// must look like `primitive.op` (at least one dot). Rejects blanks.
fn parse_ops(raw: Option<&str>) -> KvendraResult<Vec<String>> {
    let raw = raw.ok_or_else(|| {
        KvendraError::InvalidArgs(
            "`kvendra bypass` requires `--ops <prim.op>[,...]` — a bypass must declare its scope \
             (there is no blind off switch). Example: --ops kvendra.git.push,kvendra.aws.s3_sync"
                .into(),
        )
    })?;
    let mut ops: Vec<String> = Vec::new();
    for tok in raw.split(',') {
        let t = tok.trim();
        if t.is_empty() {
            continue;
        }
        if !t.contains('.') {
            return Err(KvendraError::InvalidArgs(format!(
                "invalid op '{t}' — expected `primitive.op` (e.g. kvendra.git.push)"
            )));
        }
        if !ops.contains(&t.to_string()) {
            ops.push(t.to_string());
        }
    }
    if ops.is_empty() {
        return Err(KvendraError::InvalidArgs(
            "`--ops` is empty after parsing — declare at least one `primitive.op` to relax".into(),
        ));
    }
    Ok(ops)
}

/// Cap a requested TTL to the vault idle timeout. A grant must never outlive
/// the session backing it. Rejects rather than silently shrinking so the
/// operator sees the constraint.
fn cap_to_idle(requested: Duration, idle_cap: Duration) -> KvendraResult<Duration> {
    if requested.as_secs() == 0 {
        return Err(KvendraError::InvalidArgs("TTL must be > 0".into()));
    }
    if requested > idle_cap {
        return Err(KvendraError::InvalidArgs(format!(
            "TTL {} exceeds the vault idle timeout {} — a grant cannot outlive its session. \
             Lower --ttl or raise `vault.idle_timeout_minutes`.",
            format_ttl(requested),
            format_ttl(idle_cap)
        )));
    }
    Ok(requested)
}

/// Resolve the workspace root: explicit `--workspace-root`, else CWD. The
/// path is canonicalized so the grant's `workspace_root` matches what the
/// hook (which canonicalizes its CWD) sends.
fn resolve_workspace_root(explicit: Option<&str>) -> KvendraResult<String> {
    let raw = match explicit {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::current_dir()
            .map_err(|e| KvendraError::InvalidArgs(format!("cannot read cwd: {e}")))?,
    };
    let canon = std::fs::canonicalize(&raw).unwrap_or(raw);
    Ok(canon.to_string_lossy().into_owned())
}

/// Read the master password from stdin / `KVENDRA_PASSWORD` / interactive
/// prompt. Mirror of `cli/secret.rs::read_master_password`.
fn read_master_password(password_stdin: bool) -> KvendraResult<String> {
    if password_stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .map_err(|e| KvendraError::Vault(format!("read password from stdin: {e}")))?;
        if buf.ends_with('\n') {
            buf.pop();
            if buf.ends_with('\r') {
                buf.pop();
            }
        }
        return Ok(buf);
    }
    if let Ok(p) = std::env::var("KVENDRA_PASSWORD")
        && !p.is_empty()
    {
        return Ok(p);
    }
    println!("Re-enter the master password to authorize the bypass (will not echo):");
    rpassword::read_password().map_err(|e| KvendraError::Vault(format!("read password: {e}")))
}

fn random_nonce_b64() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Short-lived `AuditWriter` that appends one row and shuts down cleanly.
/// Mirror of `cli/unlock.rs::record_event`.
async fn record_event(
    home: &Path,
    hmac_key: Vec<u8>,
    flag: &str,
    severity: Severity,
    action: &str,
    detail: &serde_json::Value,
) -> KvendraResult<()> {
    let writer = AuditWriter::spawn(home.join("audit.db"), hmac_key)?;
    let event = AuditEvent {
        ts_unix_ms: chrono::Utc::now().timestamp_millis(),
        profile_id: PRIMITIVE_SYSTEM.into(),
        primitive: PRIMITIVE_SYSTEM.into(),
        action: action.into(),
        args_hash_hex: args_hash_hex(detail),
        status: Status::Ok,
        severity,
        flags: flag.into(),
        remote_audit_id: None,
    };
    writer.record(event).await?;
    writer.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ops_rejects_missing() {
        assert!(parse_ops(None).is_err());
    }

    #[test]
    fn parse_ops_rejects_empty_and_blank() {
        assert!(parse_ops(Some("")).is_err());
        assert!(parse_ops(Some("  , ,")).is_err());
    }

    #[test]
    fn parse_ops_requires_dotted_tokens() {
        assert!(parse_ops(Some("push")).is_err());
        assert!(parse_ops(Some("kvendra.git.push")).is_ok());
    }

    #[test]
    fn parse_ops_dedups_and_trims() {
        let ops = parse_ops(Some(
            " kvendra.git.push , kvendra.git.push ,kvendra.aws.s3_sync",
        ))
        .unwrap();
        assert_eq!(ops, vec!["kvendra.git.push", "kvendra.aws.s3_sync"]);
    }

    #[test]
    fn cap_to_idle_rejects_overlong() {
        let cap = Duration::from_secs(30 * 60);
        assert!(cap_to_idle(Duration::from_secs(60 * 60), cap).is_err());
        assert_eq!(
            cap_to_idle(Duration::from_secs(15 * 60), cap).unwrap(),
            Duration::from_secs(15 * 60)
        );
    }

    #[test]
    fn cap_to_idle_rejects_zero() {
        assert!(cap_to_idle(Duration::from_secs(0), Duration::from_secs(1800)).is_err());
    }
}
