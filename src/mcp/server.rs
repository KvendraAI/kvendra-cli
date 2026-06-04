//! MCP dispatcher with audit hooks + allowlist enforcement + detection.
//!
//! Per AC-AUDIT-1 each `tools/call` records a `Status::Started` event in
//! the audit log BEFORE invoking the primitive, then updates the row to
//! `Ok` / `Error` after execution.
//!
//! Per AC-MCP-3 no plaintext credential ever rides on the response wire,
//! save for the documented `kvendra.unsafe.raw_token` exception.
//!
//! Per ADR-KVD-010 + ADR-KVD-012 the audit-HMAC key is derived from the
//! current session via HKDF-SHA256. If the vault is locked when the server
//! starts, the dispatcher logs to stderr and refuses to record audit rows.

use crate::allowlist::{ProfileSpec, check as allowlist_check, validate as allowlist_validate};
use crate::approval::{self, ApprovalCache, Transport};
use crate::audit::reader::args_hash_hex;
use crate::audit::{
    AuditEvent, AuditWriter, FLAG_TOOL_CALL_BLOCKED_PENDING_UNLOCK, PRIMITIVE_SYSTEM, Severity,
    Status,
};
use crate::config::Config;
use crate::detection::{Decision, detect};
use crate::error::{KvendraError, KvendraResult};
use crate::mcp::protocol::{
    InitializeResult, JsonRpcRequest, JsonRpcResponse, ServerInfo, ToolDescriptor, ToolsListResult,
    codes,
};
use crate::mcp::transport::StdioTransport;
use crate::primitives::catalog;
use crate::secret_resolver::{CallCtx, SecretResolver};
use crate::session::{SessionState, list_active_sessions};
use crate::vault::session::VaultStateKind;
use crate::vault::{SecretPlaintext, Vault};
use chrono::Utc;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::{Mutex, RwLock};

const PROTOCOL_VERSION: &str = "2025-03-26";

/// Outcome returned by [`enforce_allowlist`] when the allowlist check passes.
///
/// Distinguishes the steady-state `Unchanged` path from the rare `Migrated`
/// path where a legacy profile (no `allowlist_hmac_hex` persisted) was
/// auto-signed during this call. Callers can ignore the variant for control
/// flow — the dispatcher does — but the type makes the side-effect visible
/// in the signature so future audit hooks can react to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationOutcome {
    Unchanged,
    Migrated,
}

/// Server-side context shared across all dispatch calls.
pub struct ServerContext {
    pub vault: Vault,
    pub config: Config,
    /// Audit writer slot. Wrapped in `RwLock<Option<_>>` (interior
    /// mutability) so the dispatcher can lazy-spawn the writer the first
    /// time the vault transitions from `LockedPendingUnlock` to `Unlocked`
    /// via `try_self_heal_vault` — fixes ISSUE-KVD-CLI-9764AC where audit
    /// rows were silently dropped post-self-heal because the writer was
    /// constructed `None` at boot and never reconciled.
    ///
    /// `AuditWriter` is `Clone` (it wraps an `mpsc::Sender`), so callers
    /// take a short read lock, clone the handle out, drop the lock, and
    /// await on the clone — never holding the lock across `.await`.
    pub writer: std::sync::RwLock<Option<AuditWriter>>,
    /// Approve-all-5min cache (REQ-KVD-003 / ADR-KVD-014). Per-profile, in-mem.
    pub approval_cache: Arc<ApprovalCache>,
    /// Serializa los prompts de approval concurrentes (REQ-KVD-003 risk
    /// mitigation): solo un prompt activo a la vez.
    pub approval_prompt_lock: Arc<Mutex<()>>,
    /// Transport canal del approval flow (REQ-KVD-006 / ADR-KVD-021).
    /// Inicializado a `Transport::Mcp` desde `serve_with_vault`; tests
    /// pure-policy pueden construir un `ServerContext` con `Transport::Cli`.
    pub transport: Transport,
    /// Secret resolver injected at startup (REQ-KVD-CLI-004 AC-RESOLVER-4).
    /// `None` only when neither a workspace session nor an unlocked vault is
    /// available — in that case `tools/call` short-circuits with the usual
    /// VaultLocked / ProfileNotFound errors via the legacy path.
    pub resolver: Option<Arc<dyn SecretResolver>>,
    /// Shared session state when running in workspace mode. `None` in local
    /// (standalone) mode. Cloned into the proactive refresh background task.
    pub session: Option<Arc<RwLock<SessionState>>>,
    /// Workspace identifier this server is bound to (mirrors
    /// `session.workspace_id`). Used by allowlist sync + stale-blocked checks.
    pub workspace_id: Option<String>,
}

impl ServerContext {
    /// Returns a cloned handle to the audit writer if one is attached, or
    /// `None` if the vault is still locked and the writer has not been
    /// spawned yet. Cheap: `AuditWriter` is an mpsc::Sender wrapper that is
    /// `Clone`. Read lock is held only across the clone — never across
    /// `.await`.
    pub fn audit_writer(&self) -> Option<AuditWriter> {
        // Recover from a poisoned lock instead of panicking: a panic on the
        // audit side must not be able to tear down the serve task on the next
        // `tools/call` (ISSUE-KVD-CLI-330251 hardening). The audit writer is
        // an mpsc::Sender wrapper; reading it after a panic on another thread
        // is safe.
        self.writer
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    /// Lazy-spawn the audit writer if it is currently `None`. Used by
    /// `try_self_heal_vault` to reconcile the writer slot after a
    /// `LockedPendingUnlock` → `Unlocked` transition (fixes
    /// ISSUE-KVD-CLI-9764AC). Returns `Ok(true)` when a writer was just
    /// spawned, `Ok(false)` when one was already present (idempotent), and
    /// `Err` only if the vault refuses to mint the HMAC sub-key (which
    /// should never happen on the success path of self-heal because the
    /// caller has just transitioned the vault to `Unlocked`).
    fn ensure_audit_writer_spawned(&self) -> KvendraResult<bool> {
        // Fast path: writer already present — release the read lock and
        // return without touching the vault.
        if self
            .writer
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .is_some()
        {
            return Ok(false);
        }
        let key = self.vault.audit_hmac_key()?;
        let db_path = self.vault.home().join("audit.db");
        let mut guard = self
            .writer
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        // Re-check inside the write lock to avoid double-spawn under racing
        // self-heal attempts (two `tools/call` arriving within microseconds).
        if guard.is_some() {
            return Ok(false);
        }
        *guard = Some(AuditWriter::spawn(db_path, key)?);
        Ok(true)
    }
}

/// Run the MCP server until the client disconnects (creates a fresh `Vault`
/// pointed at `home`; the vault is locked unless the caller has already
/// unlocked it via `Vault::unlock`).
pub async fn serve(home: PathBuf) -> KvendraResult<()> {
    crate::config::ensure_layout(&home)?;
    let vault = Vault::new(home.clone());
    serve_with_vault(vault).await
}

/// Run the MCP server with an already-constructed `Vault` (typically already
/// unlocked by the CLI entrypoint).
pub async fn serve_with_vault(vault: Vault) -> KvendraResult<()> {
    let home = vault.home().to_path_buf();
    crate::config::ensure_layout(&home)?;
    // Load with the unlocked vault when available so the HMAC verifies and
    // any home-redirect attack is detected before the broker accepts traffic.
    let config = Config::load(
        &home,
        if vault.is_unlocked() {
            Some(&vault)
        } else {
            None
        },
    )
    .unwrap_or_default();

    // The audit writer needs the HMAC sub-key, which comes from the unlocked
    // session. If locked, we degrade: audit rows are NOT appended and the
    // dispatcher logs a warning to stderr (per ADR-KVD-010 + ADR-KVD-012).
    let writer = match vault.audit_hmac_key() {
        Ok(key) => Some(AuditWriter::spawn(home.join("audit.db"), key)?),
        Err(_) => {
            eprintln!(
                "kvendra mcp serve: vault is locked — audit log disabled. Run \
                 `kvendra unlock` before serving for full security."
            );
            None
        }
    };

    // REQ-KVD-CLI-004 AC-RESOLVER-4 — pick Local vs Remote based on session
    // presence. Multi-session ambiguity is resolved by KVENDRA_ACTIVE_WORKSPACE.
    let (resolver, session_arc, workspace_id) = build_resolver(&home, &vault)?;

    // REQ-KVD-CLI-008 AC-JWT-5 — proactive refresh in a tokio background
    // task. Wakes every 60s; refreshes when the cached JWT is within 5min
    // of expiry. Errors are logged; the next tools/call surfaces
    // WorkspaceSessionExpired explicitly.
    if let Some(session) = session_arc.clone() {
        let home_bg = home.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                match crate::auth::refresh::refresh_if_needed(&home_bg, &session).await {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(
                            target: "kvendra::auth",
                            error = %e,
                            "background refresh failed"
                        );
                    }
                }
            }
        });
    }

    // REQ-KVD-CLI-009 AC-ALLOWSYNC-1 — full sync on startup + periodic ticks
    // every N minutes (default 5).
    if let (Some(session), Some(ws_id)) = (session_arc.clone(), workspace_id.clone()) {
        let home_bg = home.clone();
        let ws_id_owned = ws_id.clone();
        tokio::spawn(async move {
            // Initial full sync — best effort.
            let jwt = session.read().await.jwt.clone();
            if let Err(e) =
                crate::workspace::allowlist_sync::sync_once(&home_bg, &ws_id_owned, &jwt, true)
                    .await
            {
                tracing::warn!(
                    target: "kvendra::workspace",
                    workspace = %ws_id_owned,
                    error = %e,
                    "initial allowlist sync failed"
                );
            }
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
                u64::from(crate::workspace::allowlist_sync::DEFAULT_SYNC_INTERVAL_MINUTES) * 60,
            ));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await; // consume immediate tick
            loop {
                ticker.tick().await;
                let jwt = session.read().await.jwt.clone();
                match crate::workspace::allowlist_sync::sync_once(
                    &home_bg,
                    &ws_id_owned,
                    &jwt,
                    false,
                )
                .await
                {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(
                            target: "kvendra::workspace",
                            workspace = %ws_id_owned,
                            error = %e,
                            "allowlist sync tick failed"
                        );
                    }
                }
            }
        });
    }

    let ctx = Arc::new(ServerContext {
        vault,
        config,
        writer: std::sync::RwLock::new(writer),
        approval_cache: Arc::new(ApprovalCache::new()),
        approval_prompt_lock: Arc::new(Mutex::new(())),
        transport: Transport::Mcp,
        resolver,
        session: session_arc,
        workspace_id,
    });
    let mut transport = StdioTransport::new();

    // Track how the serve loop ends so a future disconnect leaves a trace
    // (ISSUE-KVD-CLI-330251 observability). A clean `Ok(None)` is a real EOF
    // on stdin; an `Err` is a transport/read failure.
    let mut served: u64 = 0;
    let exit_result = loop {
        match transport.read().await {
            Ok(Some(req)) => {
                let resp = dispatch(req, ctx.clone()).await;
                if let Err(e) = transport.write(&resp).await {
                    break Err(e);
                }
                served += 1;
            }
            Ok(None) => {
                tracing::info!(
                    served_requests = served,
                    "MCP serve loop ended: clean EOF on stdin (client closed the request pipe)"
                );
                break Ok(());
            }
            Err(e) => {
                tracing::warn!(
                    served_requests = served,
                    error = %e,
                    "MCP serve loop ended: transport read error on stdin"
                );
                break Err(e);
            }
        }
    };

    if let Some(w) = ctx.audit_writer() {
        w.shutdown().await;
    }
    exit_result
}

/// Select the [`SecretResolver`] implementation based on the presence of
/// workspace session tokens under `~/.kvendra/sessions/`. Per
/// REQ-KVD-CLI-004 AC-RESOLVER-4:
///  - 0 sessions → `LocalVaultResolver`.
///  - 1 session  → `RemoteBrokerResolver` bound to that workspace.
///  - ≥2 sessions → require `KVENDRA_ACTIVE_WORKSPACE`; else error.
#[allow(clippy::type_complexity)]
fn build_resolver(
    home: &std::path::Path,
    vault: &Vault,
) -> KvendraResult<(
    Option<Arc<dyn SecretResolver>>,
    Option<Arc<RwLock<SessionState>>>,
    Option<String>,
)> {
    let active = list_active_sessions(home)?;
    match active.len() {
        0 => {
            let resolver = Arc::new(crate::secret_resolver::local::LocalVaultResolver::new(
                vault.clone(),
            ));
            Ok((Some(resolver as Arc<dyn SecretResolver>), None, None))
        }
        1 => {
            let ws_id = active.into_iter().next().expect("len==1");
            let Some(state) = SessionState::load(home, &ws_id)? else {
                // Race: the file disappeared between list+load. Fall back to local.
                let resolver = Arc::new(crate::secret_resolver::local::LocalVaultResolver::new(
                    vault.clone(),
                ));
                return Ok((Some(resolver as Arc<dyn SecretResolver>), None, None));
            };
            let session_arc = Arc::new(RwLock::new(state));
            let resolver = Arc::new(crate::secret_resolver::remote::RemoteBrokerResolver::new(
                session_arc.clone(),
            )?);
            Ok((
                Some(resolver as Arc<dyn SecretResolver>),
                Some(session_arc),
                Some(ws_id),
            ))
        }
        _ => {
            let pick = std::env::var("KVENDRA_ACTIVE_WORKSPACE").ok();
            let Some(ws_id) = pick else {
                return Err(KvendraError::MultipleWorkspaceSessionsAmbiguous);
            };
            let Some(state) = SessionState::load(home, &ws_id)? else {
                return Err(KvendraError::SessionStore(format!(
                    "KVENDRA_ACTIVE_WORKSPACE points to '{ws_id}' but no session token found"
                )));
            };
            let session_arc = Arc::new(RwLock::new(state));
            let resolver = Arc::new(crate::secret_resolver::remote::RemoteBrokerResolver::new(
                session_arc.clone(),
            )?);
            Ok((
                Some(resolver as Arc<dyn SecretResolver>),
                Some(session_arc),
                Some(ws_id),
            ))
        }
    }
}

/// Dispatch a single JSON-RPC request against an existing [`ServerContext`].
///
/// Exposed so integration tests can drive the dispatcher in-process without
/// going through the stdio transport.
pub async fn dispatch(req: JsonRpcRequest, ctx: Arc<ServerContext>) -> JsonRpcResponse {
    let id = req.id.clone();

    if req.jsonrpc != "2.0" {
        return JsonRpcResponse::error(id, codes::INVALID_REQUEST, "jsonrpc must be \"2.0\"");
    }

    match req.method.as_str() {
        "initialize" => initialize(id),
        "tools/list" => tools_list(id),
        "tools/call" => tools_call(id, req.params.unwrap_or(Value::Null), ctx).await,
        "notifications/initialized" => JsonRpcResponse::success(None, Value::Null),
        other => JsonRpcResponse::error(
            id,
            codes::METHOD_NOT_FOUND,
            format!("method '{other}' not implemented"),
        ),
    }
}

fn initialize(id: Option<Value>) -> JsonRpcResponse {
    let result = InitializeResult {
        protocol_version: PROTOCOL_VERSION.into(),
        capabilities: serde_json::json!({ "tools": {} }),
        server_info: ServerInfo {
            name: "kvendra".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
    };
    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
}

fn tools_list(id: Option<Value>) -> JsonRpcResponse {
    let tools: Vec<ToolDescriptor> = catalog()
        .iter()
        .map(|p| ToolDescriptor {
            name: p.name.into(),
            description: p.tools_list_description(),
            input_schema: p.input_schema(),
        })
        .collect();
    let result = ToolsListResult { tools };
    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
}

/// Self-healing unlock attempt (REQ-KVD-CLI-011 / closes PAT-KVD-009 fix
/// path). If the in-RAM `SessionKey` expired by `idle_timeout_minutes`
/// (default 30 min) but the on-disk session blob is still valid (TTL
/// 4–24h depending on `session.default_ttl_seconds`), re-inject the
/// derived key into the vault so the subprocess survives without a
/// Claude Code restart.
///
/// Silent on the happy path. On failure (blob absent / expired /
/// tampered / wrong machine) leaves the vault locked so the next
/// `get_secret` returns `VaultLocked` as usual.
fn try_self_heal_vault(ctx: &ServerContext) {
    // REQ-KVD-CLI-42CB74 — accept both `Locked` (steady-state idle expiry,
    // PAT-KVD-009 path) and `LockedPendingUnlock` (tolerant boot, this
    // REQ). The audit flag emitted on success distinguishes the two so
    // forensics can tell idle-recovery from cold-boot-recovery apart.
    let prior_state = ctx.vault.state();
    let self_heal_flag = match prior_state {
        VaultStateKind::Unlocked => return,
        VaultStateKind::Locked => "mcp_self_heal_from_idle",
        VaultStateKind::LockedPendingUnlock => "mcp_self_heal_from_pending",
    };
    let home = ctx.vault.home();
    match crate::session::local::load(home) {
        Ok(state) => {
            let idle_timeout = ctx.config.vault.idle_timeout_minutes;
            match ctx
                .vault
                .unlock_from_derived_key(&state.derived_key, idle_timeout)
            {
                Ok(()) => {
                    tracing::info!(
                        target: "kvendra::mcp",
                        flag = self_heal_flag,
                        "vault locked → re-unlocked from active session blob"
                    );
                    // ISSUE-KVD-CLI-9764AC fix — if the server booted with
                    // the vault in `LockedPendingUnlock`, the audit writer
                    // was constructed `None` and `record_audit` is a silent
                    // no-op. Now that the vault is `Unlocked` and the HMAC
                    // sub-key is available, lazy-spawn the writer so events
                    // (including this very self-heal entry when surfaced by
                    // `record_audit` higher up the call chain) persist to
                    // SQLite. Idempotent: returns `Ok(false)` if a writer is
                    // already attached (e.g. plain `Locked` → `Unlocked`
                    // idle recovery from PAT-KVD-009).
                    match ctx.ensure_audit_writer_spawned() {
                        Ok(true) => {
                            tracing::info!(
                                target: "kvendra::mcp",
                                flag = "audit_writer_lazy_spawned",
                                trigger = self_heal_flag,
                                "audit writer lazy-spawned post self-heal — \
                                 subsequent tools/call events will persist to SQLite"
                            );
                        }
                        Ok(false) => { /* writer already attached, nothing to do */ }
                        Err(e) => {
                            tracing::warn!(
                                target: "kvendra::mcp",
                                flag = "audit_writer_lazy_spawn_failed",
                                error = %e,
                                "vault unlocked OK but audit writer spawn failed — \
                                 audit log will remain disabled this session"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        target: "kvendra::mcp",
                        flag = "session_self_heal_failed",
                        error = %e,
                        "blob load OK but derived key did not match sentinel"
                    );
                }
            }
        }
        Err(_) => {
            // Blob also missing / expired / tampered. Leave the vault
            // locked so the primitive surfaces its canonical
            // VaultLocked error and the user is told to re-run unlock.
        }
    }
}

async fn tools_call(id: Option<Value>, params: Value, ctx: Arc<ServerContext>) -> JsonRpcResponse {
    // Self-healing — if our in-RAM SessionKey expired (idle timeout) but
    // the on-disk session blob is still inside its TTL, recover the
    // derived key transparently. Closes PAT-KVD-009 ("Cmd+Q + restart
    // Claude Code is the canonical fix"). See try_self_heal_vault above.
    try_self_heal_vault(&ctx);

    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);

    let profile_id = arguments
        .get("profile_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let action = arguments
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let mut flags = if name == "kvendra.unsafe.raw_token" {
        vec!["unsafe_escape_hatch".to_string()]
    } else {
        vec![]
    };

    // REQ-KVD-CLI-42CB74 — tolerant-boot gate. If the vault is still in
    // `LockedPendingUnlock` after self-heal (no session blob on disk yet,
    // so the user has not run `kvendra unlock` from their own terminal)
    // AND the requested tool needs vault material, return a distinguishable
    // JSON-RPC `-32002` error with `help.topic =
    // "vault-locked-pending-unlock"`. Non-vault tools (future `whoami` /
    // `help` / `config_get`) bypass this gate.
    if ctx.vault.state() == VaultStateKind::LockedPendingUnlock
        && crate::primitives::tool_requires_vault(name)
    {
        flags.push(FLAG_TOOL_CALL_BLOCKED_PENDING_UNLOCK.to_string());
        let _ = record_audit(
            &ctx,
            &arguments,
            name,
            &profile_id,
            &action,
            &flags,
            true,
            None,
            Some(&KvendraError::VaultLocked),
        )
        .await;
        let data = serde_json::json!({
            "state": "locked_pending_unlock",
            "tool_call_blocked": name,
            "help": {
                "topic": "vault-locked-pending-unlock",
                "action": "Run `kvendra unlock` in your terminal. The MCP server will auto-recover without restart.",
            },
        });
        return JsonRpcResponse::error_with_data(
            id,
            codes::VAULT_LOCKED_PENDING_UNLOCK,
            "Kvendra vault locked-pending-unlock",
            data,
        );
    }

    // Detection (REQ-KVD-002 Bloque 7) — inspect arguments JSON BEFORE dispatch.
    let args_text = serde_json::to_string(&arguments).unwrap_or_default();
    let detection_hits = detect(&args_text);
    let detection_decision = if detection_hits.is_empty() {
        Decision::Allow
    } else {
        Decision::from_severity(ctx.config.detection.severity)
    };
    if !detection_hits.is_empty() {
        match detection_decision {
            Decision::Warn => {
                flags.push("detection_warned".into());
                eprintln!(
                    "kvendra detection: {} hit(s) on tools/call args (severity=warn): {:?}",
                    detection_hits.len(),
                    detection_hits
                        .iter()
                        .map(|h| &h.provider)
                        .collect::<Vec<_>>()
                );
            }
            Decision::Error => {
                flags.push("detection_error".into());
                let det_err = KvendraError::DetectionBlocked(format!(
                    "{} secret pattern hit(s) on inbound args, severity=error",
                    detection_hits.len()
                ));
                let _ = record_audit(
                    &ctx,
                    &arguments,
                    name,
                    &profile_id,
                    &action,
                    &flags,
                    true,
                    None,
                    Some(&det_err),
                )
                .await;
                return JsonRpcResponse::error(
                    id,
                    codes::APPLICATION_ERROR,
                    format!(
                        "detection: {} hit(s) on inbound args, severity=error",
                        detection_hits.len()
                    ),
                );
            }
            Decision::Block => {
                flags.push("detection_blocked".into());
                if !profile_id.is_empty() {
                    let _ = ctx.vault.mark_quarantined(&profile_id);
                }
                let det_err = KvendraError::DetectionBlocked(format!(
                    "{} secret pattern hit(s) on inbound args, severity=block — profile quarantined",
                    detection_hits.len()
                ));
                let _ = record_audit(
                    &ctx,
                    &arguments,
                    name,
                    &profile_id,
                    &action,
                    &flags,
                    true,
                    None,
                    Some(&det_err),
                )
                .await;
                return JsonRpcResponse::error(
                    id,
                    codes::APPLICATION_ERROR,
                    format!(
                        "detection: {} hit(s) on inbound args, severity=block — profile quarantined",
                        detection_hits.len()
                    ),
                );
            }
            Decision::Allow => {}
        }
    }

    // Allowlist enforcement (when a profile metadata + allowlist exists).
    if !profile_id.is_empty() {
        match enforce_allowlist(&ctx, &profile_id, name, &action, &arguments).await {
            Ok(MigrationOutcome::Unchanged) | Ok(MigrationOutcome::Migrated) => {}
            Err(KvendraError::AllowlistTampered(pid)) => {
                flags.push("allowlist_tampered_detected".into());
                let tamper_err = KvendraError::AllowlistTampered(pid.clone());
                let _ = record_audit(
                    &ctx,
                    &arguments,
                    name,
                    &profile_id,
                    &action,
                    &flags,
                    true,
                    None,
                    Some(&tamper_err),
                )
                .await;
                let data = serde_json::json!({
                    "error_type": "allowlist_tampered",
                    "hint": "re-run `kvendra secret set-allowlist <profile> --file <yaml>` or restore from backup",
                });
                return JsonRpcResponse::error_with_data(
                    id,
                    codes::APPLICATION_ERROR,
                    format!("allowlist for profile '{pid}' has been tampered"),
                    data,
                );
            }
            Err(e) => {
                // REQ-KVD-CLI-002 / ISSUE-023+033 — emit the canonical flag
                // for forensic reconstruction (`kvendra audit --json | jq
                // '.flags | contains("allowlist_denied")'`). Without this,
                // the audit row is indistinguishable from network errors.
                if let Some(canonical_flag) = audit_flag_for_error(&e) {
                    flags.push(canonical_flag.into());
                }
                let _ = record_audit(
                    &ctx,
                    &arguments,
                    name,
                    &profile_id,
                    &action,
                    &flags,
                    true,
                    None,
                    Some(&e),
                )
                .await;
                // AC-MCP-3 defence in depth: the error string can include the
                // primitive's argv / parsed YAML on certain code paths, which
                // could carry leaked tokens. Always scrub before returning.
                let msg = crate::detection::sanitize_output(&e.to_string());
                return JsonRpcResponse::error(id, codes::APPLICATION_ERROR, msg);
            }
        }
    }

    // Approval layer (REQ-KVD-003 — gap V7 + O1.LLM-auto-approve del threat
    // model). Se evalúa entre el enforcement de la allowlist y el record_audit
    // Started: si la allowlist permite y el modo del approval bloquea, NO se
    // emite Started (sólo una row Error con flag estructurada).
    let approval_decision = approval::check(&ctx, name, &profile_id, &action, &arguments).await;
    if let Some(flag) = approval_decision.audit_flag() {
        flags.push(flag.into());
    }
    if approval_decision.blocks_dispatch() {
        // APPROVAL_DENIED — the error_type detail also rides in `flags` via
        // `approval_decision.audit_flag()`, so the code+message pair stays
        // aggregatable while preserving the nuance.
        let approval_err = KvendraError::BiometricRejected;
        let _ = record_audit(
            &ctx,
            &arguments,
            name,
            &profile_id,
            &action,
            &flags,
            true,
            None,
            Some(&approval_err),
        )
        .await;
        let error_type = approval_decision.error_type().unwrap_or("approval_failed");
        let hint = approval::hint_for(approval_decision, ctx.config.approval.timeout_seconds);
        let data = serde_json::json!({
            "error_type": error_type,
            "hint": hint,
        });
        return JsonRpcResponse::error_with_data(
            id,
            codes::APPLICATION_ERROR,
            format!("approval not granted: {error_type}"),
            data,
        );
    }

    // REQ-KVD-CLI-009 AC-ALLOWSYNC-3 — if the allowlist cache has been stale
    // for >24h, refuse the call before talking to the resolver.
    if let Some(ws_id) = ctx.workspace_id.as_deref()
        && crate::workspace::allowlist_sync::is_stale_blocked(ctx.vault.home(), ws_id)
    {
        flags.push("allowlist_cache_stale".into());
        let _ = record_audit(
            &ctx,
            &arguments,
            name,
            &profile_id,
            &action,
            &flags,
            true,
            None,
            Some(&KvendraError::AllowlistCacheStale),
        )
        .await;
        return JsonRpcResponse::error(
            id,
            codes::APPLICATION_ERROR,
            KvendraError::AllowlistCacheStale.to_string(),
        );
    }

    // Resolve the secret via the configured SecretResolver. In local mode
    // this is the existing vault path; in workspace mode the resolver POSTs
    // tokens:issue to the broker. The 8 primitives stay untouched — they
    // consume `Option<&SecretPlaintext>` exactly as before.
    //
    // We resolve BEFORE writing the Started audit row so the remote
    // `audit_id` correlation rides on the same row.
    let mut remote_audit_id_for_event: Option<String> = None;
    let secret: Option<SecretPlaintext> = if profile_id.is_empty() {
        None
    } else if let Some(resolver) = ctx.resolver.as_ref() {
        let ctx_call = CallCtx {
            primitive: name.to_string(),
            op: action.clone(),
            args_hash_hex: args_hash_hex(&arguments),
            requested_at: Utc::now(),
        };
        match resolver.resolve(&profile_id, &ctx_call).await {
            Ok(eph) => {
                remote_audit_id_for_event = eph.audit_id.clone();
                Some(eph.token)
            }
            Err(KvendraError::ProfileNotFound) | Err(KvendraError::VaultLocked) => None,
            Err(other) => {
                // Fail the call early with a sanitized message — the
                // resolver-level errors (WorkspaceMembershipRevoked,
                // BrokerUnreachable, RateLimited, ...) carry user-friendly
                // text and never include secret material.
                let msg = crate::detection::sanitize_output(&other.to_string());
                let _ = record_audit(
                    &ctx,
                    &arguments,
                    name,
                    &profile_id,
                    &action,
                    &flags,
                    true,
                    None,
                    Some(&other),
                )
                .await;
                return JsonRpcResponse::error(id, codes::APPLICATION_ERROR, msg);
            }
        }
    } else {
        // Resolver not constructed (vault locked + no workspace session) —
        // legacy fall-through. Primitives that do not require a profile
        // still execute.
        None
    };

    // Started event. `0` indicates audit was disabled (vault locked). The
    // `remote_audit_id` (when present) commits to the chain via the v2
    // HMAC, materializing the cross-component audit correlation.
    let event_id: i64 = record_audit(
        &ctx,
        &arguments,
        name,
        &profile_id,
        &action,
        &flags,
        false,
        remote_audit_id_for_event.as_deref(),
        None,
    )
    .await
    .unwrap_or_default();

    let outcome = invoke_primitive(name, &arguments, &ctx.vault, secret.as_ref()).await;
    drop(secret); // explicit drop → ZeroizeOnDrop fires.

    let (status, severity) = match &outcome {
        Ok(_) => (Status::Ok, Severity::Info),
        Err(KvendraError::AllowlistViolation(_))
        | Err(KvendraError::ProfileExpired)
        | Err(KvendraError::UnsafeNotEnabled)
        | Err(KvendraError::DetectionBlocked(_)) => (Status::Error, Severity::Warn),
        Err(_) => (Status::Error, Severity::Error),
    };
    // On the error path, classify a closed-vocabulary `error_code` and capture
    // a SANITIZED `error_message` (ISSUE-KVD-CLI-6C43AA). `crate::audit::
    // error_code::from_error` scrubs the text through the same secret redactor
    // used for outbound MCP payloads, so no PAT / password / token can land in
    // the audit DB. Both are committed to the v3 HMAC.
    let (err_code, err_msg) = match &outcome {
        Err(e) => {
            let (code, msg) = crate::audit::error_code::from_error(e);
            (Some(code.as_str().to_string()), Some(msg))
        }
        Ok(_) => (None, None),
    };
    if let Some(w) = ctx.audit_writer()
        && event_id > 0
    {
        let _ = w
            .update_status(event_id, status, severity, err_code, err_msg)
            .await;
    }

    match outcome {
        Ok(value) => {
            let (text, structured) = build_sanitized_payload(name, value);
            JsonRpcResponse::success(
                id,
                serde_json::json!({
                    "content": [{ "type": "text", "text": text }],
                    "isError": false,
                    "structuredContent": structured,
                    "auditEventId": event_id,
                }),
            )
        }
        Err(err) => {
            // Defence in depth: sanitize the outbound error message. A
            // misbehaving primitive that includes a leaked token in its
            // error string must not bypass AC-MCP-3.
            let sanitized_msg = crate::detection::sanitize_output(&err.to_string());
            // ISSUE-KVD-CLI-014 fix C — para errores de InvalidArgs devolvemos
            // un payload estructurado en `data` con el primitive + operation +
            // hint, para que el cliente MCP (LLM) auto-corrija sin retry.
            if matches!(err, KvendraError::InvalidArgs(_)) {
                let data = serde_json::json!({
                    "error_type": "invalid_args",
                    "primitive": name,
                    "operation": action,
                    "message": sanitized_msg,
                    "hint": format!(
                        "see `kvendra primitive info {name}` or the description in tools/list for the expected args shape per operation"
                    ),
                });
                JsonRpcResponse::error_with_data(id, codes::INVALID_PARAMS, sanitized_msg, data)
            } else {
                JsonRpcResponse::error(id, codes::APPLICATION_ERROR, sanitized_msg)
            }
        }
    }
}

/// Build the `(content.text, structuredContent)` pair that goes on the wire
/// for a successful `tools/call`, applying the AC-MCP-3 sanitization policy.
///
/// Every primitive's payload is recursively scrubbed via
/// [`crate::detection::sanitize_value`] EXCEPT for the documented escape
/// hatch `kvendra.unsafe.raw_token` (per IF-KVD-CLI-008): for that single
/// primitive the plaintext rides through both `text` and
/// `structuredContent` unaltered. This is the ONLY exception to AC-MCP-3
/// and is gated by the profile-level `unsafe_raw_token_enabled` flag and
/// per-session quota in the primitive itself.
pub fn build_sanitized_payload(name: &str, value: Value) -> (String, Value) {
    if name == "kvendra.unsafe.raw_token" {
        // AC-MCP-3 exception: documented escape hatch per IF-KVD-CLI-008.
        let pt = value
            .get("plaintext")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_default();
        (pt, value)
    } else {
        let text = crate::detection::sanitize_output(&value.to_string());
        let mut structured = value;
        crate::detection::sanitize_value(&mut structured);
        (text, structured)
    }
}

#[allow(clippy::too_many_arguments)]
async fn record_audit(
    ctx: &ServerContext,
    arguments: &Value,
    name: &str,
    profile_id: &str,
    action: &str,
    flags: &[String],
    failed_pre_dispatch: bool,
    remote_audit_id: Option<&str>,
    error: Option<&KvendraError>,
) -> KvendraResult<i64> {
    let Some(w) = ctx.audit_writer() else {
        return Err(KvendraError::Audit("audit disabled (vault locked)".into()));
    };
    // For pre-dispatch rejections (allowlist/detection/approval/stale) the row
    // is written directly as `Status::Error`; classify + sanitize the diagnostic
    // here so the forensic columns are populated on the same row
    // (ISSUE-KVD-CLI-6C43AA).
    let (error_code, error_message) = match (failed_pre_dispatch, error) {
        (true, Some(e)) => {
            let (code, msg) = crate::audit::error_code::from_error(e);
            (Some(code.as_str().to_string()), Some(msg))
        }
        _ => (None, None),
    };
    let event = AuditEvent {
        ts_unix_ms: OffsetDateTime::now_utc().unix_timestamp_nanos() as i64 / 1_000_000,
        profile_id: profile_id.to_string(),
        primitive: name.to_string(),
        action: action.to_string(),
        args_hash_hex: args_hash_hex(arguments),
        status: if failed_pre_dispatch {
            Status::Error
        } else {
            Status::Started
        },
        severity: if failed_pre_dispatch {
            Severity::Warn
        } else {
            Severity::Info
        },
        flags: flags.join(","),
        remote_audit_id: remote_audit_id.map(str::to_string),
        error_code,
        error_message,
    };
    w.record(event).await
}

/// Map a [`KvendraError`] surfaced by `enforce_allowlist` (or any other
/// pre-dispatch barrier) to the canonical audit flag string used by the
/// forensic tooling. Returning `None` means "no flag — emit the row with
/// whatever flags were already accumulated".
///
/// The set is intentionally closed: only errors that represent a *boundary
/// rejection* (allowlist deny, expired profile, escape-hatch off) get a
/// canonical flag. Generic I/O / parse / network errors do NOT — those
/// would make the flag noisy and useless for forensic queries.
fn audit_flag_for_error(err: &KvendraError) -> Option<&'static str> {
    match err {
        KvendraError::AllowlistViolation(_) => Some("allowlist_denied"),
        KvendraError::ProfileExpired => Some("profile_expired"),
        KvendraError::UnsafeNotEnabled => Some("unsafe_not_enabled"),
        // AllowlistTampered is handled in a dedicated branch in tools_call
        // and gets `allowlist_tampered_detected`; do not double-count it
        // here.
        _ => None,
    }
}

async fn enforce_allowlist(
    ctx: &ServerContext,
    profile_id: &str,
    primitive: &str,
    operation: &str,
    arguments: &Value,
) -> KvendraResult<MigrationOutcome> {
    let path = ctx.vault.profile_allowlist_path(profile_id);
    if !path.exists() {
        // No allowlist on disk → defer to existing behaviour: allowed.
        // Documented: profiles must declare an allowlist for production use.
        return Ok(MigrationOutcome::Unchanged);
    }
    let raw = std::fs::read_to_string(&path)?;

    // REQ-KVD-007 / ISSUE-018: verify HMAC of the YAML against the value
    // persisted in ProfileMeta. Mismatch → reject + audit. Missing HMAC
    // (legacy profile) → auto-sign on first read post-update (D4 silent).
    let key = ctx.vault.allowlist_hmac_key()?;
    let current_hmac = crate::vault::compute_allowlist_hmac(&key, raw.as_bytes());
    let mut profile = ctx.vault.load_profile_meta(profile_id)?;
    let mut migration_outcome = MigrationOutcome::Unchanged;
    match profile.allowlist_hmac_hex.as_deref() {
        Some(stored) if stored == current_hmac => { /* OK, continue */ }
        Some(_stored) => {
            tracing::error!(
                target: "kvendra::mcp",
                flag = "allowlist_tampered_detected",
                profile_id,
                "Allowlist HMAC mismatch — refusing to use modified allowlist"
            );
            return Err(KvendraError::AllowlistTampered(profile_id.to_string()));
        }
        None => {
            // Migration on first read (REQ-KVD-007 AC-6, D4 silent).
            profile.allowlist_hmac_hex = Some(current_hmac.clone());
            ctx.vault.save_profile_meta(&profile)?;
            tracing::info!(
                target: "kvendra::mcp",
                flag = "allowlist_hmac_migrated",
                profile_id,
                "Auto-signed legacy allowlist on first read post-REQ-007"
            );
            // REQ-KVD-CLI-002 / ISSUE-023 — emit a DEDICATED audit row for the
            // migration event (owner D4 decision, TXN-KVD-20260508-012). A
            // separate row preserves the literal AC of ISSUE-023 ("audit row
            // ... contains flag allowlist_hmac_migrated") without forcing the
            // boundary call row to also carry the flag.
            if let Some(writer) = ctx.audit_writer() {
                let event = AuditEvent {
                    ts_unix_ms: OffsetDateTime::now_utc().unix_timestamp_nanos() as i64 / 1_000_000,
                    profile_id: profile_id.to_string(),
                    primitive: PRIMITIVE_SYSTEM.to_string(),
                    action: "allowlist_hmac_migrated".to_string(),
                    args_hash_hex: sha256_hex(profile_id.as_bytes()),
                    status: Status::Ok,
                    severity: Severity::Info,
                    flags: "allowlist_hmac_migrated".to_string(),
                    remote_audit_id: None,
                    error_code: None,
                    error_message: None,
                };
                writer.record(event).await?;
            }
            migration_outcome = MigrationOutcome::Migrated;
        }
    }

    let spec: ProfileSpec = serde_yaml_ng::from_str(&raw)?;
    allowlist_validate(&spec)?;
    allowlist_check(&spec, primitive, operation, arguments)?;
    Ok(migration_outcome)
}

/// SHA-256 over arbitrary bytes, hex-encoded. Local helper used to derive
/// `args_hash_hex` for system-level audit rows that are not driven by a
/// JSON args payload (e.g. the `allowlist_hmac_migrated` row, which only
/// references the `profile_id`).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

async fn invoke_primitive(
    name: &str,
    args: &Value,
    vault: &Vault,
    secret: Option<&SecretPlaintext>,
) -> KvendraResult<Value> {
    use crate::primitives::*;

    match name {
        "kvendra.git" => git::execute(args, secret).await,
        "kvendra.github" => github::execute(args, secret).await,
        "kvendra.npm" => npm::execute(args, secret).await,
        "kvendra.pypi" => pypi::execute(args, secret).await,
        "kvendra.aws" => aws::execute(args, secret).await,
        "kvendra.http" => http::execute(args, secret).await,
        "kvendra.shell" => shell::execute(args, secret).await,
        "kvendra.unsafe.raw_token" => unsafe_raw_token::execute(args, vault, secret).await,
        other => Err(KvendraError::PrimitiveNotImplemented(other.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::ApprovalCache;
    use crate::vault::{Profile, kdf::KdfParams};
    use std::sync::Arc;

    fn fast_params() -> KdfParams {
        KdfParams {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: vec![1u8; 16],
        }
    }

    /// Helper used by the `enforce_allowlist` test trio below: builds an
    /// unlocked Vault with a profile + allowlist YAML on disk + minimal
    /// `ServerContext`. By default no audit writer is attached (the tests
    /// exercise the HMAC verification path only); pass `attach_writer=true`
    /// to wire up an `AuditWriter` so the dedicated migration / boundary
    /// rows can be inspected by SQLite query in-test.
    fn fixture_with_allowlist(yaml: &str) -> (tempfile::TempDir, ServerContext) {
        fixture_with_allowlist_inner(yaml, false)
    }

    fn fixture_with_allowlist_and_writer(yaml: &str) -> (tempfile::TempDir, ServerContext) {
        fixture_with_allowlist_inner(yaml, true)
    }

    fn fixture_with_allowlist_inner(
        yaml: &str,
        attach_writer: bool,
    ) -> (tempfile::TempDir, ServerContext) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        crate::config::ensure_layout(home).unwrap();
        let v = Vault::new(home.to_path_buf());
        v.create_with_params(b"hunter2-allowlist-test", fast_params())
            .unwrap();
        v.unlock(b"hunter2-allowlist-test", 30).unwrap();
        v.put_secret("p", b"sometoken").unwrap();
        v.save_profile_meta(&Profile {
            profile_id: "p".into(),
            secret_type: "github_pat".into(),
            created_at: "2026-05-07T00:00:00Z".into(),
            expiration: None,
            unsafe_raw_token_enabled: false,
            quarantined: false,
            allowlist_hmac_hex: None,
        })
        .unwrap();
        let allowlist_path = v.profile_allowlist_path("p");
        std::fs::write(&allowlist_path, yaml).unwrap();
        let key = v.allowlist_hmac_key().unwrap();
        let hmac_hex = crate::vault::compute_allowlist_hmac(&key, yaml.as_bytes());
        let mut profile = v.load_profile_meta("p").unwrap();
        profile.allowlist_hmac_hex = Some(hmac_hex);
        v.save_profile_meta(&profile).unwrap();

        let writer = if attach_writer {
            Some(
                AuditWriter::spawn(v.audit_db_path(), v.audit_hmac_key().unwrap())
                    .expect("spawn audit writer"),
            )
        } else {
            None
        };

        let ctx = ServerContext {
            vault: v,
            config: Config::default(),
            writer: std::sync::RwLock::new(writer),
            approval_cache: Arc::new(ApprovalCache::new()),
            approval_prompt_lock: Arc::new(Mutex::new(())),
            transport: Transport::Mcp,
            resolver: None,
            session: None,
            workspace_id: None,
        };
        (dir, ctx)
    }

    const TEST_ALLOWLIST_YAML: &str = "profile_id: p\nsecret:\n  type: github_pat\nallowlist:\n  primitives:\n    - name: kvendra.shell\n      operations:\n        - run:\n            binaries: [\"echo\"]\n";

    /// REQ-KVD-007 AC-2 — a YAML matching the persisted HMAC must pass.
    #[tokio::test]
    async fn enforce_allowlist_passes_on_match() {
        let (_dir, ctx) = fixture_with_allowlist(TEST_ALLOWLIST_YAML);
        let res = enforce_allowlist(
            &ctx,
            "p",
            "kvendra.shell",
            "run",
            &serde_json::json!({ "argv": ["echo", "hi"] }),
        )
        .await;
        assert!(
            matches!(res, Ok(MigrationOutcome::Unchanged)),
            "well-formed allowlist must enforce as Unchanged: {res:?}"
        );
    }

    /// REQ-KVD-007 AC-3 — a YAML modified out-of-band must trip the HMAC
    /// check and surface as `KvendraError::AllowlistTampered`.
    #[tokio::test]
    async fn enforce_allowlist_rejects_on_tampering() {
        let (_dir, ctx) = fixture_with_allowlist(TEST_ALLOWLIST_YAML);
        // Out-of-band edit: append a permissive line. HMAC no longer matches.
        let path = ctx.vault.profile_allowlist_path("p");
        let mut tampered = std::fs::read_to_string(&path).unwrap();
        tampered.push_str("    env_allowlist: [\"PATH\"]\n");
        std::fs::write(&path, tampered).unwrap();

        let res = enforce_allowlist(
            &ctx,
            "p",
            "kvendra.shell",
            "run",
            &serde_json::json!({ "argv": ["echo", "hi"] }),
        )
        .await;
        match res {
            Err(KvendraError::AllowlistTampered(pid)) => assert_eq!(pid, "p"),
            other => panic!("expected AllowlistTampered, got {other:?}"),
        }
    }

    /// REQ-KVD-007 AC-6 — a profile without `allowlist_hmac_hex` is a legacy
    /// profile pre-REQ-007 and must be auto-signed silently on first read.
    /// After the call, `ProfileMeta.allowlist_hmac_hex` is populated AND a
    /// dedicated `allowlist_hmac_migrated` audit row is appended (REQ-KVD-CLI-002,
    /// owner D4 decision).
    #[tokio::test]
    async fn enforce_allowlist_auto_migrates_legacy_profile() {
        let (_dir, ctx) = fixture_with_allowlist_and_writer(TEST_ALLOWLIST_YAML);
        // Reset the migrated HMAC to None to simulate a legacy profile.
        let mut profile = ctx.vault.load_profile_meta("p").unwrap();
        profile.allowlist_hmac_hex = None;
        ctx.vault.save_profile_meta(&profile).unwrap();

        let res = enforce_allowlist(
            &ctx,
            "p",
            "kvendra.shell",
            "run",
            &serde_json::json!({ "argv": ["echo", "hi"] }),
        )
        .await;
        assert!(
            matches!(res, Ok(MigrationOutcome::Migrated)),
            "auto-migration must surface Migrated outcome: {res:?}"
        );
        let after = ctx.vault.load_profile_meta("p").unwrap();
        assert!(
            after.allowlist_hmac_hex.is_some(),
            "auto-migration must populate allowlist_hmac_hex"
        );

        // Drain the writer and inspect the SQLite DB directly for the
        // dedicated row.
        ctx.audit_writer().unwrap().shutdown().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conn = rusqlite::Connection::open(ctx.vault.audit_db_path()).unwrap();
        let (action, primitive, flags): (String, String, String) = conn
            .query_row(
                "SELECT action, primitive, flags FROM audit_events \
                 WHERE action = 'allowlist_hmac_migrated' ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("dedicated allowlist_hmac_migrated row must be present");
        assert_eq!(action, "allowlist_hmac_migrated");
        assert_eq!(primitive, PRIMITIVE_SYSTEM);
        assert!(
            flags.contains("allowlist_hmac_migrated"),
            "dedicated row must carry canonical flag, got: {flags}"
        );
    }

    /// REQ-KVD-007 — when no allowlist YAML is on disk, `enforce_allowlist`
    /// is a no-op (existing behaviour preserved). The HMAC code path must
    /// not panic / error in this case.
    #[tokio::test]
    async fn enforce_allowlist_noop_when_no_allowlist_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        crate::config::ensure_layout(home).unwrap();
        let v = Vault::new(home.to_path_buf());
        v.create_with_params(b"hunter2-noop-test", fast_params())
            .unwrap();
        v.unlock(b"hunter2-noop-test", 30).unwrap();
        let ctx = ServerContext {
            vault: v,
            config: Config::default(),
            writer: std::sync::RwLock::new(None),
            approval_cache: Arc::new(ApprovalCache::new()),
            approval_prompt_lock: Arc::new(Mutex::new(())),
            transport: Transport::Mcp,
            resolver: None,
            session: None,
            workspace_id: None,
        };
        let res = enforce_allowlist(
            &ctx,
            "p",
            "kvendra.shell",
            "run",
            &serde_json::json!({ "argv": ["echo", "hi"] }),
        )
        .await;
        assert!(
            matches!(res, Ok(MigrationOutcome::Unchanged)),
            "no allowlist on disk → allow + Unchanged: {res:?}"
        );
    }

    /// AC-MCP-3 — `structuredContent` of a non-escape-hatch primitive must
    /// have every leaked secret recursively redacted, even when the value
    /// is buried inside nested arrays / objects (e.g. captured stdout from
    /// `kvendra.shell`).
    #[test]
    fn structured_content_is_sanitized_for_regular_primitive() {
        let payload = serde_json::json!({
            "binary": "printenv",
            "exit_code": 0,
            "stdout_sanitized": "GITHUB_TOKEN=ghp_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaaaa\n",
            "stderr_sanitized": "",
        });
        let (text, structured) = build_sanitized_payload("kvendra.shell", payload);
        let s = serde_json::to_string(&structured).unwrap();
        assert!(
            !s.contains("ghp_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaaaa"),
            "PAT leaked through structuredContent: {s}"
        );
        assert!(s.contains("<redacted:github_pat_classic>"), "got: {s}");
        assert!(
            !text.contains("ghp_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaaaa"),
            "PAT leaked in text: {text}"
        );
    }

    /// AC-MCP-3 documented exception — the escape hatch
    /// `kvendra.unsafe.raw_token` MUST return plaintext so that opt-in
    /// callers can read tokens directly. Every other primitive is scrubbed.
    #[test]
    fn unsafe_raw_token_bypasses_sanitization() {
        let secret = "ghp_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaaaa";
        let payload = serde_json::json!({
            "operation": "get",
            "profile_id": "test.github",
            "plaintext": secret,
        });
        let (text, structured) =
            build_sanitized_payload("kvendra.unsafe.raw_token", payload.clone());
        // `text` carries the plaintext verbatim (consumer reads from there).
        assert_eq!(text, secret);
        // `structuredContent` keeps the plaintext intact too — the entire
        // point of the escape hatch is to deliver the raw material.
        let s = serde_json::to_string(&structured).unwrap();
        assert!(
            s.contains(secret),
            "escape hatch unexpectedly redacted: {s}"
        );
    }

    /// REQ-KVD-CLI-011 self-healing (PAT-KVD-009 closure): an unlocked
    /// vault that gets locked mid-flight (idle timeout) recovers
    /// transparently when `try_self_heal_vault` is called, provided the
    /// session blob is still valid on disk.
    #[test]
    fn self_heal_recovers_locked_vault_from_active_blob() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        crate::config::ensure_layout(home).unwrap();
        let v = Vault::new(home.to_path_buf());
        v.create_with_params(b"hunter2-self-heal", fast_params())
            .unwrap();
        v.unlock(b"hunter2-self-heal", 30).unwrap();

        // Write the local session blob using the vault's current derived
        // key (same flow `kvendra unlock` follows in production).
        let derived = v.peek_session_derived_key().unwrap();
        let state = crate::session::local::build_state_for_current_machine(
            derived,
            std::time::Duration::from_secs(3600),
            home,
        )
        .unwrap();
        crate::session::local::persist_atomic(&state, home).unwrap();

        // Simulate idle expiry by force-locking the in-RAM session.
        v.lock();
        assert!(!v.is_unlocked(), "precondition: vault must be locked");

        let ctx = ServerContext {
            vault: v,
            config: Config::default(),
            writer: std::sync::RwLock::new(None),
            approval_cache: Arc::new(ApprovalCache::new()),
            approval_prompt_lock: Arc::new(Mutex::new(())),
            transport: Transport::Mcp,
            resolver: None,
            session: None,
            workspace_id: None,
        };

        super::try_self_heal_vault(&ctx);

        assert!(
            ctx.vault.is_unlocked(),
            "self-healing should re-unlock the vault from the active blob"
        );
    }

    /// REQ-KVD-CLI-42CB74 AC-HEAL-1 + AC-HEAL-2 + AC-HEAL-4 — when the
    /// vault is in `LockedPendingUnlock` (cold boot, never had a session)
    /// and a session blob lands on disk later (because the user ran
    /// `kvendra unlock` in their own terminal), `try_self_heal_vault`
    /// must (1) transition the vault to `Unlocked` and (2) emit the
    /// `mcp_self_heal_from_pending` flag — NOT the `_from_idle` variant
    /// which is reserved for steady-state idle-timeout recovery.
    ///
    /// We verify (1) via `vault.state()` post-call. We verify (2) by
    /// capturing the `tracing` events through a custom subscriber for the
    /// duration of the call.
    #[test]
    fn try_self_heal_from_locked_pending_unlock_succeeds() {
        use std::sync::{Arc as StdArc, Mutex as StdMutex};
        use tracing::Subscriber;
        use tracing::field::{Field, Visit};
        use tracing_subscriber::layer::{Context as LayerCtx, Layer, SubscriberExt};
        use tracing_subscriber::registry::Registry;

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        crate::config::ensure_layout(home).unwrap();
        let v = Vault::new(home.to_path_buf());
        v.create_with_params(b"hunter2-pending-heal", fast_params())
            .unwrap();
        // Prime with a password unlock to mint a derived key + write a
        // blob for the cold-boot scenario.
        v.unlock(b"hunter2-pending-heal", 30).unwrap();
        let derived = v.peek_session_derived_key().unwrap();
        let state = crate::session::local::build_state_for_current_machine(
            derived,
            std::time::Duration::from_secs(3600),
            home,
        )
        .unwrap();
        crate::session::local::persist_atomic(&state, home).unwrap();
        v.lock();

        // Simulate a fresh cold-boot: the vault has never been unlocked
        // in this "process" — only marked pending by attach_session_key.
        v.mark_pending_unlock();
        assert_eq!(v.state(), VaultStateKind::LockedPendingUnlock);

        let ctx = ServerContext {
            vault: v,
            config: Config::default(),
            writer: std::sync::RwLock::new(None),
            approval_cache: Arc::new(ApprovalCache::new()),
            approval_prompt_lock: Arc::new(Mutex::new(())),
            transport: Transport::Mcp,
            resolver: None,
            session: None,
            workspace_id: None,
        };

        // Capture tracing events emitted during the self-heal call.
        #[derive(Default)]
        struct FlagCapture(StdArc<StdMutex<Vec<String>>>);
        impl<S: Subscriber> Layer<S> for FlagCapture {
            fn on_event(&self, event: &tracing::Event<'_>, _ctx: LayerCtx<'_, S>) {
                struct V<'a>(&'a StdMutex<Vec<String>>);
                impl<'a> Visit for V<'a> {
                    fn record_str(&mut self, field: &Field, value: &str) {
                        if field.name() == "flag" {
                            self.0.lock().unwrap().push(value.to_string());
                        }
                    }
                    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                        if field.name() == "flag" {
                            self.0.lock().unwrap().push(format!("{value:?}"));
                        }
                    }
                }
                event.record(&mut V(&self.0));
            }
        }

        let flags = StdArc::new(StdMutex::new(Vec::new()));
        let layer = FlagCapture(flags.clone());
        let subscriber = Registry::default().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            super::try_self_heal_vault(&ctx);
        });

        // AC-HEAL-1 — state transitions to Unlocked.
        assert!(
            ctx.vault.is_unlocked(),
            "self-heal from LockedPendingUnlock must unlock the vault"
        );

        // AC-HEAL-2 + AC-HEAL-4 — emits _from_pending, NOT _from_idle.
        let captured = flags.lock().unwrap().clone();
        assert!(
            captured
                .iter()
                .any(|f| f.contains("mcp_self_heal_from_pending")),
            "expected flag mcp_self_heal_from_pending, captured: {captured:?}"
        );
        assert!(
            !captured
                .iter()
                .any(|f| f.contains("mcp_self_heal_from_idle")),
            "must NOT emit _from_idle flag when prior state was LockedPendingUnlock, captured: {captured:?}"
        );
    }

    /// REQ-KVD-CLI-42CB74 AC-REGRESSION-2 — when the vault is in plain
    /// `Locked` state (session existed, idle-timeout expired — PAT-KVD-009
    /// path) and a fresh blob is loadable, `try_self_heal_vault` must
    /// (1) unlock the vault and (2) emit the `mcp_self_heal_from_idle`
    /// flag — NOT `_from_pending` which is reserved for cold-boot recovery.
    ///
    /// This is the existing PAT-KVD-009 closure behaviour and must NOT
    /// regress when the cold-boot branch was added.
    #[test]
    fn try_self_heal_from_locked_idle_keeps_existing_flag() {
        use std::sync::{Arc as StdArc, Mutex as StdMutex};
        use tracing::Subscriber;
        use tracing::field::{Field, Visit};
        use tracing_subscriber::layer::{Context as LayerCtx, Layer, SubscriberExt};
        use tracing_subscriber::registry::Registry;

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        crate::config::ensure_layout(home).unwrap();
        let v = Vault::new(home.to_path_buf());
        v.create_with_params(b"hunter2-idle-heal", fast_params())
            .unwrap();
        v.unlock(b"hunter2-idle-heal", 30).unwrap();

        // Persist the local session blob then force-lock the in-RAM
        // session (simulates idle-timeout expiry — pending flag stays
        // clear, this is the PAT-KVD-009 path).
        let derived = v.peek_session_derived_key().unwrap();
        let state = crate::session::local::build_state_for_current_machine(
            derived,
            std::time::Duration::from_secs(3600),
            home,
        )
        .unwrap();
        crate::session::local::persist_atomic(&state, home).unwrap();
        v.lock();

        assert_eq!(
            v.state(),
            VaultStateKind::Locked,
            "must be plain Locked, not pending"
        );

        let ctx = ServerContext {
            vault: v,
            config: Config::default(),
            writer: std::sync::RwLock::new(None),
            approval_cache: Arc::new(ApprovalCache::new()),
            approval_prompt_lock: Arc::new(Mutex::new(())),
            transport: Transport::Mcp,
            resolver: None,
            session: None,
            workspace_id: None,
        };

        #[derive(Default)]
        struct FlagCapture(StdArc<StdMutex<Vec<String>>>);
        impl<S: Subscriber> Layer<S> for FlagCapture {
            fn on_event(&self, event: &tracing::Event<'_>, _ctx: LayerCtx<'_, S>) {
                struct V<'a>(&'a StdMutex<Vec<String>>);
                impl<'a> Visit for V<'a> {
                    fn record_str(&mut self, field: &Field, value: &str) {
                        if field.name() == "flag" {
                            self.0.lock().unwrap().push(value.to_string());
                        }
                    }
                    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                        if field.name() == "flag" {
                            self.0.lock().unwrap().push(format!("{value:?}"));
                        }
                    }
                }
                event.record(&mut V(&self.0));
            }
        }

        let flags = StdArc::new(StdMutex::new(Vec::new()));
        let layer = FlagCapture(flags.clone());
        let subscriber = Registry::default().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            super::try_self_heal_vault(&ctx);
        });

        assert!(ctx.vault.is_unlocked(), "self-heal from Locked must unlock");
        let captured = flags.lock().unwrap().clone();
        assert!(
            captured
                .iter()
                .any(|f| f.contains("mcp_self_heal_from_idle")),
            "expected mcp_self_heal_from_idle, captured: {captured:?}"
        );
        assert!(
            !captured
                .iter()
                .any(|f| f.contains("mcp_self_heal_from_pending")),
            "must NOT emit _from_pending flag for plain Locked, captured: {captured:?}"
        );
    }

    /// REQ-KVD-CLI-42CB74 AC-BOOT-3 + AC-UX-1 — when the vault is in
    /// `LockedPendingUnlock` and the dispatcher receives a `tools/call`
    /// for a vault-dependent primitive (e.g. `kvendra.git`), the response
    /// must be a JSON-RPC error with code `-32002` and a `data` payload
    /// carrying the `vault-locked-pending-unlock` help topic.
    ///
    /// `try_self_heal_vault` is the first step inside `tools_call` and
    /// will attempt to unlock from a blob. With NO blob on disk, it is
    /// a no-op (verified by `self_heal_is_noop_when_no_active_blob`) so
    /// the gate is the actual subject of this test.
    #[tokio::test]
    async fn tools_call_blocked_in_pending_state() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        crate::config::ensure_layout(home).unwrap();
        let v = Vault::new(home.to_path_buf());
        v.create_with_params(b"hunter2-pending-gate", fast_params())
            .unwrap();
        // Do NOT write a session blob — self-heal will be a no-op.
        v.mark_pending_unlock();
        assert_eq!(v.state(), VaultStateKind::LockedPendingUnlock);

        let ctx = Arc::new(ServerContext {
            vault: v,
            config: Config::default(),
            writer: std::sync::RwLock::new(None),
            approval_cache: Arc::new(ApprovalCache::new()),
            approval_prompt_lock: Arc::new(Mutex::new(())),
            transport: Transport::Mcp,
            resolver: None,
            session: None,
            workspace_id: None,
        });

        let resp = super::tools_call(
            Some(Value::from(42)),
            serde_json::json!({
                "name": "kvendra.git",
                "arguments": {
                    "profile_id": "doesnotexist",
                    "operation": "clone",
                    "args": { "url": "https://example/x.git" }
                }
            }),
            ctx,
        )
        .await;

        let err = resp.error.as_ref().expect("expected JSON-RPC error");
        assert_eq!(
            err.code,
            codes::VAULT_LOCKED_PENDING_UNLOCK,
            "expected -32002 VAULT_LOCKED_PENDING_UNLOCK"
        );
        assert_eq!(err.message, "Kvendra vault locked-pending-unlock");
        let data = err.data.as_ref().expect("expected error.data payload");
        assert_eq!(data["state"].as_str(), Some("locked_pending_unlock"));
        assert_eq!(data["tool_call_blocked"].as_str(), Some("kvendra.git"));
        assert_eq!(
            data["help"]["topic"].as_str(),
            Some("vault-locked-pending-unlock")
        );
        assert!(
            data["help"]["action"]
                .as_str()
                .is_some_and(|s| s.contains("kvendra unlock")),
            "help.action must instruct the user to run `kvendra unlock`"
        );
    }

    /// REQ-KVD-CLI-42CB74 AC-BOOT-4 — vault-free tools (when added) must
    /// bypass the LockedPendingUnlock gate. Today no such tool exists in
    /// the catalog, so we exercise the gate's BRANCH behaviour instead:
    /// when the vault state is `Unlocked` (not pending), the dispatcher
    /// must NOT short-circuit with -32002 even for a vault-dep primitive.
    /// The call will still fail downstream (profile missing) but with
    /// the legacy APPLICATION_ERROR / INVALID_PARAMS path — proving the
    /// pending gate is the only branch under test.
    #[tokio::test]
    async fn tools_call_allowed_in_pending_state_for_vault_free() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        crate::config::ensure_layout(home).unwrap();
        let v = Vault::new(home.to_path_buf());
        v.create_with_params(b"hunter2-allowed-branch", fast_params())
            .unwrap();
        v.unlock(b"hunter2-allowed-branch", 30).unwrap();
        assert_eq!(v.state(), VaultStateKind::Unlocked);

        let ctx = Arc::new(ServerContext {
            vault: v,
            config: Config::default(),
            writer: std::sync::RwLock::new(None),
            approval_cache: Arc::new(ApprovalCache::new()),
            approval_prompt_lock: Arc::new(Mutex::new(())),
            transport: Transport::Mcp,
            resolver: None,
            session: None,
            workspace_id: None,
        });

        let resp = super::tools_call(
            Some(Value::from(7)),
            serde_json::json!({
                "name": "kvendra.git",
                "arguments": {
                    "profile_id": "nope",
                    "operation": "clone",
                    "args": { "url": "https://example/x.git" }
                }
            }),
            ctx,
        )
        .await;

        // Must NOT be -32002 — the pending gate only fires for
        // LockedPendingUnlock + vault-dep, and we're Unlocked here.
        if let Some(err) = resp.error.as_ref() {
            assert_ne!(
                err.code,
                codes::VAULT_LOCKED_PENDING_UNLOCK,
                "unlocked vault must NOT trigger the pending-unlock gate"
            );
        }
        // (We don't assert success — the primitive will fail later for
        // missing profile / git args — only that the gate did not fire.)
    }

    /// REQ-KVD-CLI-42CB74 AC-HEAL-3 audit — when a `tools/call` is blocked
    /// by the LockedPendingUnlock gate AND an audit writer is attached,
    /// the dispatcher must record an audit row carrying the canonical
    /// `tool_call_blocked_pending_unlock` flag (cf.
    /// `FLAG_TOOL_CALL_BLOCKED_PENDING_UNLOCK` in `audit/mod.rs`).
    ///
    /// We assert by querying the SQLite audit DB directly after
    /// shutting the writer down.
    #[tokio::test]
    async fn tools_call_blocked_emits_audit_flag() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        crate::config::ensure_layout(home).unwrap();
        let v = Vault::new(home.to_path_buf());
        v.create_with_params(b"hunter2-audit-pending", fast_params())
            .unwrap();
        // Unlock once to mint the HMAC sub-key for the audit writer, then
        // simulate a cold-boot state by force-locking + marking pending.
        // The HMAC sub-key is captured by the writer at spawn time and
        // survives the in-RAM session being dropped, mirroring how the
        // pre-existing test fixture exercises the audit chain.
        v.unlock(b"hunter2-audit-pending", 30).unwrap();
        let writer = AuditWriter::spawn(v.audit_db_path(), v.audit_hmac_key().unwrap())
            .expect("spawn audit writer");
        v.lock();
        v.mark_pending_unlock();
        assert_eq!(v.state(), VaultStateKind::LockedPendingUnlock);

        let ctx = Arc::new(ServerContext {
            vault: v,
            config: Config::default(),
            writer: std::sync::RwLock::new(Some(writer)),
            approval_cache: Arc::new(ApprovalCache::new()),
            approval_prompt_lock: Arc::new(Mutex::new(())),
            transport: Transport::Mcp,
            resolver: None,
            session: None,
            workspace_id: None,
        });

        let resp = super::tools_call(
            Some(Value::from(9)),
            serde_json::json!({
                "name": "kvendra.git",
                "arguments": {
                    "profile_id": "p-audit",
                    "operation": "clone",
                    "args": { "url": "https://example/x.git" }
                }
            }),
            ctx.clone(),
        )
        .await;
        assert_eq!(
            resp.error.as_ref().map(|e| e.code),
            Some(codes::VAULT_LOCKED_PENDING_UNLOCK),
            "precondition: gate must have fired"
        );

        // Drain writer.
        ctx.audit_writer().unwrap().shutdown().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let conn = rusqlite::Connection::open(ctx.vault.audit_db_path()).unwrap();
        let flags: String = conn
            .query_row(
                "SELECT flags FROM audit_events \
                 WHERE primitive = 'kvendra.git' AND profile_id = 'p-audit' \
                 ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .expect("gate must have written at least one audit row");
        assert!(
            flags.contains(crate::audit::FLAG_TOOL_CALL_BLOCKED_PENDING_UNLOCK),
            "audit row must carry the canonical pending-unlock flag, got: {flags}"
        );
    }

    /// Negative path: with no session blob on disk, the vault stays
    /// locked and the call is a no-op (will surface as VaultLocked
    /// downstream so the primitive returns a clean error).
    #[test]
    fn self_heal_is_noop_when_no_active_blob() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        crate::config::ensure_layout(home).unwrap();
        let v = Vault::new(home.to_path_buf());
        v.create_with_params(b"hunter2-no-blob", fast_params())
            .unwrap();
        // Never unlock + never persist a blob.
        assert!(!v.is_unlocked());

        let ctx = ServerContext {
            vault: v,
            config: Config::default(),
            writer: std::sync::RwLock::new(None),
            approval_cache: Arc::new(ApprovalCache::new()),
            approval_prompt_lock: Arc::new(Mutex::new(())),
            transport: Transport::Mcp,
            resolver: None,
            session: None,
            workspace_id: None,
        };

        super::try_self_heal_vault(&ctx);
        assert!(
            !ctx.vault.is_unlocked(),
            "no blob → vault must remain locked"
        );
    }

    /// ISSUE-KVD-CLI-9764AC fix — when the server boots with the vault in
    /// `LockedPendingUnlock` the audit writer is initialised to `None`.
    /// After a successful self-heal from a freshly-landed session blob,
    /// the writer slot MUST transition to `Some(_)` so subsequent
    /// `record_audit` calls do not silently drop events. Before the fix,
    /// `ctx.writer` stayed `None` for the lifetime of the process, which
    /// explains the empirical evidence: `auditEventId: 0` in JSON-RPC
    /// responses + zero rows in `~/.kvendra/audit.db` for
    /// `flags LIKE '%self_heal%'`.
    #[test]
    fn audit_writer_lazy_spawn_after_self_heal_from_pending() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        crate::config::ensure_layout(home).unwrap();
        let v = Vault::new(home.to_path_buf());
        v.create_with_params(b"hunter2-lazy-spawn", fast_params())
            .unwrap();
        // Mint the derived key, persist a session blob, then drop the in-RAM
        // session and mark the vault `LockedPendingUnlock` (cold-boot shape).
        v.unlock(b"hunter2-lazy-spawn", 30).unwrap();
        let derived = v.peek_session_derived_key().unwrap();
        let state = crate::session::local::build_state_for_current_machine(
            derived,
            std::time::Duration::from_secs(3600),
            home,
        )
        .unwrap();
        crate::session::local::persist_atomic(&state, home).unwrap();
        v.lock();
        v.mark_pending_unlock();
        assert_eq!(v.state(), VaultStateKind::LockedPendingUnlock);

        // Critical pre-condition: writer constructed as None (mirrors the
        // production boot path when `audit_hmac_key()` errored).
        let ctx = ServerContext {
            vault: v,
            config: Config::default(),
            writer: std::sync::RwLock::new(None),
            approval_cache: Arc::new(ApprovalCache::new()),
            approval_prompt_lock: Arc::new(Mutex::new(())),
            transport: Transport::Mcp,
            resolver: None,
            session: None,
            workspace_id: None,
        };
        assert!(
            ctx.audit_writer().is_none(),
            "precondition: writer must start as None"
        );

        super::try_self_heal_vault(&ctx);

        // Vault unlocked (sanity).
        assert!(
            ctx.vault.is_unlocked(),
            "self-heal must unlock the vault from the session blob"
        );
        // The actual ISSUE-KVD-CLI-9764AC assertion — writer slot is now Some.
        assert!(
            ctx.audit_writer().is_some(),
            "audit writer MUST be lazy-spawned after self-heal from \
             LockedPendingUnlock (ISSUE-KVD-CLI-9764AC fix)"
        );
    }

    /// ISSUE-KVD-CLI-9764AC fix — end-to-end: after lazy-spawn the writer
    /// must actually persist rows to SQLite. Drives `record_audit` directly
    /// post self-heal and verifies the row lands in `audit_events` with a
    /// non-zero id and the expected flags.
    #[tokio::test]
    async fn audit_row_persisted_after_lazy_spawn() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        crate::config::ensure_layout(home).unwrap();
        let v = Vault::new(home.to_path_buf());
        v.create_with_params(b"hunter2-row-persist", fast_params())
            .unwrap();
        v.unlock(b"hunter2-row-persist", 30).unwrap();
        let derived = v.peek_session_derived_key().unwrap();
        let state = crate::session::local::build_state_for_current_machine(
            derived,
            std::time::Duration::from_secs(3600),
            home,
        )
        .unwrap();
        crate::session::local::persist_atomic(&state, home).unwrap();
        v.lock();
        v.mark_pending_unlock();

        let ctx = ServerContext {
            vault: v,
            config: Config::default(),
            writer: std::sync::RwLock::new(None),
            approval_cache: Arc::new(ApprovalCache::new()),
            approval_prompt_lock: Arc::new(Mutex::new(())),
            transport: Transport::Mcp,
            resolver: None,
            session: None,
            workspace_id: None,
        };

        // Trigger self-heal (sync) → writer should be lazy-spawned.
        super::try_self_heal_vault(&ctx);
        assert!(ctx.vault.is_unlocked());
        assert!(ctx.audit_writer().is_some(), "writer must be spawned");

        // Drive record_audit through the public entry point. Before the
        // fix this call returned `Err(Audit("audit disabled (vault locked)"))`
        // because `ctx.writer` was still `None`. Post-fix it returns a
        // valid event id > 0.
        let event_id = super::record_audit(
            &ctx,
            &serde_json::json!({ "operation": "ping" }),
            "kvendra.test",
            "test-profile",
            "ping",
            &["mcp_self_heal_from_pending".to_string()],
            false,
            None,
            None,
        )
        .await
        .expect("record_audit must succeed post lazy-spawn");
        assert!(
            event_id > 0,
            "post lazy-spawn record_audit must return a real event id, got {event_id}"
        );

        // Drain writer and inspect SQLite directly — verifies the HMAC
        // chain is wired correctly (the writer task only acks after the
        // INSERT + HMAC compute succeed).
        ctx.audit_writer().unwrap().shutdown().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let conn = rusqlite::Connection::open(ctx.vault.audit_db_path()).unwrap();
        let (id, primitive, flags, hmac_hex): (i64, String, String, String) = conn
            .query_row(
                "SELECT id, primitive, flags, hmac_hex FROM audit_events \
                 WHERE primitive = 'kvendra.test' ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .expect("lazy-spawned writer must have persisted at least one row");
        assert_eq!(id, event_id, "in-memory event_id must match SQLite row id");
        assert_eq!(primitive, "kvendra.test");
        assert!(
            flags.contains("mcp_self_heal_from_pending"),
            "row must carry the self-heal flag we passed in, got: {flags}"
        );
        assert!(
            !hmac_hex.is_empty(),
            "HMAC chain column must be populated — empty means writer skipped HMAC compute"
        );
    }
}
