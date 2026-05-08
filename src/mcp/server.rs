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
use crate::audit::{AuditEvent, AuditWriter, PRIMITIVE_SYSTEM, Severity, Status};
use crate::config::Config;
use crate::detection::{Decision, detect};
use crate::error::{KvendraError, KvendraResult};
use crate::mcp::protocol::{
    InitializeResult, JsonRpcRequest, JsonRpcResponse, ServerInfo, ToolDescriptor, ToolsListResult,
    codes,
};
use crate::mcp::transport::StdioTransport;
use crate::primitives::catalog;
use crate::vault::{SecretPlaintext, Vault};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::Mutex;

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
    pub writer: Option<AuditWriter>,
    /// Approve-all-5min cache (REQ-KVD-003 / ADR-KVD-014). Per-profile, in-mem.
    pub approval_cache: Arc<ApprovalCache>,
    /// Serializa los prompts de approval concurrentes (REQ-KVD-003 risk
    /// mitigation): solo un prompt activo a la vez.
    pub approval_prompt_lock: Arc<Mutex<()>>,
    /// Transport canal del approval flow (REQ-KVD-006 / ADR-KVD-021).
    /// Inicializado a `Transport::Mcp` desde `serve_with_vault`; tests
    /// pure-policy pueden construir un `ServerContext` con `Transport::Cli`.
    pub transport: Transport,
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

    let ctx = Arc::new(ServerContext {
        vault,
        config,
        writer,
        approval_cache: Arc::new(ApprovalCache::new()),
        approval_prompt_lock: Arc::new(Mutex::new(())),
        transport: Transport::Mcp,
    });
    let mut transport = StdioTransport::new();

    while let Some(req) = transport.read().await? {
        let resp = dispatch(req, ctx.clone()).await;
        transport.write(&resp).await?;
    }
    if let Some(w) = &ctx.writer {
        w.shutdown().await;
    }
    Ok(())
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

async fn tools_call(id: Option<Value>, params: Value, ctx: Arc<ServerContext>) -> JsonRpcResponse {
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
                let _ =
                    record_audit(&ctx, &arguments, name, &profile_id, &action, &flags, true).await;
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
                let _ =
                    record_audit(&ctx, &arguments, name, &profile_id, &action, &flags, true).await;
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
                let _ =
                    record_audit(&ctx, &arguments, name, &profile_id, &action, &flags, true).await;
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
                let _ =
                    record_audit(&ctx, &arguments, name, &profile_id, &action, &flags, true).await;
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
        let _ = record_audit(&ctx, &arguments, name, &profile_id, &action, &flags, true).await;
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

    // Started event. `0` indicates audit was disabled (vault locked).
    let event_id: i64 = record_audit(&ctx, &arguments, name, &profile_id, &action, &flags, false)
        .await
        .unwrap_or_default();

    // Load secret plaintext if vault unlocked + profile exists.
    let secret = if !profile_id.is_empty() && ctx.vault.is_unlocked() {
        ctx.vault.get_secret(&profile_id).ok()
    } else {
        None
    };

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
    if let Some(w) = &ctx.writer {
        if event_id > 0 {
            let _ = w.update_status(event_id, status, severity).await;
        }
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

async fn record_audit(
    ctx: &ServerContext,
    arguments: &Value,
    name: &str,
    profile_id: &str,
    action: &str,
    flags: &[String],
    failed_pre_dispatch: bool,
) -> KvendraResult<i64> {
    let Some(w) = &ctx.writer else {
        return Err(KvendraError::Audit("audit disabled (vault locked)".into()));
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
            if let Some(writer) = ctx.writer.as_ref() {
                let event = AuditEvent {
                    ts_unix_ms: OffsetDateTime::now_utc().unix_timestamp_nanos() as i64
                        / 1_000_000,
                    profile_id: profile_id.to_string(),
                    primitive: PRIMITIVE_SYSTEM.to_string(),
                    action: "allowlist_hmac_migrated".to_string(),
                    args_hash_hex: sha256_hex(profile_id.as_bytes()),
                    status: Status::Ok,
                    severity: Severity::Info,
                    flags: "allowlist_hmac_migrated".to_string(),
                };
                writer.record(event).await?;
            }
            migration_outcome = MigrationOutcome::Migrated;
        }
    }

    let spec: ProfileSpec = serde_yml::from_str(&raw)?;
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
            writer,
            approval_cache: Arc::new(ApprovalCache::new()),
            approval_prompt_lock: Arc::new(Mutex::new(())),
            transport: Transport::Mcp,
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
        ctx.writer.as_ref().unwrap().shutdown().await;
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
            writer: None,
            approval_cache: Arc::new(ApprovalCache::new()),
            approval_prompt_lock: Arc::new(Mutex::new(())),
            transport: Transport::Mcp,
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
}
