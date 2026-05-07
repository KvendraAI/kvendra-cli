//! Approval layer — interactive per-`tools/call` confirmation (REQ-KVD-003).
//!
//! Cierra el gap V7 (agente AI malicioso/comprometido invoca primitives) +
//! sub-vector aceptado O1.LLM-auto-approve del threat model (ADR-KVD-010).
//!
//! Tres modos configurables (ADR-KVD-013..016):
//! - `silent` — ejecuta directo. Default para CI/automation. NO requiere TTY.
//! - `ask` — prompt para CADA `tools/call`. Requiere TTY.
//! - `ask-destructive` (DEFAULT) — prompt sólo cuando la operación está marcada
//!   `destructive: true` en la allowlist. Requiere TTY si la operación dispara.
//!
//! Cascade de configuración (más específica gana):
//!   env > profile YAML > config.toml > default.

pub mod biometric;
pub mod cache;
pub mod policy;
pub mod transport;
pub mod tty;

pub use transport::Transport;

use crate::allowlist::ProfileSpec;
use crate::audit::reader::args_hash_hex;
use crate::audit::{AuditEvent, Severity, Status};
use crate::error::KvendraResult;
use crate::mcp::server::ServerContext;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use time::OffsetDateTime;

pub use cache::{ApprovalCache, DEFAULT_TTL_SECONDS};

const ARGS_SUMMARY_MAX_CHARS: usize = 80;

/// Modo activo de validación humana per `tools/call`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalMode {
    /// Ejecuta directo según allowlist; sin prompts.
    Silent,
    /// Prompt antes de cada `tools/call`.
    Ask,
    /// Prompt sólo para operaciones marcadas `destructive`. Default sensato.
    #[default]
    AskDestructive,
}

/// Resultado de la decisión de approval para un `tools/call` concreto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// El user pulsó `[y]`.
    Granted,
    /// El user pulsó `[a]` (approve-all-5min). Cache poblada.
    GrantedAllForFiveMin,
    /// Acertó el cache approve-all-5min (sin prompt mostrado).
    CacheHit,
    /// Modo no requiere prompt para esta llamada (silent o non-destructive en
    /// ask-destructive).
    Silent,
    /// El user pulsó `[N]` o cualquier respuesta no afirmativa.
    Denied,
    /// Timeout sin respuesta del user.
    Timeout,
    /// Modo `ask*` activo pero sin TTY accesible.
    NoTty,
    /// MCP transport: el user aceptó el popup OS (TouchID / dialog) y la
    /// llamada queda autorizada por la ventana de cache. Cache poblada.
    BiometricGranted,
    /// MCP transport: el user rechazó el popup OS. Bloquea dispatch.
    BiometricRejected,
    /// MCP transport: el OS no puede mostrar el popup biometric (Linux
    /// headless, Windows no soportado, etc.). Bloquea dispatch.
    BiometricUnavailable,
}

impl ApprovalDecision {
    /// Flag CSV para el audit log. `None` = sin flag adicional.
    pub fn audit_flag(&self) -> Option<&'static str> {
        match self {
            ApprovalDecision::Granted => Some("approval_granted"),
            ApprovalDecision::GrantedAllForFiveMin => Some("approval_granted_all_5min"),
            ApprovalDecision::CacheHit => Some("approval_cache_hit"),
            ApprovalDecision::Silent => None,
            ApprovalDecision::Denied => Some("approval_denied"),
            ApprovalDecision::Timeout => Some("approval_timeout"),
            ApprovalDecision::NoTty => Some("approval_no_tty_denied"),
            ApprovalDecision::BiometricGranted => Some("mcp_approval_biometric_granted"),
            ApprovalDecision::BiometricRejected => Some("mcp_approval_biometric_rejected"),
            ApprovalDecision::BiometricUnavailable => Some("mcp_approval_biometric_not_available"),
        }
    }

    /// Si la decisión bloquea el dispatch (no se invoca al primitive).
    pub fn blocks_dispatch(&self) -> bool {
        matches!(
            self,
            ApprovalDecision::Denied
                | ApprovalDecision::Timeout
                | ApprovalDecision::NoTty
                | ApprovalDecision::BiometricRejected
                | ApprovalDecision::BiometricUnavailable
        )
    }

    /// Identificador estable del error_type devuelto al cliente MCP.
    pub fn error_type(&self) -> Option<&'static str> {
        match self {
            ApprovalDecision::Denied => Some("approval_denied"),
            ApprovalDecision::Timeout => Some("approval_timeout"),
            ApprovalDecision::NoTty => Some("approval_no_tty"),
            ApprovalDecision::BiometricRejected => Some("approval_denied"),
            ApprovalDecision::BiometricUnavailable => Some("approval_no_biometric"),
            _ => None,
        }
    }
}

/// Datos pasados al backend de prompt para construir la UI.
#[derive(Debug, Clone)]
pub struct ApprovalContext {
    pub profile_id: String,
    pub primitive: String,
    pub operation: String,
    pub args_summary: String,
    pub destructive: bool,
    pub mode: ApprovalMode,
    pub timeout_seconds: u32,
}

/// Backend abstracto del prompt de approval. Permite inyectar implementaciones
/// alternativas en tests (`AutoApproveBackend` etc.).
pub trait ApprovalBackend: Send + Sync {
    fn ask(
        &self,
        ctx: ApprovalContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ApprovalDecision> + Send + '_>>;
}

/// Trunca la representación JSON de `value` a [`ARGS_SUMMARY_MAX_CHARS`] con `…`
/// si excede.
pub fn format_args_summary(value: &Value) -> String {
    let raw = match value {
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| format!("{k}={}", json_brief(v)))
            .collect::<Vec<_>>()
            .join(", "),
        _ => json_brief(value),
    };
    if raw.chars().count() > ARGS_SUMMARY_MAX_CHARS {
        let mut out: String = raw.chars().take(ARGS_SUMMARY_MAX_CHARS - 1).collect();
        out.push('…');
        out
    } else {
        raw
    }
}

fn json_brief(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        other => other.to_string(),
    }
}

/// Entry-point invocado por `mcp::server::tools_call` entre el enforcement de
/// la allowlist y el `record_audit` Started.
///
/// Aplica la cascade env → profile YAML → config.toml → default y delega al
/// backend TTY si procede. Garantiza la regla **nunca ejecuta sin confirmación
/// explícita** cuando el modo lo exige.
pub async fn check(
    ctx: &ServerContext,
    primitive: &str,
    profile_id: &str,
    operation: &str,
    arguments: &Value,
) -> ApprovalDecision {
    let env_mode = std::env::var("KVENDRA_APPROVAL_MODE")
        .ok()
        .and_then(|s| policy::parse_mode(&s));

    let (profile_override_mode, destructive) = if profile_id.is_empty() {
        (None, false)
    } else {
        match load_profile_spec(ctx, profile_id) {
            Some(spec) => {
                let mode = spec
                    .approval
                    .as_ref()
                    .and_then(|a| a.mode.as_deref())
                    .and_then(policy::parse_mode);
                let destructive =
                    policy::lookup_destructive(&spec, primitive, operation, arguments);
                (mode, destructive)
            }
            None => (None, false),
        }
    };

    let global = ctx.config.approval.mode;
    let mode = policy::resolve_mode(env_mode, profile_override_mode, global);

    if !policy::should_prompt(mode, destructive) {
        return ApprovalDecision::Silent;
    }

    if !profile_id.is_empty()
        && let Some(_remaining) = ctx.approval_cache.lookup(profile_id).await
    {
        return ApprovalDecision::CacheHit;
    }

    let timeout_seconds = ctx.config.approval.timeout_seconds;
    let cache_ttl = Duration::from_secs(u64::from(ctx.config.approval.cache_ttl_seconds));

    let prompt_ctx = ApprovalContext {
        profile_id: profile_id.to_string(),
        primitive: primitive.to_string(),
        operation: operation.to_string(),
        args_summary: format_args_summary(arguments),
        destructive,
        mode,
        timeout_seconds,
    };

    let _guard = ctx.approval_prompt_lock.lock().await;
    let decision: ApprovalDecision = if ctx.transport.is_mcp() {
        biometric::BiometricApprovalBackend.ask(prompt_ctx).await
    } else {
        tty::TtyApprovalBackend.ask(prompt_ctx).await
    };

    // The TTY path uses an explicit `[a]pprove-all-5min` button to populate
    // the cache. The biometric path has no equivalent multi-button UI, so a
    // single biometric grant warms the cache for the same TTL window — the
    // prompt is OS-mediated and the user is implicitly opting into the
    // 5-minute relaxation by accepting it.
    if matches!(
        decision,
        ApprovalDecision::GrantedAllForFiveMin | ApprovalDecision::BiometricGranted
    ) && !profile_id.is_empty()
    {
        ctx.approval_cache.approve(profile_id, cache_ttl).await;
    }

    decision
}

fn load_profile_spec(ctx: &ServerContext, profile_id: &str) -> Option<ProfileSpec> {
    let path = ctx.vault.profile_allowlist_path(profile_id);
    if !path.exists() {
        return None;
    }
    let raw = std::fs::read_to_string(&path).ok()?;
    serde_yml::from_str(&raw).ok()
}

/// Hint estructurado a devolver en el `data` del error MCP cuando la decisión
/// bloquea el dispatch.
pub fn hint_for(decision: ApprovalDecision, timeout_seconds: u32) -> &'static str {
    match decision {
        ApprovalDecision::Denied => "user denied this operation",
        ApprovalDecision::Timeout => {
            // Static hint genérico — el cliente puede leer timeout_seconds del
            // payload si lo necesita; aquí prima una cadena estable.
            let _ = timeout_seconds;
            "no response within configured timeout — increase [approval].timeout_seconds in ~/.kvendra/config.toml or set KVENDRA_APPROVAL_MODE=silent"
        }
        ApprovalDecision::NoTty => {
            "no TTY available; set KVENDRA_APPROVAL_MODE=silent for non-interactive contexts"
        }
        ApprovalDecision::BiometricRejected => "user denied this operation via OS popup",
        ApprovalDecision::BiometricUnavailable => {
            "biometric/OS popup not available on this platform (macOS-only in this release); \
             set KVENDRA_APPROVAL_MODE=silent for non-supported platforms"
        }
        _ => "",
    }
}

/// Helper compartido con `record_audit` en `mcp::server` para construir un
/// `AuditEvent` con flags actualizados desde `tools_call`.
pub fn build_pre_dispatch_event(
    arguments: &Value,
    primitive: &str,
    profile_id: &str,
    action: &str,
    flags: &[String],
    failed_pre_dispatch: bool,
) -> AuditEvent {
    AuditEvent {
        ts_unix_ms: OffsetDateTime::now_utc().unix_timestamp_nanos() as i64 / 1_000_000,
        profile_id: profile_id.to_string(),
        primitive: primitive.to_string(),
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
    }
}

/// Mantén la firma compatible con tests futuros aunque hoy no se use el
/// retorno: KvendraResult permite encadenar.
#[allow(dead_code)]
pub fn ok() -> KvendraResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn approval_mode_default_is_ask_destructive() {
        assert_eq!(ApprovalMode::default(), ApprovalMode::AskDestructive);
    }

    #[test]
    fn approval_decision_audit_flag_silent_is_none() {
        assert_eq!(ApprovalDecision::Silent.audit_flag(), None);
    }

    #[test]
    fn approval_decision_blocks_dispatch_only_on_negative_outcomes() {
        assert!(ApprovalDecision::Denied.blocks_dispatch());
        assert!(ApprovalDecision::Timeout.blocks_dispatch());
        assert!(ApprovalDecision::NoTty.blocks_dispatch());
        assert!(!ApprovalDecision::Granted.blocks_dispatch());
        assert!(!ApprovalDecision::GrantedAllForFiveMin.blocks_dispatch());
        assert!(!ApprovalDecision::CacheHit.blocks_dispatch());
        assert!(!ApprovalDecision::Silent.blocks_dispatch());
    }

    #[test]
    fn approval_mode_serde_kebab_case_round_trip() {
        let s = serde_json::to_string(&ApprovalMode::AskDestructive).unwrap();
        assert_eq!(s, "\"ask-destructive\"");
        let back: ApprovalMode = serde_json::from_str("\"ask\"").unwrap();
        assert_eq!(back, ApprovalMode::Ask);
    }

    #[test]
    fn args_summary_truncates_long_values() {
        let v = json!({ "data": "a".repeat(200) });
        let s = format_args_summary(&v);
        assert!(s.chars().count() <= ARGS_SUMMARY_MAX_CHARS);
        assert!(s.ends_with('…'));
    }

    #[test]
    fn args_summary_short_values_pass_through() {
        let v = json!({ "repo": "KvendraAI/kvendra-cli" });
        let s = format_args_summary(&v);
        assert_eq!(s, "repo=KvendraAI/kvendra-cli");
    }
}
