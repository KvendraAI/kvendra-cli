//! Integration tests for the approval layer (REQ-KVD-003).
//!
//! Cubre los ACs no cubiertos por los tests inline de FASE 2:
//! - AC-APPROVAL-3 (TTY isolation del JSON-RPC stdio)
//! - AC-APPROVAL-4 (timeout auto-deny + audit row)
//! - AC-APPROVAL-6 (no TTY en modo `ask*` → audit `approval_no_tty_denied` +
//!   error MCP estructurado, NUNCA ejecuta el primitive)
//!
//! Estos tests son auto-contenidos — no spawn de procesos: aprovechan que
//! `cargo test` corre sin TTY adjunto, lo que ejercita exactamente el
//! comportamiento que valida AC-APPROVAL-6.

use kvendra::approval::tty::{AutoApproveBackend, AutoDenyBackend, TtyApprovalBackend};
use kvendra::approval::{ApprovalBackend, ApprovalContext, ApprovalDecision, ApprovalMode};
use kvendra::mcp::protocol::{JsonRpcResponse, codes};
use serde_json::Value;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

fn ctx_destructive() -> ApprovalContext {
    ApprovalContext {
        profile_id: "test.aws.deploy".into(),
        primitive: "kvendra.aws".into(),
        operation: "s3_sync".into(),
        args_summary: "src=./out, dst=s3://prod, delete=true".into(),
        destructive: true,
        mode: ApprovalMode::AskDestructive,
        timeout_seconds: 1,
    }
}

// ----------------------------------------------------------------------
// AC-APPROVAL-6 — sin TTY, modo ask* → NoTty (NUNCA ejecuta)
// ----------------------------------------------------------------------

/// El test runner de cargo no tiene TTY adjunto: el TtyApprovalBackend
/// debe responder `NoTty` y NO bloquear esperando input. Es exactamente la
/// invariante que protege contra ejecuciones silenciosas en CI/automation
/// con modo `ask*` activo.
#[tokio::test(flavor = "current_thread")]
async fn tty_backend_returns_no_tty_in_cargo_test_environment() {
    let backend = TtyApprovalBackend;
    let decision = tokio::time::timeout(Duration::from_secs(2), backend.ask(ctx_destructive()))
        .await
        .expect("backend must complete within 2s without TTY (no input read)");
    assert_eq!(
        decision,
        ApprovalDecision::NoTty,
        "without a TTY the backend must return NoTty, never block on input"
    );
}

/// Si la decisión del approval layer es `NoTty`, el flag de audit + el
/// error_type estructurado devuelto al cliente MCP deben ser canónicos.
/// Cubre el contrato que `mcp::server::tools_call` consume tras el hook
/// (`if blocks_dispatch { record_audit + error_with_data }`).
#[test]
fn no_tty_decision_carries_canonical_audit_flag_and_error_type() {
    let d = ApprovalDecision::NoTty;
    assert!(d.blocks_dispatch(), "NoTty must block dispatch");
    assert_eq!(d.audit_flag(), Some("approval_no_tty_denied"));
    assert_eq!(d.error_type(), Some("approval_no_tty"));
}

// ----------------------------------------------------------------------
// AC-APPROVAL-4 — timeout auto-deny + canonical flag + error_type
// ----------------------------------------------------------------------

/// `ApprovalDecision::Timeout` debe bloquear el dispatch y exponer las
/// constantes esperadas por el cliente MCP / el audit reader.
#[test]
fn timeout_decision_carries_canonical_audit_flag_and_error_type() {
    let d = ApprovalDecision::Timeout;
    assert!(d.blocks_dispatch(), "Timeout must block dispatch");
    assert_eq!(d.audit_flag(), Some("approval_timeout"));
    assert_eq!(d.error_type(), Some("approval_timeout"));
}

/// Mock backend que duerme deliberadamente más que el timeout configurado,
/// emulando un user que no responde. Verificamos que envuelto en
/// `tokio::time::timeout` se mapea a un `Timeout` reproducible (pieza
/// equivalente a la lógica interna del TtyApprovalBackend).
struct SlowBackend {
    delay_ms: u64,
}

impl ApprovalBackend for SlowBackend {
    fn ask(
        &self,
        _ctx: ApprovalContext,
    ) -> Pin<Box<dyn Future<Output = ApprovalDecision> + Send + '_>> {
        let delay = self.delay_ms;
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(delay)).await;
            ApprovalDecision::Granted
        })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn slow_backend_triggers_outer_timeout() {
    let backend = SlowBackend { delay_ms: 500 };
    let result =
        tokio::time::timeout(Duration::from_millis(50), backend.ask(ctx_destructive())).await;
    assert!(
        result.is_err(),
        "outer timeout must fire when backend is slow; got {result:?}"
    );
}

// ----------------------------------------------------------------------
// AC-APPROVAL-3 — TTY isolation: JSON-RPC error response well-formed
// ----------------------------------------------------------------------

/// El cliente MCP debe recibir un error JSON-RPC con `data.error_type` y
/// `data.hint` cuando el approval bloquea el dispatch. Esto valida el
/// contrato del wire (consumido por agentes IA para auto-corregir el
/// modo / configuración).
#[test]
fn approval_error_response_serializes_with_structured_data() {
    let data = serde_json::json!({
        "error_type": "approval_no_tty",
        "hint": "no TTY available; set KVENDRA_APPROVAL_MODE=silent for non-interactive contexts",
    });
    let resp = JsonRpcResponse::error_with_data(
        Some(Value::from(42)),
        codes::APPLICATION_ERROR,
        "approval not granted: approval_no_tty",
        data.clone(),
    );

    let wire = serde_json::to_string(&resp).unwrap();
    assert!(wire.contains("\"jsonrpc\":\"2.0\""));
    assert!(wire.contains("\"id\":42"));
    assert!(wire.contains("\"error\""));
    assert!(
        !wire.contains("\"result\""),
        "error response must omit result field"
    );
    assert!(wire.contains("\"error_type\":\"approval_no_tty\""));
    assert!(wire.contains("\"hint\""));
    assert!(wire.contains(&codes::APPLICATION_ERROR.to_string()));
}

/// Defensa estructural de AC-APPROVAL-3: el ASCII box de prompt no se
/// emite cuando el backend devuelve `NoTty`. Combinado con el test de
/// arriba, garantiza que en un entorno sin TTY la salida (stdout/stderr
/// del proceso) no contiene los caracteres del box, y por tanto JSON-RPC
/// stdio no se contamina.
#[tokio::test(flavor = "current_thread")]
async fn no_tty_environment_does_not_emit_prompt_box() {
    // En este test no podemos capturar /dev/tty (que es un canal aparte),
    // pero podemos verificar que el backend devuelve NoTty inmediatamente
    // sin esperar input — lo que implica que NO escribe el box (la lógica
    // del backend retorna ANTES de `writeln!` cuando is_terminal()=false).
    let backend = TtyApprovalBackend;
    let start = std::time::Instant::now();
    let decision = backend.ask(ctx_destructive()).await;
    let elapsed = start.elapsed();
    assert_eq!(decision, ApprovalDecision::NoTty);
    assert!(
        elapsed < Duration::from_millis(500),
        "NoTty path must short-circuit without waiting for input; took {elapsed:?}"
    );
}

// ----------------------------------------------------------------------
// Sanity — los backends test-only que el approval module expone deben
// seguir funcionando como contrato estable para tester / consumidores.
// ----------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn auto_approve_backend_grants_immediately() {
    let b = AutoApproveBackend;
    let d = b.ask(ctx_destructive()).await;
    assert_eq!(d, ApprovalDecision::Granted);
    assert!(!d.blocks_dispatch());
    assert_eq!(d.audit_flag(), Some("approval_granted"));
}

#[tokio::test(flavor = "current_thread")]
async fn auto_deny_backend_denies_immediately() {
    let b = AutoDenyBackend;
    let d = b.ask(ctx_destructive()).await;
    assert_eq!(d, ApprovalDecision::Denied);
    assert!(d.blocks_dispatch());
    assert_eq!(d.audit_flag(), Some("approval_denied"));
    assert_eq!(d.error_type(), Some("approval_denied"));
}

// ----------------------------------------------------------------------
// REQ-KVD-006 / ISSUE-KVD-CLI-020 — biometric ApprovalDecision contract
// ----------------------------------------------------------------------

/// AC-BIOMETRIC-1 contract: when MCP transport accepts via biometric / OS
/// popup, the decision must NOT block dispatch and must carry the canonical
/// audit flag + no error_type (success path).
#[test]
fn biometric_granted_decision_carries_canonical_audit_flag() {
    let d = ApprovalDecision::BiometricGranted;
    assert!(
        !d.blocks_dispatch(),
        "BiometricGranted must NOT block dispatch"
    );
    assert_eq!(d.audit_flag(), Some("mcp_approval_biometric_granted"));
    assert_eq!(d.error_type(), None);
}

/// AC-BIOMETRIC-2 contract: user-rejected biometric prompt must block
/// dispatch and surface as `approval_denied` to the MCP client (so the
/// client UX is uniform with TTY denial).
#[test]
fn biometric_rejected_decision_blocks_dispatch_with_canonical_flag() {
    let d = ApprovalDecision::BiometricRejected;
    assert!(d.blocks_dispatch(), "BiometricRejected must block dispatch");
    assert_eq!(d.audit_flag(), Some("mcp_approval_biometric_rejected"));
    assert_eq!(d.error_type(), Some("approval_denied"));
}

/// AC-BIOMETRIC-3 contract: Linux headless / Windows / macOS w/o biometric
/// must block dispatch and surface as `approval_no_biometric` so the client
/// can suggest the silent-mode workaround.
#[test]
fn biometric_unavailable_decision_blocks_dispatch_with_canonical_flag() {
    let d = ApprovalDecision::BiometricUnavailable;
    assert!(
        d.blocks_dispatch(),
        "BiometricUnavailable must block dispatch"
    );
    assert_eq!(d.audit_flag(), Some("mcp_approval_biometric_not_available"));
    assert_eq!(d.error_type(), Some("approval_no_biometric"));
}

/// `hint_for` returns user-facing guidance when biometric paths block
/// dispatch. Stable strings — clients can pattern-match if needed.
#[test]
fn hint_for_biometric_decisions_returns_user_guidance() {
    use kvendra::approval::hint_for;
    let rejected = hint_for(ApprovalDecision::BiometricRejected, 30);
    assert!(rejected.contains("denied"), "got: {rejected}");
    assert!(rejected.contains("OS popup"), "got: {rejected}");

    let unavailable = hint_for(ApprovalDecision::BiometricUnavailable, 30);
    assert!(unavailable.contains("macOS-only"), "got: {unavailable}");
    assert!(
        unavailable.contains("KVENDRA_APPROVAL_MODE=silent"),
        "got: {unavailable}"
    );
}

/// AC-BIOMETRIC-3 (non-macOS path): on platforms where the keychain_acl
/// subsystem reports `Unavailable`, the BiometricApprovalBackend must
/// surface that as `BiometricUnavailable` (never panic, never return
/// `BiometricGranted` by accident — fail-safe).
#[cfg(not(target_os = "macos"))]
#[tokio::test(flavor = "current_thread")]
async fn biometric_backend_unavailable_on_non_macos() {
    let b = kvendra::approval::biometric::BiometricApprovalBackend;
    let d = b.ask(ctx_destructive()).await;
    assert_eq!(d, ApprovalDecision::BiometricUnavailable);
    assert!(d.blocks_dispatch());
    assert_eq!(d.audit_flag(), Some("mcp_approval_biometric_not_available"));
}
