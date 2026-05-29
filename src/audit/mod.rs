//! Audit log — SQLite WAL + HMAC-chain (REQ-KVD-002 Bloque 6, ADR-KVD-007).
//!
//! Public API: [`AuditEvent`], [`AuditLog`], [`AuditWriter`].

pub mod bootstrap;
pub mod export;
pub mod hmac;
pub mod migrations;
pub mod reader;
pub mod schema;
pub mod writer;

use serde::{Deserialize, Serialize};

/// Canonical primitive string for system-level (non-MCP) audit rows such as
/// `vault_created` (REQ-KVD-002 / ISSUE-003) and `home_rebound`
/// (REQ-KVD-008 / ISSUE-019). Distinct from the 7 capability primitives
/// (`kvendra.git`, `kvendra.github`, ...) so dashboards can filter system
/// events without enumerating each action.
pub const PRIMITIVE_SYSTEM: &str = "kvendra.system";

// ─── Canonical flag strings for the local session model (REQ-KVD-CLI-011 /
//     AC-SESSION-14). Defined here so callers cannot drift on the wire and
//     downstream dashboards / `audit verify` filters can match exact bytes.

/// `kvendra unlock` finished successfully and a session blob was written.
pub const FLAG_UNLOCK_SUCCEEDED: &str = "unlock_succeeded";

/// `kvendra unlock` was rejected because `/dev/tty` (or `CONIN$`) could not
/// be opened — almost always a captured-stdio MCP subprocess.
pub const FLAG_UNLOCK_REJECTED_NO_CONTROLLING_TTY: &str = "unlock_rejected_no_controlling_tty";

/// `kvendra unlock` was rejected by the triple `isatty` + foreground pgrp
/// check (second layer of the captured-env defense).
pub const FLAG_UNLOCK_REJECTED_STDIO_NOT_OWNED: &str = "unlock_rejected_stdio_not_owned";

/// `kvendra unlock --extend` bumped the TTL of an existing session.
pub const FLAG_UNLOCK_EXTENDED: &str = "unlock_extended";

/// `kvendra unlock --recovery` consumed one recovery code and reset the
/// master password (chains to REQ-KVD-CLI-003 / ADR-KVD-012).
pub const FLAG_UNLOCK_RECOVERY_CODE_CONSUMED: &str = "unlock_recovery_code_consumed";

/// `kvendra lock` deleted the active session blob.
pub const FLAG_UNLOCK_LOCKED_MANUAL: &str = "unlock_locked_manual";

/// `kvendra mcp serve` read the session blob but its TTL had already
/// expired.
pub const FLAG_SESSION_EXPIRED_AT_READ: &str = "session_expired_at_read";

/// The HMAC sidecar did not match the encrypted blob — either tamper or
/// a key mismatch from a different machine that copied the file.
pub const FLAG_SESSION_BLOB_TAMPERED: &str = "session_blob_tampered";

/// Blob loaded successfully but its `hostname` / `uid` / `kvendra_home`
/// do not match the current machine.
pub const FLAG_SESSION_BLOB_MACHINE_MISMATCH: &str = "session_blob_machine_mismatch";

/// REQ-KVD-CLI-42CB74 — a vault-dependent `tools/call` was blocked because
/// the MCP server is in `LockedPendingUnlock` state (booted without
/// credentials and the user has not yet run `kvendra unlock`). The
/// dispatcher returns JSON-RPC `-32002` with `help.topic =
/// vault-locked-pending-unlock` and records this flag at severity `warn`.
pub const FLAG_TOOL_CALL_BLOCKED_PENDING_UNLOCK: &str = "tool_call_blocked_pending_unlock";

// ─── Break-glass bypass grant (REQ-KVD-SKILLS-41032D / ISSUE-KVD-CLI-238B54).
//     Canonical flag strings for the `kvendra bypass` / `protect` /
//     `verify-grant` lifecycle. Defined here so dashboards and `audit verify`
//     filters can match exact bytes and the AC-AUDIT-1 trace can reconstruct
//     which ops were relaxed, when, and for how long.

/// `kvendra bypass` granted a signed grant (records scope + TTL + workspace).
pub const FLAG_BYPASS_GRANTED: &str = "bypass_granted";

/// `kvendra protect` (or `kvendra lock` auto-revoke) revoked a grant.
pub const FLAG_BYPASS_REVOKED: &str = "bypass_revoked";

/// A grant was found expired at verification time (TTL elapsed).
pub const FLAG_BYPASS_EXPIRED: &str = "bypass_expired";

/// A valid in-scope grant relaxed an op at `verify-grant` time (the hook
/// allowed an otherwise-blocked op).
pub const FLAG_BYPASS_USED: &str = "bypass_used";

/// A grant failed signature verification — tamper or a foreign/rotated key.
pub const FLAG_BYPASS_SIG_INVALID: &str = "bypass_sig_invalid";

/// Status field of an audit row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Started,
    Ok,
    Error,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Started => "started",
            Status::Ok => "ok",
            Status::Error => "error",
        }
    }
}

/// Severity level — info | warn | error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Error,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::Error => "error",
        }
    }
}

/// Logical audit event payload (pre-HMAC).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts_unix_ms: i64,
    pub profile_id: String,
    pub primitive: String,
    pub action: String,
    pub args_hash_hex: String,
    pub status: Status,
    pub severity: Severity,
    /// Optional comma-separated flags (e.g. "unsafe_escape_hatch").
    pub flags: String,
    /// ULID returned by the remote broker (`tokens:issue` audit_id field).
    /// `None` for rows generated by `LocalVaultResolver` and for every row
    /// that pre-dates the v2 migration (REQ-KVD-CLI-010).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_audit_id: Option<String>,
}

pub use writer::AuditWriter;
