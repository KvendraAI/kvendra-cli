//! Audit log — SQLite WAL + HMAC-chain (REQ-KVD-002 Bloque 6, ADR-KVD-007).
//!
//! Public API: [`AuditEvent`], [`AuditLog`], [`AuditWriter`].

pub mod bootstrap;
pub mod error_code;
pub mod export;
pub mod hmac;
pub mod layout_commit;
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

// ─── Fail-closed enforcement hardening (ISSUE-KVD-CLI-B78ED5, external audit
//     by Salva Ferrer / avtn.es, 2026-09). Canonical flags for the boundary
//     rejections introduced by the v0.6.4 security patch. Each marks a call
//     the dispatcher refused BEFORE dispatch so the AC-AUDIT-1 trace can tell
//     these deliberate denials apart from network / parse errors.

/// A `tools/call` for a vault-dependent primitive arrived with an empty
/// `profile_id`. Pre-0.6.4 this silently skipped the allowlist AND the
/// approval layer (audit finding C1). The dispatcher now fails closed.
pub const FLAG_EMPTY_PROFILE_DENIED: &str = "empty_profile_denied";

/// A `tools/call` arrived with a `profile_id` outside the safe character set
/// `[A-Za-z0-9._-]`. The id is interpolated into vault filesystem paths
/// (`allowlists/<id>.yaml`, `secrets/<id>.blob`, `profiles/<id>.json`), so an
/// id containing `/` or `..` was a path-traversal vector. Found during the
/// v0.6.4 adversarial pass (cycle 2, beyond the external audit); the
/// dispatcher now rejects it before any path is built.
pub const FLAG_INVALID_PROFILE_DENIED: &str = "invalid_profile_denied";

/// A profile carried a secret but no allowlist YAML on disk. Pre-0.6.4 this
/// was fail-open (any op allowed — audit finding C4). The dispatcher now
/// refuses the call and points the user at `kvendra secret set-allowlist`.
pub const FLAG_MISSING_ALLOWLIST_DENIED: &str = "missing_allowlist_denied";

/// The `kvendra.unsafe.raw_token` escape hatch exceeded its per-session
/// `unsafe_max_uses_per_session` quota. Pre-0.6.4 the counter was declared
/// in the DSL but never read (audit finding H4); it is now enforced.
pub const FLAG_UNSAFE_QUOTA_EXCEEDED: &str = "unsafe_quota_exceeded";

/// A `kvendra.git` call was rejected because its URL used a dangerous
/// transport (`ext::`, option-injection via a leading `-`, or a
/// non-allowlisted scheme). Pre-0.6.4 `git clone` passed the URL through
/// unvalidated, enabling `ext::sh -c ...` RCE (audit finding H5).
pub const FLAG_GIT_URL_REJECTED: &str = "git_url_rejected";

/// A `kvendra.shell` allowlist declared a `binaries:` constraint but the
/// call payload carried no `binary` field the enforcer could check. Pre-0.6.4
/// the enforcer read the wrong key (`bin` vs `binary`) so the constraint was
/// inert (audit finding C2); it now fails closed on shape mismatch.
pub const FLAG_SHELL_BINARY_SHAPE_MISMATCH: &str = "shell_binary_shape_mismatch";

/// A `tools/call` arrived with a tool `name` (or a non-empty `operation`)
/// outside the audit-field charset (`path_id::is_safe_audit_field`). Both
/// values become MAC-bound audit columns; ISSUE-KVD-CLI-F4ED93 showed that a
/// `|` in them could re-split the legacy pipe-joined MAC input. The
/// dispatcher refuses the call before any dispatch (defence in depth next to
/// the injective v4 layout).
pub const FLAG_INVALID_TOOL_FIELD_DENIED: &str = "invalid_tool_field_denied";

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
    /// Closed-vocabulary diagnostic code for `status:error` rows
    /// (ISSUE-KVD-CLI-6C43AA). `None` for `started`/`ok` rows and for every
    /// row that pre-dates the v3 migration. Persisted as the
    /// SCREAMING_SNAKE_CASE string of [`error_code::AuditErrorCode`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Free-form, **sanitized** human-readable failure detail for
    /// `status:error` rows. Scrubbed through `crate::detection::sanitize_output`
    /// before it reaches this field — never contains plaintext secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

pub use writer::AuditWriter;
