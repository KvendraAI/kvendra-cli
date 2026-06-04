//! Canonical audit `error_code` taxonomy (ISSUE-KVD-CLI-6C43AA).
//!
//! When a primitive fails we now persist two diagnostic columns on the audit
//! row: a closed-vocabulary `error_code` (this enum) and a free-form,
//! **sanitized** `error_message`. The code is what forensic tooling filters on
//! (`kvendra audit --json | jq 'select(.error_code=="ALLOWLIST_VIOLATION")'`);
//! the message carries the human-readable detail.
//!
//! The vocabulary is intentionally *closed*: each variant maps to a real
//! failure class the dispatcher already distinguishes. New failure classes get
//! a new variant rather than free-text in the code field, so dashboards stay
//! aggregatable.
//!
//! Classification is centralized in [`AuditErrorCode::classify`], which maps a
//! [`KvendraError`] to its canonical code. The mapping is total — anything we
//! do not recognize collapses to [`AuditErrorCode::RuntimeError`].

use crate::error::KvendraError;

/// Closed vocabulary of audit error codes. Serialized to the
/// `audit_events.error_code` TEXT column as the SCREAMING_SNAKE_CASE string
/// returned by [`AuditErrorCode::as_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditErrorCode {
    /// The profile allowlist rejected the requested op/args.
    AllowlistViolation,
    /// The on-disk allowlist YAML failed its HMAC check (tamper).
    AllowlistTampered,
    /// The allowlist cache has been stale (>24h without sync) — refused.
    AllowlistStale,
    /// No profile metadata found for the requested profile_id.
    ProfileNotFound,
    /// The profile's validity window has elapsed.
    ProfileExpired,
    /// A vault-gated op was attempted while the vault is locked.
    VaultLocked,
    /// The `kvendra.unsafe.raw_token` escape hatch is not enabled / quota hit.
    UnsafeNotEnabled,
    /// The inbound detection layer blocked the call (secret in args).
    DetectionBlocked,
    /// The approval layer (TTY / biometric / policy) denied dispatch.
    ApprovalDenied,
    /// A `git`/`github` push over an HTTPS remote was rejected because the
    /// primitive only supports the SSH remote path.
    HttpsRemoteNotSupported,
    /// The remote rejected a `git push` (non-fast-forward, protected branch…).
    RemoteRejectedPush,
    /// Network-layer failure reaching a remote (broker, registry, host).
    NetworkError,
    /// The broker rate-limited the call (HTTP 429).
    RateLimited,
    /// The caller's MCP arguments did not match the primitive's schema.
    InvalidArgs,
    /// The requested primitive is not built into this binary.
    PrimitiveNotImplemented,
    /// Catch-all for any failure we do not classify more precisely.
    RuntimeError,
}

impl AuditErrorCode {
    /// The canonical on-disk / on-wire string.
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditErrorCode::AllowlistViolation => "ALLOWLIST_VIOLATION",
            AuditErrorCode::AllowlistTampered => "ALLOWLIST_TAMPERED",
            AuditErrorCode::AllowlistStale => "ALLOWLIST_STALE",
            AuditErrorCode::ProfileNotFound => "PROFILE_NOT_FOUND",
            AuditErrorCode::ProfileExpired => "PROFILE_EXPIRED",
            AuditErrorCode::VaultLocked => "VAULT_LOCKED",
            AuditErrorCode::UnsafeNotEnabled => "UNSAFE_NOT_ENABLED",
            AuditErrorCode::DetectionBlocked => "DETECTION_BLOCKED",
            AuditErrorCode::ApprovalDenied => "APPROVAL_DENIED",
            AuditErrorCode::HttpsRemoteNotSupported => "HTTPS_REMOTE_NOT_SUPPORTED",
            AuditErrorCode::RemoteRejectedPush => "REMOTE_REJECTED_PUSH",
            AuditErrorCode::NetworkError => "NETWORK_ERROR",
            AuditErrorCode::RateLimited => "RATE_LIMITED",
            AuditErrorCode::InvalidArgs => "INVALID_ARGS",
            AuditErrorCode::PrimitiveNotImplemented => "PRIMITIVE_NOT_IMPLEMENTED",
            AuditErrorCode::RuntimeError => "RUNTIME_ERROR",
        }
    }

    /// Map a [`KvendraError`] to its canonical audit code.
    ///
    /// Total mapping — unrecognized variants fall through to
    /// [`AuditErrorCode::RuntimeError`]. `HTTPS_REMOTE_NOT_SUPPORTED` and
    /// `REMOTE_REJECTED_PUSH` are derived from the (sanitized) message text of
    /// `Http`/`PrimitiveFailed` errors because the git primitive surfaces them
    /// as those variants rather than dedicated enum arms.
    pub fn classify(err: &KvendraError) -> AuditErrorCode {
        match err {
            KvendraError::AllowlistViolation(_) => AuditErrorCode::AllowlistViolation,
            KvendraError::AllowlistParse(_) => AuditErrorCode::AllowlistViolation,
            KvendraError::AllowlistTampered(_) => AuditErrorCode::AllowlistTampered,
            KvendraError::AllowlistCacheStale | KvendraError::AllowlistDeniedByBroker => {
                AuditErrorCode::AllowlistStale
            }
            KvendraError::ProfileNotFound => AuditErrorCode::ProfileNotFound,
            KvendraError::ProfileExpired => AuditErrorCode::ProfileExpired,
            KvendraError::VaultLocked => AuditErrorCode::VaultLocked,
            KvendraError::UnsafeNotEnabled | KvendraError::UnsafeQuotaExceeded { .. } => {
                AuditErrorCode::UnsafeNotEnabled
            }
            KvendraError::DetectionBlocked(_) => AuditErrorCode::DetectionBlocked,
            KvendraError::BiometricRejected => AuditErrorCode::ApprovalDenied,
            KvendraError::RateLimited(_) => AuditErrorCode::RateLimited,
            KvendraError::BrokerUnreachable(_) => AuditErrorCode::NetworkError,
            KvendraError::InvalidArgs(_) => AuditErrorCode::InvalidArgs,
            KvendraError::PrimitiveNotImplemented(_) => AuditErrorCode::PrimitiveNotImplemented,
            KvendraError::Http(msg) | KvendraError::PrimitiveFailed { operation: msg, .. } => {
                classify_message(msg)
            }
            _ => AuditErrorCode::RuntimeError,
        }
    }
}

/// Heuristic sub-classification of `Http` / `PrimitiveFailed` error text.
/// These two variants are the catch-all the git/github/http primitives use,
/// so we sniff well-known phrases to recover the precise forensic code.
fn classify_message(msg: &str) -> AuditErrorCode {
    let lower = msg.to_lowercase();
    if lower.contains("https remote") || lower.contains("https is not supported") {
        AuditErrorCode::HttpsRemoteNotSupported
    } else if lower.contains("rejected")
        || lower.contains("non-fast-forward")
        || lower.contains("failed to push")
    {
        AuditErrorCode::RemoteRejectedPush
    } else if lower.contains("timed out")
        || lower.contains("connection")
        || lower.contains("dns")
        || lower.contains("could not resolve")
        || lower.contains("network")
    {
        AuditErrorCode::NetworkError
    } else {
        AuditErrorCode::RuntimeError
    }
}

/// Build the sanitized `(error_code, error_message)` pair for an audit row from
/// a [`KvendraError`]. The message is scrubbed through the canonical
/// [`crate::detection::sanitize_output`] secret redactor — the SAME pass used
/// for outbound MCP error payloads — so no PAT / master password / session
/// token can ride into the audit DB. The message is additionally truncated to
/// keep audit rows bounded.
pub fn from_error(err: &KvendraError) -> (AuditErrorCode, String) {
    let code = AuditErrorCode::classify(err);
    let msg = crate::detection::sanitize_output(&err.to_string());
    (code, truncate(&msg))
}

/// Maximum stored error_message length (chars). Long primitive stderr dumps
/// are clipped so a single row cannot bloat the audit DB.
const MAX_ERROR_MESSAGE_LEN: usize = 512;

fn truncate(s: &str) -> String {
    if s.chars().count() <= MAX_ERROR_MESSAGE_LEN {
        return s.to_string();
    }
    let mut out: String = s.chars().take(MAX_ERROR_MESSAGE_LEN - 1).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_violation_maps() {
        let e = KvendraError::AllowlistViolation("ref 'HEAD' not allowed".into());
        let (code, msg) = from_error(&e);
        assert_eq!(code.as_str(), "ALLOWLIST_VIOLATION");
        assert!(msg.contains("ref 'HEAD' not allowed"));
    }

    #[test]
    fn unknown_falls_back_to_runtime() {
        let e = KvendraError::Internal;
        assert_eq!(AuditErrorCode::classify(&e), AuditErrorCode::RuntimeError);
    }

    #[test]
    fn https_remote_sniffed_from_message() {
        let e = KvendraError::Http("push over HTTPS remote is not supported".into());
        assert_eq!(
            AuditErrorCode::classify(&e),
            AuditErrorCode::HttpsRemoteNotSupported
        );
    }

    #[test]
    fn rejected_push_sniffed() {
        let e = KvendraError::PrimitiveFailed {
            primitive: "kvendra.git".into(),
            operation: "remote rejected: non-fast-forward".into(),
        };
        assert_eq!(
            AuditErrorCode::classify(&e),
            AuditErrorCode::RemoteRejectedPush
        );
    }

    #[test]
    fn message_is_sanitized() {
        // A leaked GitHub token in the error string must be redacted before it
        // is stored in the audit DB. Use a high-entropy token so it clears the
        // detector's Shannon-entropy false-positive filter (an all-`A` token is
        // intentionally treated as lorem-ipsum and left alone).
        let leaked = "ghp_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaaaa";
        let e = KvendraError::Http(format!("auth failed with token {leaked}"));
        let (_code, msg) = from_error(&e);
        assert!(
            !msg.contains(leaked),
            "raw token leaked into audit msg: {msg}"
        );
    }

    #[test]
    fn long_message_is_truncated() {
        let big = "x".repeat(2000);
        let e = KvendraError::Http(big);
        let (_c, msg) = from_error(&e);
        assert!(msg.chars().count() <= MAX_ERROR_MESSAGE_LEN);
    }

    #[test]
    fn vault_locked_maps() {
        assert_eq!(
            AuditErrorCode::classify(&KvendraError::VaultLocked),
            AuditErrorCode::VaultLocked
        );
    }
}
