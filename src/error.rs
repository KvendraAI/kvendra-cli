//! Unified error type for the kvendra CLI.
//!
//! `KvendraError` aggregates errors across all modules. Its `Display`
//! implementation is sanitized: it must never include plaintext credentials,
//! derived keys, or absolute filesystem paths that reveal user layout.

use thiserror::Error;

/// Unified error type for kvendra.
#[derive(Debug, Error)]
pub enum KvendraError {
    #[error("vault error: {0}")]
    Vault(String),

    #[error("invalid master password")]
    InvalidMasterPassword,

    #[error("vault is locked")]
    VaultLocked,

    #[error("recovery failed")]
    RecoveryFailed,

    #[error("recovery code does not match any known slot")]
    RecoveryCodeInvalid,

    #[error("recovery code at slot {slot} already consumed for {used_for} at {used_at}")]
    RecoveryCodeAlreadyUsed {
        slot: usize,
        used_for: String,
        used_at: String,
    },

    #[error("'rebind-home' requires interactive TTY confirmation")]
    RebindRequiresTty,

    #[error("rebind confirmation mismatch — typed path does not canonicalize to target")]
    RebindConfirmationMismatch,

    #[error("'config recovery-codes regenerate' requires interactive TTY confirmation")]
    RegenerateRequiresTty,

    #[error(
        "regenerate confirmation mismatch — typed string must equal 'REGENERATE-RECOVERY-CODES' exactly"
    )]
    RegenerateAcknowledgeMismatch,

    #[error("audit log error: {0}")]
    Audit(String),

    #[error("audit hmac chain broken at row {0}")]
    AuditChainBroken(i64),

    #[error("allowlist parse error: {0}")]
    AllowlistParse(String),

    #[error("allowlist violation: {0}")]
    AllowlistViolation(String),

    #[error(
        "allowlist for profile '{0}' has been tampered — re-run `kvendra secret set-allowlist`"
    )]
    AllowlistTampered(String),

    #[error("profile not found")]
    ProfileNotFound,

    #[error("profile expired")]
    ProfileExpired,

    #[error("primitive '{0}' not implemented in this build")]
    PrimitiveNotImplemented(String),

    #[error("primitive '{primitive}' operation '{operation}' failed")]
    PrimitiveFailed {
        primitive: String,
        operation: String,
    },

    #[error("mcp protocol error: {0}")]
    McpProtocol(String),

    #[error("invalid arguments: {0}")]
    InvalidArgs(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("io error")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("unsafe escape hatch not enabled for this profile")]
    UnsafeNotEnabled,

    #[error("unsafe escape hatch quota exceeded ({used}/{max})")]
    UnsafeQuotaExceeded { used: u32, max: u32 },

    #[error("detection blocked: {0}")]
    DetectionBlocked(String),

    #[error("keychain error: {0}")]
    Keychain(String),

    #[error("biometric/presence prompt rejected by user")]
    BiometricRejected,

    #[error("biometric/keychain ACL not available on this platform: {0}")]
    BiometricUnavailable(String),

    #[error("http error: {0}")]
    Http(String),

    #[error("tui error: {0}")]
    Tui(String),

    // ─── M1 Sprint 4 — workspace mode (REQ-KVD-CLI-004/008/009/010) ───
    /// Server signalled the workspace membership has been revoked or the
    /// workspace itself has been deleted. The CLI must invalidate the cached
    /// session and prompt the user to re-login or contact an admin.
    #[error("workspace membership revoked or workspace deleted")]
    WorkspaceMembershipRevoked,

    /// Cached JWT (or its refresh token) is no longer accepted by the IdP.
    /// User must run `kvendra login --workspace <id>` again.
    #[error("workspace session expired — run `kvendra login --workspace <id>` to reconnect")]
    WorkspaceSessionExpired,

    /// Broker returned 429 Too Many Requests. `retry_after_seconds` carries
    /// the server-provided hint when available, 0 otherwise.
    #[error("rate limited by broker; retry after {0} seconds")]
    RateLimited(u64),

    /// Connect/IO error talking to the broker (timeout, DNS, TLS handshake).
    /// Distinct from HTTP 5xx replies which surface as `Http`.
    #[error("broker unreachable: {0}")]
    BrokerUnreachable(String),

    /// All loopback ports in the OIDC callback range 54321..54330 are taken;
    /// PKCE login cannot proceed.
    #[error("OIDC callback port range 54321..54330 is fully occupied")]
    OidcCallbackPortRangeExhausted,

    /// `state` parameter returned by the IdP did not match the one generated
    /// locally for this PKCE flow — possible CSRF or replay.
    #[error("OIDC state mismatch — possible CSRF attack")]
    OidcStateMismatch,

    /// `.well-known/openid-configuration` fetch / parse failure.
    #[error("OIDC discovery failed: {0}")]
    OidcDiscoveryFailed(String),

    /// Generic OIDC protocol-level error during the login dance (token
    /// exchange, callback parsing, browser-open). Carries a sanitized
    /// human-readable message.
    #[error("OIDC flow failed: {0}")]
    OidcFlow(String),

    /// `audit_events` HMAC chain verification post-migration failed at a
    /// specific row. The migration restores the pre-migration backup before
    /// returning this error.
    #[error("audit migration v{from}->v{to} HMAC mismatch at row {row_id} — backup restored")]
    AuditMigrationHmacMismatch { from: u32, to: u32, row_id: i64 },

    /// Audit migration aborted because of an unrecoverable IO / schema error.
    /// The backup written before the migration is left intact.
    #[error("audit migration aborted: {0}")]
    AuditMigrationAborted(String),

    /// Caller lacks the required role (owner / admin) for the operation.
    /// `0` is the resource the caller tried to act on (e.g. profile id).
    #[error("insufficient privilege for '{0}' (owner/admin required)")]
    InsufficientPrivilege(String),

    /// Multiple `~/.kvendra/sessions/*.token` files are valid; the CLI cannot
    /// pick a default. The user must set `KVENDRA_ACTIVE_WORKSPACE`.
    #[error("multiple workspace sessions active — set KVENDRA_ACTIVE_WORKSPACE=<id>")]
    MultipleWorkspaceSessionsAmbiguous,

    /// Background allowlist sync has not succeeded in over 24h; the CLI
    /// refuses to consume the cached YAMLs until a manual / scheduled refresh
    /// recovers.
    #[error(
        "allowlist cache is stale (last successful sync >24h ago) — run `kvendra workspace allowlist refresh`"
    )]
    AllowlistCacheStale,

    /// The server (broker) rejected an op the local allowlist would accept.
    /// Typical when the local cache is out of date vs server-side policy.
    #[error("server denies this operation despite local allowlist — possible stale cache")]
    AllowlistDeniedByBroker,

    /// I/O error during session token file persistence (mode 0600 + flock).
    #[error("session token store error: {0}")]
    SessionStore(String),

    #[error("internal error")]
    Internal,
}

impl From<reqwest::Error> for KvendraError {
    fn from(err: reqwest::Error) -> Self {
        KvendraError::Http(err.to_string())
    }
}

impl From<serde_json::Error> for KvendraError {
    fn from(err: serde_json::Error) -> Self {
        KvendraError::Serialization(err.to_string())
    }
}

impl From<serde_yaml_ng::Error> for KvendraError {
    fn from(err: serde_yaml_ng::Error) -> Self {
        KvendraError::Serialization(err.to_string())
    }
}

impl From<rusqlite::Error> for KvendraError {
    fn from(err: rusqlite::Error) -> Self {
        KvendraError::Audit(err.to_string())
    }
}

/// Convenience alias.
pub type KvendraResult<T> = std::result::Result<T, KvendraError>;
