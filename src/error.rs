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

impl From<serde_yml::Error> for KvendraError {
    fn from(err: serde_yml::Error) -> Self {
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
