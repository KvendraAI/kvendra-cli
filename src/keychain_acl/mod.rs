//! Cross-platform OS keychain reads/writes gated by user presence
//! (REQ-KVD-005 / ISSUE-KVD-CLI-017).
//!
//! macOS: `security-framework` with `SecAccessControlCreateWithFlags(.userPresence)`.
//! TouchID popup, or — when biometric hardware is absent — the OS modal
//! password prompt. Either way, the prompt is OS-mediated and never touches
//! `/dev/tty`.
//!
//! Windows / Linux: explicit reject in this release. We do not fall back to
//! `keyring` base without an ACL because that would create a false sense of
//! security: the keychain item would appear "biometric-protected" while
//! actually being readable by any L1 process. Owner decision (2026-05-07):
//! ship macOS-only first. Cross-platform hardening lands in a future ROAD.
//!
//! Workaround for non-macOS: keep using the legacy `KVENDRA_MCP_PASSWORD`
//! env var path until cross-platform support exists.

use thiserror::Error;

/// Service name used for every kvendra keychain item.
pub const KEYCHAIN_SERVICE: &str = "kvendra";

/// Errors raised by the user-presence-gated keychain abstraction.
#[derive(Debug, Error)]
pub enum BiometricError {
    /// User dismissed the TouchID / password popup.
    #[error("user rejected biometric/presence prompt")]
    Rejected,
    /// Platform / backend does not support presence-gated keychain ACL.
    #[error("biometric/keychain ACL not available on this platform: {0}")]
    Unavailable(String),
    /// No item with the given label found under `KEYCHAIN_SERVICE`.
    #[error("keychain item not found (label={0})")]
    NotFound(String),
    /// Other backend / OS error.
    #[error("keychain backend error: {0}")]
    Backend(String),
}

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{
    delete, read_with_user_presence, request_user_presence_only, save_with_user_presence,
};

#[cfg(not(target_os = "macos"))]
mod other;
#[cfg(not(target_os = "macos"))]
pub use other::{
    delete, read_with_user_presence, request_user_presence_only, save_with_user_presence,
};

/// Convenience: pre-canned message recommending the legacy env-var
/// workaround on platforms where ACL is not yet supported.
pub fn unavailable_user_message() -> String {
    String::from(
        "Biometric/presence ACL is macOS-only in this release. \
         Workaround for Windows/Linux: continue using the `KVENDRA_MCP_PASSWORD` env var \
         in your MCP client config. Cross-platform support is tracked in ROAD-KVD-008.",
    )
}
