//! Windows / Linux fallback — no presence-gated items (REQ-KVD-005
//! AC-USE-KEYCHAIN-4); only legacy plain `keyring` entries can be checked
//! and removed.
//!
//! See [`super::unavailable_user_message`] for guidance to the user.

use super::{BiometricError, unavailable_user_message};

pub fn save_with_user_presence(_label: &str, _secret: &str) -> Result<(), BiometricError> {
    Err(BiometricError::Unavailable(unavailable_user_message()))
}

pub fn read_with_user_presence(_label: &str) -> Result<String, BiometricError> {
    Err(BiometricError::Unavailable(unavailable_user_message()))
}

/// Remove an entry written by alpha.3 or earlier with the plain `keyring`
/// crate (`service = "kvendra"`, `account = label`, no ACL — 4ae7d36). There
/// is no presence-gated item on this platform, but such a legacy entry may
/// hold a master password and must be removable (`config mcp-password
/// disable`, `recover`, `passwd`).
pub fn delete(label: &str) -> Result<(), BiometricError> {
    let entry = keyring::Entry::new(super::KEYCHAIN_SERVICE, label)
        .map_err(|e| BiometricError::Backend(e.to_string()))?;
    super::delete_from_keyring(entry.delete_credential(), label)
}

pub fn request_user_presence_only(_reason: &str) -> Result<(), BiometricError> {
    Err(BiometricError::Unavailable(unavailable_user_message()))
}

/// Whether a legacy `keyring` entry (same service / account as alpha.3)
/// exists. `keyring` has no attributes-only query, so this reads the value
/// (into a zeroizing buffer, dropped at once) — never returned or logged.
pub fn exists(label: &str) -> Result<bool, BiometricError> {
    let entry = keyring::Entry::new(super::KEYCHAIN_SERVICE, label)
        .map_err(|e| BiometricError::Backend(e.to_string()))?;
    super::exists_from_keyring(entry.get_password().map(zeroize::Zeroizing::new))
}
