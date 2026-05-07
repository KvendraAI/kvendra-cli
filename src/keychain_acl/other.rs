//! Windows / Linux fallback — explicit reject (REQ-KVD-005 AC-USE-KEYCHAIN-4).
//!
//! See [`super::unavailable_user_message`] for guidance to the user.

use super::{BiometricError, unavailable_user_message};

pub fn save_with_user_presence(_label: &str, _secret: &str) -> Result<(), BiometricError> {
    Err(BiometricError::Unavailable(unavailable_user_message()))
}

pub fn read_with_user_presence(_label: &str) -> Result<String, BiometricError> {
    Err(BiometricError::Unavailable(unavailable_user_message()))
}

pub fn delete(_label: &str) -> Result<(), BiometricError> {
    Err(BiometricError::Unavailable(unavailable_user_message()))
}
