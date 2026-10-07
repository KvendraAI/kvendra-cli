//! AES-256-GCM authenticated encryption with 96-bit random nonces.
//!
//! Each `seal()` generates a fresh random nonce. The 16-byte authentication
//! tag is appended to the ciphertext (standard `aes-gcm` API).

use crate::error::{KvendraError, KvendraResult};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;

/// 96-bit nonce size for AES-GCM.
pub const NONCE_LEN: usize = 12;

/// Generate a fresh random 96-bit nonce.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut n);
    n
}

/// AES-256-GCM seal: returns ciphertext (with tag appended).
pub fn seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> KvendraResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| KvendraError::Vault(format!("aes-gcm key: {e}")))?;
    let nonce_obj = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce_obj, plaintext)
        .map_err(|_| KvendraError::Vault("encryption failed".into()))
}

/// AES-256-GCM open: verifies tag and returns plaintext.
pub fn open(key: &[u8; 32], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> KvendraResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| KvendraError::Vault(format!("aes-gcm key: {e}")))?;
    let nonce_obj = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce_obj, ciphertext)
        .map_err(|_| KvendraError::InvalidMasterPassword)
}

/// AES-256-GCM seal with associated data (REQ-KVD-11F906 D1). Used by the
/// local-vars blob, whose AAD binds the ciphertext to its format so a secret
/// blob and a vars blob are never interchangeable (AC-LVR-5). `seal` / `open`
/// stay AAD-less for the existing secret blobs.
pub fn seal_aad(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> KvendraResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| KvendraError::Vault(format!("aes-gcm key: {e}")))?;
    let nonce_obj = Nonce::from_slice(nonce);
    cipher
        .encrypt(
            nonce_obj,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| KvendraError::Vault("encryption failed".into()))
}

/// AES-256-GCM open with associated data. A wrong key, a wrong AAD or a
/// tampered ciphertext all fail with a `Vault` error distinct from
/// `InvalidMasterPassword` (the vars blob is never a password check).
pub fn open_aad(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> KvendraResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| KvendraError::Vault(format!("aes-gcm key: {e}")))?;
    let nonce_obj = Nonce::from_slice(nonce);
    cipher
        .decrypt(
            nonce_obj,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| KvendraError::Vault("local vars blob: decrypt failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_succeeds() {
        let key = [7u8; 32];
        let nonce = random_nonce();
        let plaintext = b"hello kvendra";
        let ct = seal(&key, &nonce, plaintext).unwrap();
        let pt = open(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn tampering_is_detected() {
        let key = [7u8; 32];
        let nonce = random_nonce();
        let plaintext = b"hello kvendra";
        let mut ct = seal(&key, &nonce, plaintext).unwrap();
        // Flip a byte in the ciphertext.
        ct[0] ^= 0xFF;
        let result = open(&key, &nonce, &ct);
        assert!(result.is_err(), "tampering should be detected");
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = [7u8; 32];
        let key2 = [8u8; 32];
        let nonce = random_nonce();
        let ct = seal(&key1, &nonce, b"top secret").unwrap();
        assert!(open(&key2, &nonce, &ct).is_err());
    }

    /// REQ-KVD-11F906 D1 — AAD round-trip, and the AAD is binding: a wrong
    /// AAD, or opening an AAD ciphertext with the AAD-less `open`, fails.
    #[test]
    fn aad_round_trip_and_binding() {
        let key = [9u8; 32];
        let nonce = random_nonce();
        let ct = seal_aad(&key, &nonce, b"aad-1", b"payload").unwrap();
        assert_eq!(open_aad(&key, &nonce, b"aad-1", &ct).unwrap(), b"payload");
        assert!(open_aad(&key, &nonce, b"aad-2", &ct).is_err());
        assert!(open(&key, &nonce, &ct).is_err());
        let plain_ct = seal(&key, &nonce, b"payload").unwrap();
        assert!(open_aad(&key, &nonce, b"aad-1", &plain_ct).is_err());
    }

    #[test]
    fn open_aad_error_is_not_invalid_master_password() {
        let key = [9u8; 32];
        let nonce = random_nonce();
        let ct = seal_aad(&key, &nonce, b"a", b"p").unwrap();
        let err = open_aad(&[1u8; 32], &nonce, b"a", &ct).unwrap_err();
        assert!(matches!(err, KvendraError::Vault(_)), "{err:?}");
    }
}
