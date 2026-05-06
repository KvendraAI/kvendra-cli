//! AES-256-GCM authenticated encryption with 96-bit random nonces.
//!
//! Each `seal()` generates a fresh random nonce. The 16-byte authentication
//! tag is appended to the ciphertext (standard `aes-gcm` API).

use crate::error::{KvendraError, KvendraResult};
use aes_gcm::aead::{Aead, KeyInit};
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
}
