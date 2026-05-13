//! HKDF sub-key derivation + AES-256-GCM single-shot encrypt/decrypt.

use crate::error::{KvendraError, KvendraResult};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Derive the 32-byte backup cipher sub-key from the unlocked session key.
///
/// `vault_key` is the raw 32-byte master key (held by the unlocked vault).
/// This function does NOT see the master password — only the derived session
/// key, satisfying the zero-knowledge invariant (server never sees either).
pub fn derive_backup_key(vault_key: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, vault_key);
    let mut okm = [0u8; 32];
    hk.expand(super::BACKUP_HKDF_INFO, &mut okm)
        .expect("HKDF expand to 32 bytes always succeeds");
    okm
}

/// AES-256-GCM encrypt — output is `[nonce(12) || ciphertext || tag(16)]`.
pub fn encrypt_bundle(key: &[u8; 32], plaintext: &[u8]) -> KvendraResult<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: b"kvendra-vault-backup/v1",
            },
        )
        .map_err(|e| KvendraError::Vault(format!("backup encrypt: {e}")))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// AES-256-GCM decrypt — input is `[nonce(12) || ciphertext || tag(16)]`.
pub fn decrypt_bundle(key: &[u8; 32], ciphertext_with_nonce: &[u8]) -> KvendraResult<Vec<u8>> {
    if ciphertext_with_nonce.len() < NONCE_LEN + TAG_LEN {
        return Err(KvendraError::Vault("backup ciphertext too short".into()));
    }
    let (nonce_bytes, rest) = ciphertext_with_nonce.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: rest,
                aad: b"kvendra-vault-backup/v1",
            },
        )
        .map_err(|_| KvendraError::Vault("WrongMasterPassword: backup decrypt failed".into()))
}

/// SHA-256 hex digest of a byte slice — used as pre-encryption checksum.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic() {
        let k = [7u8; 32];
        let a = derive_backup_key(&k);
        let b = derive_backup_key(&k);
        assert_eq!(a, b);
    }

    #[test]
    fn derive_differs_per_vault_key() {
        let a = derive_backup_key(&[7u8; 32]);
        let b = derive_backup_key(&[8u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_differs_from_audit_subkey() {
        // The backup sub-key MUST differ from the audit-hmac sub-key per
        // domain separation invariants (REQ-KVD-005 threat model).
        let vk = [42u8; 32];
        let backup = derive_backup_key(&vk);
        let hk = Hkdf::<Sha256>::new(None, &vk);
        let mut audit = [0u8; 32];
        hk.expand(b"kvendra/audit-hmac/v1", &mut audit).unwrap();
        assert_ne!(backup, audit);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_backup_key(&[1u8; 32]);
        let pt = b"hello kvendra backup world";
        let ct = encrypt_bundle(&key, pt).expect("encrypt");
        let recovered = decrypt_bundle(&key, &ct).expect("decrypt");
        assert_eq!(pt.to_vec(), recovered);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key_a = derive_backup_key(&[1u8; 32]);
        let key_b = derive_backup_key(&[2u8; 32]);
        let ct = encrypt_bundle(&key_a, b"secret stuff").unwrap();
        let result = decrypt_bundle(&key_b, &ct);
        assert!(result.is_err(), "decrypt must fail with wrong key");
    }

    #[test]
    fn nonce_differs_each_call() {
        let key = derive_backup_key(&[3u8; 32]);
        let a = encrypt_bundle(&key, b"same plaintext").unwrap();
        let b = encrypt_bundle(&key, b"same plaintext").unwrap();
        // First 12 bytes are the nonce — must differ for AES-GCM safety.
        assert_ne!(&a[..NONCE_LEN], &b[..NONCE_LEN]);
    }

    #[test]
    fn sha256_hex_known_vector() {
        // Echo "abc" via SHA-256 → ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let h = sha256_hex(b"abc");
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
