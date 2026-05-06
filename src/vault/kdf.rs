//! KDF — Argon2id password-based key derivation.
//!
//! Cost params target ≥1s on modern hardware (REQ-KVD-002 AC-VAULT-4):
//! `m_cost = 64 MiB`, `t_cost = 3`, `p_cost = 1`. The derived key is 32 bytes
//! (AES-256-GCM key length).

use crate::error::{KvendraError, KvendraResult};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Argon2id parameters serialized into each blob header.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost (KiB).
    pub m_cost_kib: u32,
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Parallelism degree.
    pub p_cost: u32,
    /// Salt (random per blob).
    pub salt: Vec<u8>,
}

impl KdfParams {
    /// Default high-cost params targeting ≥1s on modern hardware.
    pub fn high_cost(salt: Vec<u8>) -> Self {
        Self {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
            salt,
        }
    }
}

/// 32-byte derived key — wrapped in `ZeroizeOnDrop`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey(pub [u8; 32]);

impl DerivedKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Derive a 32-byte key from `password` and `params`.
pub fn derive(password: &[u8], params: &KdfParams) -> KvendraResult<DerivedKey> {
    let p = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| KvendraError::Vault(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password, &params.salt, &mut out)
        .map_err(|e| KvendraError::Vault(format!("argon2 derive: {e}")))?;
    Ok(DerivedKey(out))
}

/// Generate a fresh random salt (16 bytes is standard).
pub fn random_salt() -> Vec<u8> {
    use rand::RngCore;
    let mut s = vec![0u8; 16];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_params(salt: Vec<u8>) -> KdfParams {
        // Test-only fast params (still real argon2id).
        KdfParams {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt,
        }
    }

    #[test]
    fn derive_is_deterministic_with_same_params() {
        let salt = vec![1u8; 16];
        let p = fast_params(salt);
        let k1 = derive(b"hunter2", &p).unwrap();
        let k2 = derive(b"hunter2", &p).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_differs_with_different_salt() {
        let p1 = fast_params(vec![1u8; 16]);
        let p2 = fast_params(vec![2u8; 16]);
        let k1 = derive(b"hunter2", &p1).unwrap();
        let k2 = derive(b"hunter2", &p2).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_differs_with_different_password() {
        let p = fast_params(vec![1u8; 16]);
        let k1 = derive(b"hunter2", &p).unwrap();
        let k2 = derive(b"correct horse battery staple", &p).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }
}
