//! Session state: the derived master key while the vault is unlocked.
//!
//! Per ADR-KVD-012 the key is RAM-only by default and zeroized on Drop /
//! `lock()`. An idle timeout (default 30 min, configurable) is tracked.
//!
//! Per ADR-KVD-010 + ADR-KVD-012 the audit-HMAC sub-key is derived from
//! the session key via HKDF-SHA256 (info `"kvendra/audit-hmac/v1"`). It
//! lives only while the vault is unlocked.

use crate::error::{KvendraError, KvendraResult};
use crate::vault::kdf::DerivedKey;
use ::hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

/// HKDF info string for the audit-HMAC sub-key (per ADR-KVD-010 + ADR-KVD-012).
pub const HKDF_INFO_AUDIT_HMAC: &[u8] = b"kvendra/audit-hmac/v1";

/// 32-byte sub-key wrapper, zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedSubKey(pub [u8; 32]);

impl DerivedSubKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

/// HKDF-SHA256 expand (single-step, salt-less) — enough for our 32-byte sub-keys.
///
/// See RFC 5869 § 2.3. We use the master key directly as PRK (it's already
/// 32 bytes of high-entropy material from Argon2id), so this is equivalent
/// to `HKDF-Expand(PRK=key, info, L=32)`.
pub fn hkdf_expand(key: &[u8; 32], info: &[u8]) -> DerivedSubKey {
    // T(1) = HMAC(PRK, info || 0x01)
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary key length");
    mac.update(info);
    mac.update(&[0x01]);
    let t1 = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&t1);
    DerivedSubKey(out)
}

/// In-memory session key with tracking metadata.
pub struct SessionKey {
    inner: Inner,
    audit_hmac_key: DerivedSubKey,
    idle_timeout: Duration,
    last_used: Instant,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Inner {
    key: [u8; 32],
}

impl SessionKey {
    pub fn new(derived: DerivedKey, idle_timeout_minutes: u32) -> Self {
        let audit_hmac_key = hkdf_expand(derived.as_bytes(), HKDF_INFO_AUDIT_HMAC);
        Self {
            inner: Inner {
                key: *derived.as_bytes(),
            },
            audit_hmac_key,
            idle_timeout: Duration::from_secs(u64::from(idle_timeout_minutes) * 60),
            last_used: Instant::now(),
        }
    }

    /// Access the raw key bytes, refreshing the idle timer.
    pub fn use_key(&mut self) -> KvendraResult<&[u8; 32]> {
        if self.is_expired() {
            return Err(KvendraError::VaultLocked);
        }
        self.last_used = Instant::now();
        Ok(&self.inner.key)
    }

    /// Read access without refreshing the idle timer (for verifications).
    pub fn peek_key(&self) -> KvendraResult<&[u8; 32]> {
        if self.is_expired() {
            return Err(KvendraError::VaultLocked);
        }
        Ok(&self.inner.key)
    }

    /// Get the derived audit-HMAC sub-key (per ADR-KVD-010 + ADR-KVD-012).
    pub fn audit_hmac_key(&self) -> KvendraResult<&DerivedSubKey> {
        if self.is_expired() {
            return Err(KvendraError::VaultLocked);
        }
        Ok(&self.audit_hmac_key)
    }

    pub fn is_expired(&self) -> bool {
        self.last_used.elapsed() >= self.idle_timeout
    }

    /// Explicit zeroize, equivalent to `Drop`.
    pub fn lock(mut self) {
        self.inner.key.zeroize();
    }
}

/// State shared by the running process: locked vs unlocked.
pub enum VaultState {
    Locked,
    Unlocked(SessionKey),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_is_deterministic() {
        let k = [7u8; 32];
        let a = hkdf_expand(&k, HKDF_INFO_AUDIT_HMAC);
        let b = hkdf_expand(&k, HKDF_INFO_AUDIT_HMAC);
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn hkdf_differs_with_different_info() {
        let k = [7u8; 32];
        let a = hkdf_expand(&k, b"info-a");
        let b = hkdf_expand(&k, b"info-b");
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn hkdf_differs_with_different_key() {
        let a = hkdf_expand(&[7u8; 32], HKDF_INFO_AUDIT_HMAC);
        let b = hkdf_expand(&[8u8; 32], HKDF_INFO_AUDIT_HMAC);
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}
