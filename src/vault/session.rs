//! Session state: the derived master key while the vault is unlocked.
//!
//! Per ADR-KVD-012 the key is RAM-only by default and zeroized on Drop /
//! `lock()`. An idle timeout (default 30 min, configurable) is tracked.

use crate::error::{KvendraError, KvendraResult};
use crate::vault::kdf::DerivedKey;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// In-memory session key with tracking metadata.
pub struct SessionKey {
    inner: Inner,
    idle_timeout: Duration,
    last_used: Instant,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Inner {
    key: [u8; 32],
}

impl SessionKey {
    pub fn new(derived: DerivedKey, idle_timeout_minutes: u32) -> Self {
        Self {
            inner: Inner {
                key: *derived.as_bytes(),
            },
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
