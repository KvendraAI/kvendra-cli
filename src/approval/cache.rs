//! In-memory `approve-all-5min` cache (ADR-KVD-014).
//!
//! `HashMap<profile_id, expires_at>` envuelto en `tokio::sync::Mutex`. Reset al
//! restart del proceso es comportamiento intencional (security-first): tras
//! restart queremos prompt fresco. No persistimos.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// TTL por defecto del botón `[a]pprove-all-5min`.
pub const DEFAULT_TTL_SECONDS: u64 = 300;

/// Cache compartido entre todas las llamadas al `tools_call`. Se materializa
/// como `Arc<ApprovalCache>` dentro del `ServerContext`.
pub struct ApprovalCache {
    inner: Mutex<HashMap<String, Instant>>,
}

impl Default for ApprovalCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ApprovalCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Devuelve `Some(remaining)` si `profile_id` está en cache y NO ha
    /// expirado. Implementa lazy cleanup: borra entradas vencidas que
    /// detecte durante el lookup.
    pub async fn lookup(&self, profile_id: &str) -> Option<Duration> {
        let mut map = self.inner.lock().await;
        let expires_at = *map.get(profile_id)?;
        let now = Instant::now();
        if now < expires_at {
            Some(expires_at - now)
        } else {
            map.remove(profile_id);
            None
        }
    }

    /// Inserta o refresca la cache para `profile_id` con TTL `ttl`.
    pub async fn approve(&self, profile_id: &str, ttl: Duration) {
        let mut map = self.inner.lock().await;
        map.insert(profile_id.to_string(), Instant::now() + ttl);
    }

    /// Elimina la entrada de `profile_id`. Devuelve `true` si existía.
    pub async fn revoke(&self, profile_id: &str) -> bool {
        let mut map = self.inner.lock().await;
        map.remove(profile_id).is_some()
    }

    /// Cardinalidad actual del cache (post-cleanup lazy). Útil para
    /// `kvendra config approval status`.
    pub async fn count(&self) -> usize {
        let mut map = self.inner.lock().await;
        let now = Instant::now();
        map.retain(|_, expires_at| *expires_at > now);
        map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lookup_returns_some_before_expiration() {
        let c = ApprovalCache::new();
        c.approve("p1", Duration::from_secs(10)).await;
        let r = c.lookup("p1").await;
        assert!(r.is_some());
    }

    #[tokio::test]
    async fn lookup_returns_none_after_expiration() {
        let c = ApprovalCache::new();
        c.approve("p1", Duration::from_millis(10)).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        let r = c.lookup("p1").await;
        assert!(r.is_none());
    }

    #[tokio::test]
    async fn approve_is_per_profile_isolated() {
        let c = ApprovalCache::new();
        c.approve("p1", Duration::from_secs(10)).await;
        assert!(c.lookup("p1").await.is_some());
        assert!(c.lookup("p2").await.is_none());
    }

    #[tokio::test]
    async fn revoke_removes_entry() {
        let c = ApprovalCache::new();
        c.approve("p1", Duration::from_secs(10)).await;
        assert!(c.revoke("p1").await);
        assert!(c.lookup("p1").await.is_none());
        assert!(!c.revoke("p1").await);
    }

    #[tokio::test]
    async fn count_excludes_expired() {
        let c = ApprovalCache::new();
        c.approve("p1", Duration::from_millis(10)).await;
        c.approve("p2", Duration::from_secs(10)).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(c.count().await, 1);
    }
}
