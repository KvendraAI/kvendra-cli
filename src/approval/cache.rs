//! In-memory `approve-all-5min` cache (ADR-KVD-014, extended by REQ-KVD-007).
//!
//! `HashMap<ApprovalCacheKey, expires_at>` envuelto en `tokio::sync::Mutex`.
//! Reset al restart del proceso es comportamiento intencional (security-first):
//! tras restart queremos prompt fresco. No persistimos.
//!
//! La key es compuesta: `(profile_id, allowlist_hmac_hex)` (REQ-KVD-007 /
//! ISSUE-018). Si el YAML del profile cambia, su HMAC cambia, y el cache
//! invalida automáticamente — cierra la TOCTOU window entre `[a]pprove-all-5min`
//! y la edición del archivo.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// TTL por defecto del botón `[a]pprove-all-5min`.
pub const DEFAULT_TTL_SECONDS: u64 = 300;

/// Composite cache key — combina el `profile_id` con el HMAC del allowlist
/// YAML actual del profile (REQ-KVD-007 / ISSUE-018). Si el YAML cambia,
/// la key cambia, y la entrada anterior queda inalcanzable (TOCTOU fix).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApprovalCacheKey {
    pub profile_id: String,
    pub allowlist_hmac_hex: String,
}

impl ApprovalCacheKey {
    pub fn new(profile_id: impl Into<String>, allowlist_hmac_hex: impl Into<String>) -> Self {
        Self {
            profile_id: profile_id.into(),
            allowlist_hmac_hex: allowlist_hmac_hex.into(),
        }
    }
}

/// Cache compartido entre todas las llamadas al `tools_call`. Se materializa
/// como `Arc<ApprovalCache>` dentro del `ServerContext`.
pub struct ApprovalCache {
    inner: Mutex<HashMap<ApprovalCacheKey, Instant>>,
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

    /// Devuelve `Some(remaining)` si `key` está en cache y NO ha expirado.
    /// Implementa lazy cleanup: borra entradas vencidas que detecte durante
    /// el lookup.
    pub async fn lookup(&self, key: &ApprovalCacheKey) -> Option<Duration> {
        let mut map = self.inner.lock().await;
        let expires_at = *map.get(key)?;
        let now = Instant::now();
        if now < expires_at {
            Some(expires_at - now)
        } else {
            map.remove(key);
            None
        }
    }

    /// Inserta o refresca la cache para `key` con TTL `ttl`.
    pub async fn approve(&self, key: ApprovalCacheKey, ttl: Duration) {
        let mut map = self.inner.lock().await;
        map.insert(key, Instant::now() + ttl);
    }

    /// Elimina la entrada de `key`. Devuelve `true` si existía.
    pub async fn revoke(&self, key: &ApprovalCacheKey) -> bool {
        let mut map = self.inner.lock().await;
        map.remove(key).is_some()
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

    fn key(profile_id: &str, hmac: &str) -> ApprovalCacheKey {
        ApprovalCacheKey::new(profile_id, hmac)
    }

    #[tokio::test]
    async fn lookup_returns_some_before_expiration() {
        let c = ApprovalCache::new();
        c.approve(key("p1", "h1"), Duration::from_secs(10)).await;
        assert!(c.lookup(&key("p1", "h1")).await.is_some());
    }

    #[tokio::test]
    async fn lookup_returns_none_after_expiration() {
        let c = ApprovalCache::new();
        c.approve(key("p1", "h1"), Duration::from_millis(10)).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(c.lookup(&key("p1", "h1")).await.is_none());
    }

    #[tokio::test]
    async fn approve_is_per_profile_isolated() {
        let c = ApprovalCache::new();
        c.approve(key("p1", "h1"), Duration::from_secs(10)).await;
        assert!(c.lookup(&key("p1", "h1")).await.is_some());
        assert!(c.lookup(&key("p2", "h1")).await.is_none());
    }

    #[tokio::test]
    async fn revoke_removes_entry() {
        let c = ApprovalCache::new();
        c.approve(key("p1", "h1"), Duration::from_secs(10)).await;
        assert!(c.revoke(&key("p1", "h1")).await);
        assert!(c.lookup(&key("p1", "h1")).await.is_none());
        assert!(!c.revoke(&key("p1", "h1")).await);
    }

    #[tokio::test]
    async fn count_excludes_expired() {
        let c = ApprovalCache::new();
        c.approve(key("p1", "h1"), Duration::from_millis(10)).await;
        c.approve(key("p2", "h2"), Duration::from_secs(10)).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(c.count().await, 1);
    }

    /// AC-ALLOWLIST-HMAC-4 — TOCTOU fix: una modificación del allowlist YAML
    /// (que cambia el HMAC) invalida automáticamente la entrada del cache
    /// poblada bajo el HMAC anterior. El segundo lookup devuelve `None`,
    /// forzando un approval fresco.
    #[tokio::test]
    async fn cache_invalidates_on_allowlist_hmac_change() {
        let c = ApprovalCache::new();
        c.approve(key("p1", "old_hmac"), Duration::from_secs(10))
            .await;
        assert!(
            c.lookup(&key("p1", "old_hmac")).await.is_some(),
            "cache hit con el HMAC original"
        );
        assert!(
            c.lookup(&key("p1", "new_hmac")).await.is_none(),
            "cache miss tras cambio del HMAC (TOCTOU fix)"
        );
    }
}
