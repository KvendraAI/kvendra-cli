//! Per-key token bucket for local-variable resolutions in the broker
//! (REQ-KVD-11F906 RF-CLI-6): 30 per minute, burst 10 → `lvr_rate_limited`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

pub const DEFAULT_PER_MINUTE: f64 = 30.0;
pub const DEFAULT_BURST: f64 = 10.0;

struct Bucket {
    tokens: f64,
    last: Instant,
}

pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
    capacity: f64,
    refill_per_sec: f64,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_PER_MINUTE, DEFAULT_BURST)
    }
}

impl RateLimiter {
    pub fn new(per_minute: f64, burst: f64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            capacity: burst,
            refill_per_sec: per_minute / 60.0,
        }
    }

    /// Take one token for `key`. `false` when the bucket is empty.
    pub fn try_take(&self, key: &str) -> bool {
        let mut map = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let b = map.entry(key.to_string()).or_insert(Bucket {
            tokens: self.capacity,
            last: now,
        });
        let elapsed = now.duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_refuse_per_key() {
        let r = RateLimiter::new(30.0, 3.0);
        assert!(r.try_take("a") && r.try_take("a") && r.try_take("a"));
        assert!(!r.try_take("a"));
        assert!(r.try_take("b"));
    }
}
