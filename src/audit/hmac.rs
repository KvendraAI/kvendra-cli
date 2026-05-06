//! HMAC-SHA256 chain over audit rows.
//!
//! Each row's HMAC commits to:
//!   `id || ts || profile_id || primitive || action || args_hash || status
//!    || severity || flags || prev_hmac`
//!
//! Tampering with any field or reordering rows breaks the chain (detected
//! by `verify_chain`).

use ::hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[allow(clippy::too_many_arguments)]
pub fn compute_hmac(
    key: &[u8],
    id: i64,
    ts_unix_ms: i64,
    profile_id: &str,
    primitive: &str,
    action: &str,
    args_hash_hex: &str,
    status: &str,
    severity: &str,
    flags: &str,
    prev_hmac_hex: &str,
) -> String {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts arbitrary-length keys");
    mac.update(&id.to_be_bytes());
    mac.update(b"|");
    mac.update(&ts_unix_ms.to_be_bytes());
    mac.update(b"|");
    mac.update(profile_id.as_bytes());
    mac.update(b"|");
    mac.update(primitive.as_bytes());
    mac.update(b"|");
    mac.update(action.as_bytes());
    mac.update(b"|");
    mac.update(args_hash_hex.as_bytes());
    mac.update(b"|");
    mac.update(status.as_bytes());
    mac.update(b"|");
    mac.update(severity.as_bytes());
    mac.update(b"|");
    mac.update(flags.as_bytes());
    mac.update(b"|");
    mac.update(prev_hmac_hex.as_bytes());
    let result = mac.finalize().into_bytes();
    hex::encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(prev: &str, action: &str) -> String {
        compute_hmac(
            b"key",
            1,
            1_700_000_000_000,
            "p",
            "kvendra.git",
            action,
            "deadbeef",
            "ok",
            "info",
            "",
            prev,
        )
    }

    #[test]
    fn chain_is_deterministic() {
        let a = h("", "push");
        let b = h("", "push");
        assert_eq!(a, b);
    }

    #[test]
    fn tampering_action_breaks_chain() {
        let a = h("", "push");
        let b = h("", "force-push");
        assert_ne!(a, b);
    }

    #[test]
    fn prev_chains_propagate() {
        let a = h("", "push");
        let b = h(&a, "push");
        let c = h("", "push");
        // Same payload, different prev_hmac → different hmac.
        assert_ne!(a, b);
        assert_eq!(a, c);
    }
}
