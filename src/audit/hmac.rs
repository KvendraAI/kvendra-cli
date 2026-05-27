//! HMAC-SHA256 chain over audit rows.
//!
//! Two HMAC layouts coexist on disk:
//!  - **v1** (alpha.1..0.1.0): commits to
//!    `id | ts | profile_id | primitive | action | args_hash | status |
//!     severity | flags | prev_hmac` (no `remote_audit_id`).
//!  - **v2** (0.3.0-alpha.1+): adds `| remote_audit_id?` at the end, where
//!    `None` canonicalizes to the empty string. Used by every new row after
//!    the v2 migration runs.
//!
//! Each row records its `hmac_version` (defaults to 2 for new inserts, 1 for
//! rows that pre-date the migration). `verify_chain` looks at that column
//! to decide which `compute_hmac_vN` to call so the chain stays valid
//! without rewriting historical rows.

use ::hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute the HMAC over a v1 row (no `remote_audit_id`).
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
    compute_hmac_v1(
        key,
        id,
        ts_unix_ms,
        profile_id,
        primitive,
        action,
        args_hash_hex,
        status,
        severity,
        flags,
        prev_hmac_hex,
    )
}

/// v1 HMAC layout — kept for verifying historical rows post-migration.
#[allow(clippy::too_many_arguments)]
pub fn compute_hmac_v1(
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
    hex::encode(mac.finalize().into_bytes())
}

/// v2 HMAC layout — extends v1 with `remote_audit_id` (NULL canonicalized
/// to the empty string).
#[allow(clippy::too_many_arguments)]
pub fn compute_hmac_v2(
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
    remote_audit_id: Option<&str>,
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
    mac.update(b"|");
    mac.update(remote_audit_id.unwrap_or("").as_bytes());
    hex::encode(mac.finalize().into_bytes())
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

    /// HMAC-versioning: a v2 row with `remote_audit_id == None` must NOT
    /// equal the same row computed under v1 — even though both reduce to
    /// "no extra field", v2 always appends the trailing `|""` separator so
    /// the inputs differ in length. We rely on `hmac_version` per row to
    /// pick the right function on verify (`verify_chain`).
    #[test]
    fn v1_and_v2_disagree_even_with_null_remote_audit() {
        let v1 = compute_hmac_v1(b"key", 1, 0, "p", "x", "y", "z", "ok", "info", "", "");
        let v2 = compute_hmac_v2(b"key", 1, 0, "p", "x", "y", "z", "ok", "info", "", "", None);
        assert_ne!(v1, v2);
    }

    /// A v2 row with `remote_audit_id = Some("01H...")` differs from a v2
    /// row with `None`: the remote correlation id is bound to the chain.
    #[test]
    fn v2_remote_audit_id_changes_hmac() {
        let none = compute_hmac_v2(b"key", 1, 0, "p", "x", "y", "z", "ok", "info", "", "", None);
        let some = compute_hmac_v2(
            b"key",
            1,
            0,
            "p",
            "x",
            "y",
            "z",
            "ok",
            "info",
            "",
            "",
            Some("01H1234567890ABCDEFGH"),
        );
        assert_ne!(none, some);
    }
}
