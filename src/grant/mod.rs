//! Break-glass bypass grant — signed, ephemeral, fail-closed
//! (REQ-KVD-SKILLS-41032D / ISSUE-KVD-CLI-20E747 + ISSUE-KVD-CLI-238B54).
//!
//! A **grant** temporarily relaxes the `kvendra-skills` PreToolUse hook
//! enforcement for a single workspace, scoped to an explicit set of
//! `primitive.op`s, with a mandatory TTL. The grant is:
//!
//! - **Signed with an asymmetric ed25519 keypair** — the private half is
//!   encrypted under the vault key (AES-256-GCM, machine-bound, mirroring
//!   `session/local.rs`), the public half is exported without unlock
//!   (`kvendra grant-pubkey`). The hook verifies the signature with the
//!   pinned public key *without* unlocking the vault. A symmetric HMAC
//!   would not work: the verifier would need the secret, and any process
//!   that could read it could forge grants.
//! - **Ephemeral & separate** — stored in
//!   `~/.kvendra/sessions/<workspace_id_safe>.bypass` (0600 + flock +
//!   atomic rename, the exact pattern of `session/store.rs`). It is NOT
//!   mixed into `.kvendra-protected` (different trust models).
//! - **Fail-closed** — a missing / expired / tampered / out-of-scope grant
//!   means the hook applies strict policy.
//!
//! ## Grant JSON format (canonical, JCS)
//!
//! The signed payload is the JCS (RFC 8785, via `serde_jcs`) serialization
//! of every [`GrantPayload`] field. The detached ed25519 signature
//! (`sig_ed25519`) lives alongside it in [`SignedGrant`] but is NOT part of
//! the signed bytes. Editing the on-disk grant by hand changes the JCS and
//! invalidates the signature (AC-CLI-4 / AC-SEC-1).
//!
//! ## Sub-key domain separation
//!
//! The ed25519 private seed is sealed under the HKDF sub-key
//! `kvendra/grant-sign/v1` (info constant [`HKDF_INFO_GRANT_SIGN`]),
//! following the canonical `kvendra/<purpose>/v<N>` namespace
//! (ADR-KVD-022, alongside audit-hmac/v1, allowlist-hmac/v1,
//! config-hmac/v1, session-wrap/v1).

pub mod keypair;
pub mod sign;
pub mod store;
pub mod verify;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// HKDF info string for the grant-signing sub-key (REQ-KVD-SKILLS-41032D).
/// Domain-separates the AES key that wraps the ed25519 private seed from
/// every other sub-key derived from the same master key. Canonical
/// `kvendra/<purpose>/v<N>` namespace (ADR-KVD-022).
pub const HKDF_INFO_GRANT_SIGN: &[u8] = b"kvendra/grant-sign/v1";

/// On-disk schema version for the grant payload. Bump on any incompatible
/// shape change so an older binary refuses to consume a newer grant.
pub const SCHEMA_VERSION: u32 = 1;

/// The signed portion of a grant. The JCS canonicalization of this struct
/// is exactly what the ed25519 signature covers. `sig_ed25519` is
/// deliberately NOT a field here — it lives on [`SignedGrant`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantPayload {
    /// On-disk schema version (always [`SCHEMA_VERSION`] when written).
    pub schema_version: u32,
    /// Absolute workspace root path this grant applies to (matches the
    /// `workspace_root` the hook sends on stdin). Resolves grant scope
    /// per-workspace (R-5 of the REQ).
    pub workspace_root: String,
    /// Filesystem-safe workspace identifier (basename of `workspace_root`,
    /// slugified) — also the `.bypass` filename stem.
    pub workspace_id: String,
    /// Exact set of relaxed `primitive.op` tokens (e.g. `kvendra.git.push`).
    /// The hook relaxes only these; everything else stays strict
    /// (AC-SCOPE-1). Never empty — a grant with no ops is rejected at
    /// creation.
    pub ops: Vec<String>,
    /// When the grant was issued (UTC).
    pub issued_at: DateTime<Utc>,
    /// When the grant expires (UTC). `now < expires_at` is required for the
    /// grant to apply (AC-CLI-3 / AC-HOOK-2).
    pub expires_at: DateTime<Utc>,
    /// Key identifier: `grant-sign/v1:<fingerprint8>` where `<fingerprint8>`
    /// is the first 8 hex chars of SHA-256 over the public key bytes. Lets
    /// the hook detect a grant signed by a rotated/foreign key.
    pub key_id: String,
    /// Random base64 nonce, fresh per grant. Prevents two otherwise-identical
    /// grants from producing byte-identical signed payloads.
    pub nonce: String,
}

impl GrantPayload {
    /// Serialize to canonical JCS bytes (RFC 8785). This is the exact byte
    /// string the ed25519 signature is computed over and verified against.
    pub fn to_jcs(&self) -> crate::error::KvendraResult<Vec<u8>> {
        serde_jcs::to_vec(self)
            .map_err(|e| crate::error::KvendraError::Serialization(format!("grant jcs: {e}")))
    }

    /// `true` when the grant is still within its TTL window relative to
    /// `now`. Pure — the caller supplies `now` so tests stay deterministic.
    pub fn is_within_ttl(&self, now: DateTime<Utc>) -> bool {
        now < self.expires_at
    }

    /// `true` when `op` is one of the relaxed ops (exact match).
    pub fn covers_op(&self, op: &str) -> bool {
        self.ops.iter().any(|o| o == op)
    }
}

/// The full on-disk grant: the signed payload plus the detached ed25519
/// signature over its JCS. Serialized with `sig_ed25519` as a sibling of
/// the payload fields so a human edit to any payload field breaks the
/// signature (the verifier re-derives the JCS from the payload only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedGrant {
    #[serde(flatten)]
    pub payload: GrantPayload,
    /// Detached ed25519 signature (base64) over `payload.to_jcs()`.
    pub sig_ed25519: String,
}

/// Derive the canonical `key_id` for a public key:
/// `grant-sign/v1:<first 8 hex of SHA-256(pubkey bytes)>`.
pub fn key_id_for_pubkey(pubkey_bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(pubkey_bytes);
    let fp8: String = hex::encode(digest).chars().take(8).collect();
    format!("grant-sign/v1:{fp8}")
}

/// Translate a `workspace_root` path into a filesystem-safe workspace id.
/// Uses the final path component (basename); slashes that survive (none,
/// for a basename) are mapped to `__` for parity with
/// [`crate::session::SessionState::workspace_id_safe`]. Falls back to a
/// hash-free `workspace` literal for a root path with no basename.
pub fn workspace_id_from_root(workspace_root: &str) -> String {
    let trimmed = workspace_root.trim_end_matches(['/', '\\']);
    let base = std::path::Path::new(trimmed)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "workspace".to_string());
    // Defence-in-depth: never let a stray separator escape the basename
    // into the filename stem.
    base.replace(['/', '\\'], "__")
}

/// Re-export the high-level revoke helper so callers (`cli/lock.rs`,
/// `cli/bypass.rs`) can `grant::revoke_all(&home)` /
/// `grant::revoke(&home, ws)` without reaching into `store`.
pub use store::{revoke, revoke_all};

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    fn sample_payload() -> GrantPayload {
        let now = Utc::now();
        GrantPayload {
            schema_version: SCHEMA_VERSION,
            workspace_root: "/Users/dev/Develop/Kvendra".into(),
            workspace_id: "Kvendra".into(),
            ops: vec!["kvendra.git.push".into(), "kvendra.aws.s3_sync".into()],
            issued_at: now,
            expires_at: now + ChronoDuration::hours(1),
            key_id: "grant-sign/v1:deadbeef".into(),
            nonce: "AAAA".into(),
        }
    }

    #[test]
    fn jcs_is_deterministic_and_excludes_signature() {
        let p = sample_payload();
        let a = p.to_jcs().unwrap();
        let b = p.to_jcs().unwrap();
        assert_eq!(a, b, "JCS must be deterministic");
        let s = String::from_utf8(a).unwrap();
        assert!(
            !s.contains("sig_ed25519"),
            "signed payload must not contain the signature field"
        );
        // JCS sorts keys lexicographically: expires_at before issued_at etc.
        assert!(s.starts_with('{'));
    }

    #[test]
    fn covers_op_is_exact_match() {
        let p = sample_payload();
        assert!(p.covers_op("kvendra.git.push"));
        assert!(p.covers_op("kvendra.aws.s3_sync"));
        assert!(!p.covers_op("kvendra.git.commit"));
        assert!(!p.covers_op("kvendra.git"));
    }

    #[test]
    fn ttl_window() {
        let now = Utc::now();
        let mut p = sample_payload();
        p.expires_at = now + ChronoDuration::minutes(10);
        assert!(p.is_within_ttl(now));
        assert!(!p.is_within_ttl(now + ChronoDuration::minutes(11)));
    }

    #[test]
    fn key_id_is_stable_prefix_plus_fingerprint() {
        let id = key_id_for_pubkey(&[0u8; 32]);
        assert!(id.starts_with("grant-sign/v1:"));
        assert_eq!(id.len(), "grant-sign/v1:".len() + 8);
        // Deterministic.
        assert_eq!(id, key_id_for_pubkey(&[0u8; 32]));
        assert_ne!(id, key_id_for_pubkey(&[1u8; 32]));
    }

    #[test]
    fn workspace_id_from_root_uses_basename() {
        assert_eq!(
            workspace_id_from_root("/Users/dev/Develop/Kvendra"),
            "Kvendra"
        );
        assert_eq!(
            workspace_id_from_root("/Users/dev/Develop/Kvendra/"),
            "Kvendra"
        );
        assert_eq!(workspace_id_from_root("/"), "workspace");
        assert_eq!(workspace_id_from_root("Kvendra"), "Kvendra");
    }

    #[test]
    fn jcs_changes_when_payload_changes() {
        let p1 = sample_payload();
        let mut p2 = sample_payload();
        p2.ops.push("kvendra.shell.exec".into());
        assert_ne!(p1.to_jcs().unwrap(), p2.to_jcs().unwrap());
    }
}
