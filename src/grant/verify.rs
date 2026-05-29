//! Verify a grant — signature, TTL, scope, and defence-in-depth session
//! check (ISSUE-KVD-CLI-20E747 / ISSUE-KVD-CLI-238B54).
//!
//! Two layers:
//!   - [`verify_signature`] — pure ed25519 check over the payload JCS. No
//!     vault, no filesystem. This is the `AC-HOOK-3` "verify without unlock"
//!     primitive.
//!   - [`verify_grant_applies`] — the full hook contract: re-derive the
//!     JCS from the payload, verify the detached signature with the supplied
//!     public key, confirm `key_id` matches that key, confirm `now <
//!     expires_at`, confirm a local master session is still active
//!     (defence-in-depth TOCTOU per the REQ), and confirm the requested op
//!     is in scope. Returns a [`GrantDecision`] the `verify-grant`
//!     subcommand maps to exit codes (0 applies / 2 fail-closed).

use crate::error::{KvendraError, KvendraResult};
use crate::grant::{SignedGrant, key_id_for_pubkey};
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::path::Path;

/// Outcome of [`verify_grant_applies`]. Only [`GrantDecision::Apply`] should
/// relax enforcement; every other variant is fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantDecision {
    /// The grant is valid, unexpired, in-scope and backed by a live
    /// session — the hook may relax this op.
    Apply,
    /// No `.bypass` file for this workspace.
    NoGrant,
    /// Signature did not verify (tamper or foreign key).
    SignatureInvalid,
    /// `key_id` does not match the supplied public key.
    KeyIdMismatch,
    /// `now >= expires_at`.
    Expired,
    /// The requested op is not in the grant's `ops`.
    OutOfScope,
    /// The grant's `workspace_root` does not match the request.
    WorkspaceMismatch,
    /// No active (unexpired) local master session — the grant is moot
    /// because the broker session itself is gone (TOCTOU defence).
    NoActiveSession,
    /// Grant file present but unparseable / wrong schema.
    Malformed,
}

impl GrantDecision {
    /// Process exit code for `kvendra verify-grant`: 0 = applies, 2 =
    /// fail-closed (any non-apply). The hook treats anything ≠ 0 as
    /// "apply strict".
    pub fn exit_code(&self) -> i32 {
        match self {
            GrantDecision::Apply => 0,
            _ => 2,
        }
    }

    /// `true` iff the grant relaxes enforcement.
    pub fn applies(&self) -> bool {
        matches!(self, GrantDecision::Apply)
    }

    /// Stable machine-readable reason string (for audit + JSON output).
    pub fn reason(&self) -> &'static str {
        match self {
            GrantDecision::Apply => "apply",
            GrantDecision::NoGrant => "no_grant",
            GrantDecision::SignatureInvalid => "signature_invalid",
            GrantDecision::KeyIdMismatch => "key_id_mismatch",
            GrantDecision::Expired => "expired",
            GrantDecision::OutOfScope => "out_of_scope",
            GrantDecision::WorkspaceMismatch => "workspace_mismatch",
            GrantDecision::NoActiveSession => "no_active_session",
            GrantDecision::Malformed => "malformed",
        }
    }
}

/// Pure ed25519 verification of a [`SignedGrant`] against a public key. Does
/// NOT touch the vault, filesystem, TTL or scope — only the signature.
/// `AC-HOOK-3`: callable without unlocking the vault.
pub fn verify_signature(grant: &SignedGrant, verifying: &VerifyingKey) -> KvendraResult<()> {
    let jcs = grant.payload.to_jcs()?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(grant.sig_ed25519.trim())
        .map_err(|e| KvendraError::Vault(format!("grant sig b64: {e}")))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| KvendraError::Vault("grant sig wrong length".into()))?;
    let sig = Signature::from_bytes(&sig_arr);
    verifying
        .verify(&jcs, &sig)
        .map_err(|_| KvendraError::Vault("grant signature verification failed".into()))
}

/// Full hook-contract evaluation. `home` locates the vault; `workspace_root`
/// and `op` come from the hook stdin; `verifying` is the pinned public key
/// the hook supplies; `now` is injected for deterministic tests.
///
/// Order of checks is fail-closed throughout: any error / missing file maps
/// to a non-`Apply` decision, never a permissive default.
pub fn verify_grant_applies(
    home: &Path,
    workspace_root: &str,
    op: &str,
    verifying: &VerifyingKey,
    now: DateTime<Utc>,
) -> GrantDecision {
    let ws_id = crate::grant::workspace_id_from_root(workspace_root);
    let grant = match crate::grant::store::load(home, &ws_id) {
        Ok(Some(g)) => g,
        Ok(None) => return GrantDecision::NoGrant,
        Err(_) => return GrantDecision::Malformed,
    };

    // 1) Signature over the JCS (also catches any payload tamper).
    if verify_signature(&grant, verifying).is_err() {
        return GrantDecision::SignatureInvalid;
    }

    // 2) key_id must match the public key we verified against — a grant
    //    signed by a rotated/foreign key with a stale key_id is rejected.
    if grant.payload.key_id != key_id_for_pubkey(verifying.to_bytes().as_slice()) {
        return GrantDecision::KeyIdMismatch;
    }

    // 3) Workspace must match (the file is keyed by id, but the payload
    //    carries the full root to defend against slug collisions).
    if grant.payload.workspace_root != workspace_root {
        return GrantDecision::WorkspaceMismatch;
    }

    // 4) TTL.
    if !grant.payload.is_within_ttl(now) {
        return GrantDecision::Expired;
    }

    // 5) Defence-in-depth: a grant is only meaningful while the local
    //    master session is alive. If the vault session expired/locked, the
    //    broker path is gated anyway, so the bypass is moot — fail closed.
    if !crate::session::local::status(home).active {
        return GrantDecision::NoActiveSession;
    }

    // 6) Scope.
    if !grant.payload.covers_op(op) {
        return GrantDecision::OutOfScope;
    }

    GrantDecision::Apply
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::SCHEMA_VERSION;
    use crate::grant::sign::sign_grant;
    use crate::grant::{GrantPayload, key_id_for_pubkey};
    use chrono::Duration as ChronoDuration;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn payload_for(
        key: &SigningKey,
        ws_root: &str,
        ops: &[&str],
        now: DateTime<Utc>,
    ) -> GrantPayload {
        GrantPayload {
            schema_version: SCHEMA_VERSION,
            workspace_root: ws_root.into(),
            workspace_id: crate::grant::workspace_id_from_root(ws_root),
            ops: ops.iter().map(|s| s.to_string()).collect(),
            issued_at: now,
            expires_at: now + ChronoDuration::hours(1),
            key_id: key_id_for_pubkey(key.verifying_key().to_bytes().as_slice()),
            nonce: "Tm9uY2U=".into(),
        }
    }

    #[test]
    fn signature_tamper_is_caught() {
        let key = SigningKey::generate(&mut OsRng);
        let now = Utc::now();
        let mut grant =
            sign_grant(payload_for(&key, "/ws", &["kvendra.git.push"], now), &key).unwrap();
        // Tamper a payload field after signing.
        grant.payload.ops.push("kvendra.shell.exec".into());
        assert!(verify_signature(&grant, &key.verifying_key()).is_err());
    }

    #[test]
    fn decision_exit_codes() {
        assert_eq!(GrantDecision::Apply.exit_code(), 0);
        assert_eq!(GrantDecision::Expired.exit_code(), 2);
        assert_eq!(GrantDecision::NoGrant.exit_code(), 2);
        assert_eq!(GrantDecision::OutOfScope.exit_code(), 2);
    }
}
