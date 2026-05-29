//! Sign a grant payload with the ed25519 private key (ISSUE-KVD-CLI-20E747).
//!
//! The signature is **detached** and computed over the JCS (RFC 8785)
//! canonicalization of the [`GrantPayload`] — never over the assembled
//! [`SignedGrant`] (which carries the signature itself). This is what makes
//! a hand-edit of any payload field on disk break verification.

use crate::error::KvendraResult;
use crate::grant::{GrantPayload, SignedGrant};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Produce a [`SignedGrant`] from a payload and the signing key. The
/// returned grant's `sig_ed25519` is the base64 detached signature over
/// `payload.to_jcs()`.
pub fn sign_grant(payload: GrantPayload, signing: &SigningKey) -> KvendraResult<SignedGrant> {
    let jcs = payload.to_jcs()?;
    let sig = signing.sign(&jcs);
    Ok(SignedGrant {
        payload,
        sig_ed25519: b64().encode(sig.to_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::SCHEMA_VERSION;
    use crate::grant::verify::verify_signature;
    use chrono::{Duration as ChronoDuration, Utc};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn payload() -> GrantPayload {
        let now = Utc::now();
        GrantPayload {
            schema_version: SCHEMA_VERSION,
            workspace_root: "/ws".into(),
            workspace_id: "ws".into(),
            ops: vec!["kvendra.git.push".into()],
            issued_at: now,
            expires_at: now + ChronoDuration::hours(1),
            key_id: "grant-sign/v1:abcdef01".into(),
            nonce: "Tm9uY2U=".into(),
        }
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let signing = SigningKey::generate(&mut OsRng);
        let grant = sign_grant(payload(), &signing).unwrap();
        let verifying = signing.verifying_key();
        assert!(verify_signature(&grant, &verifying).is_ok());
    }

    #[test]
    fn signature_fails_under_wrong_key() {
        let signing = SigningKey::generate(&mut OsRng);
        let grant = sign_grant(payload(), &signing).unwrap();
        let other = SigningKey::generate(&mut OsRng).verifying_key();
        assert!(verify_signature(&grant, &other).is_err());
    }
}
