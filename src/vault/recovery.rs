//! Recovery — 12 BIP-39 mnemonic + 8 numeric one-time codes (ADR-KVD-011).
//!
//! - 12-word BIP-39 mnemonic: 132 bits entropy (English wordlist), checksum
//!   integrated. Lives ONLY with the user; never persisted in the vault.
//! - 8 numeric codes (format `XXXX-XXXX-XX`, 10 digits): hashed with
//!   Argon2id and stored in `~/.kvendra/recovery_codes.json` as
//!   `{ hash, used_at, used_for }` (single-use).

use crate::error::{KvendraError, KvendraResult};
use crate::vault::kdf::{KdfParams, derive};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use bip39::{Language, Mnemonic};
use rand::Rng;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// Number of one-time numeric codes generated at setup.
pub const RECOVERY_CODES_COUNT: usize = 8;

/// Generate a 12-word English BIP-39 mnemonic from secure RNG.
pub fn generate_mnemonic() -> KvendraResult<Mnemonic> {
    Mnemonic::generate_in(Language::English, 12)
        .map_err(|e| KvendraError::Vault(format!("bip39 generate: {e}")))
}

/// Parse a user-provided mnemonic phrase, validating checksum.
pub fn parse_mnemonic(phrase: &str) -> KvendraResult<Mnemonic> {
    Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(|_| KvendraError::RecoveryFailed)
}

/// Generate `RECOVERY_CODES_COUNT` numeric codes formatted `XXXX-XXXX-XX`.
pub fn generate_codes() -> Vec<String> {
    let mut rng = rand::thread_rng();
    let mut out = Vec::with_capacity(RECOVERY_CODES_COUNT);
    while out.len() < RECOVERY_CODES_COUNT {
        let mut digits = String::with_capacity(10);
        for _ in 0..10 {
            digits.push(char::from(b'0' + rng.gen_range(0..10)));
        }
        let code = format!("{}-{}-{}", &digits[0..4], &digits[4..8], &digits[8..10]);
        if !out.contains(&code) {
            out.push(code);
        }
    }
    out
}

/// Stored representation of a recovery code: Argon2id hash + use markers.
///
/// `used_at` / `used_for` are skipped on serialization when `None` so the
/// JSON payload stays compact for unused codes (REQ-KVD-008 D3=A). Default
/// is also `None` so legacy `recovery_codes.json` files written by the
/// alpha.6 binary keep loading without changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCode {
    pub hash_b64: String,
    pub salt_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_for: Option<String>,
}

/// Whole-file representation of `recovery_codes.json`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RecoveryCodesFile {
    pub codes: Vec<StoredCode>,
}

/// Validate `code_input` against every stored code WITHOUT consuming it.
///
/// Returns the slot index of the matching unconsumed code, or:
/// - [`KvendraError::RecoveryCodeAlreadyUsed`] if the code matches a slot that
///   was previously consumed (replay attempt).
/// - [`KvendraError::RecoveryCodeInvalid`] if no slot matches.
///
/// Used by `kvendra config rebind-home` triple-barrier flow (REQ-KVD-008
/// AC-REBIND-2): recovery code is *validated* before the TTY confirmation
/// step so a wrong-target re-typed path never burns a slot.
pub fn validate_code_unconsumed(
    file: &RecoveryCodesFile,
    code_input: &str,
) -> KvendraResult<usize> {
    // We must check ALL slots even after a match, so timing leaks the slot
    // index but not whether a match exists. The slot index is not secret —
    // a successful rebind audit row records it explicitly.
    let mut matched: Option<usize> = None;
    for (idx, stored) in file.codes.iter().enumerate() {
        let salt = B64
            .decode(&stored.salt_b64)
            .map_err(|e| KvendraError::Vault(format!("recovery slot {idx} salt b64: {e}")))?;
        let expected = B64
            .decode(&stored.hash_b64)
            .map_err(|e| KvendraError::Vault(format!("recovery slot {idx} hash b64: {e}")))?;
        let params = KdfParams {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt,
        };
        let derived = derive(code_input.as_bytes(), &params)?;
        if derived.as_bytes().ct_eq(expected.as_slice()).unwrap_u8() == 1 {
            matched = Some(idx);
            break;
        }
    }
    let idx = matched.ok_or(KvendraError::RecoveryCodeInvalid)?;
    let stored = &file.codes[idx];
    if let (Some(used_at), Some(used_for)) = (stored.used_at.as_ref(), stored.used_for.as_ref()) {
        return Err(KvendraError::RecoveryCodeAlreadyUsed {
            slot: idx,
            used_for: used_for.clone(),
            used_at: used_at.clone(),
        });
    }
    Ok(idx)
}

/// Mark the recovery code at `slot` as consumed for `used_for`.
///
/// Caller is responsible for re-writing `~/.kvendra/recovery_codes.json` with
/// the updated file (atomic write + 0600 perms). The `used_at` timestamp is
/// produced inline as a UTC RFC-3339 string.
pub fn mark_code_consumed(file: &mut RecoveryCodesFile, slot: usize, used_for: &str) {
    if let Some(stored) = file.codes.get_mut(slot) {
        let now = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
        stored.used_at = Some(now);
        stored.used_for = Some(used_for.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Build a `RecoveryCodesFile` with one slot for `code` (Argon2id-hashed
    /// with fast test params), used by REQ-KVD-008 helper tests.
    fn build_file_with(code: &str) -> RecoveryCodesFile {
        let salt = vec![0xABu8; 16];
        let params = KdfParams {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: salt.clone(),
        };
        let h = derive(code.as_bytes(), &params).unwrap();
        RecoveryCodesFile {
            codes: vec![StoredCode {
                hash_b64: B64.encode(h.as_bytes()),
                salt_b64: B64.encode(&salt),
                used_at: None,
                used_for: None,
            }],
        }
    }

    /// REQ-KVD-008 — happy path: a matching unconsumed code returns its slot.
    #[test]
    fn validate_code_unconsumed_match_unconsumed_returns_slot_idx() {
        let file = build_file_with("1111-2222-33");
        let slot = validate_code_unconsumed(&file, "1111-2222-33").unwrap();
        assert_eq!(slot, 0);
    }

    /// REQ-KVD-008 — replay rejection: a previously consumed code returns
    /// `RecoveryCodeAlreadyUsed { slot, used_for, used_at }`.
    #[test]
    fn validate_code_unconsumed_match_consumed_returns_already_used() {
        let mut file = build_file_with("9999-8888-77");
        mark_code_consumed(&mut file, 0, "home_rebound");
        let r = validate_code_unconsumed(&file, "9999-8888-77");
        match r {
            Err(KvendraError::RecoveryCodeAlreadyUsed { slot, used_for, .. }) => {
                assert_eq!(slot, 0);
                assert_eq!(used_for, "home_rebound");
            }
            other => panic!("expected RecoveryCodeAlreadyUsed, got {other:?}"),
        }
    }

    /// REQ-KVD-008 — invalid code: no slot match returns `RecoveryCodeInvalid`.
    #[test]
    fn validate_code_unconsumed_no_match_returns_invalid() {
        let file = build_file_with("1111-2222-33");
        let r = validate_code_unconsumed(&file, "0000-0000-00");
        assert!(matches!(r, Err(KvendraError::RecoveryCodeInvalid)));
    }

    /// REQ-KVD-008 — `mark_code_consumed` populates both fields.
    #[test]
    fn mark_code_consumed_sets_used_at_and_used_for() {
        let mut file = build_file_with("4444-5555-66");
        assert!(file.codes[0].used_at.is_none());
        assert!(file.codes[0].used_for.is_none());
        mark_code_consumed(&mut file, 0, "home_rebound");
        assert_eq!(file.codes[0].used_for.as_deref(), Some("home_rebound"));
        let used_at = file.codes[0].used_at.as_deref().unwrap();
        assert!(used_at.contains('T') && used_at.ends_with('Z'));
    }

    #[test]
    fn generate_mnemonic_round_trip() {
        let m = generate_mnemonic().unwrap();
        let phrase = m.to_string();
        let parsed = parse_mnemonic(&phrase).unwrap();
        assert_eq!(parsed.to_string(), phrase);
    }

    #[test]
    fn parse_invalid_mnemonic_fails() {
        let bad = "not a real bip39 phrase at all none of these words are valid checksum";
        assert!(parse_mnemonic(bad).is_err());
    }

    #[test]
    fn generate_codes_produces_eight_unique() {
        let codes = generate_codes();
        assert_eq!(codes.len(), RECOVERY_CODES_COUNT);
        let set: HashSet<_> = codes.iter().collect();
        assert_eq!(set.len(), RECOVERY_CODES_COUNT);
        for c in &codes {
            assert_eq!(c.len(), 12); // XXXX-XXXX-XX
            assert_eq!(c.matches('-').count(), 2);
        }
    }
}
