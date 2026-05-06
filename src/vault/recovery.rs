//! Recovery — 12 BIP-39 mnemonic + 8 numeric one-time codes (ADR-KVD-011).
//!
//! - 12-word BIP-39 mnemonic: 132 bits entropy (English wordlist), checksum
//!   integrated. Lives ONLY with the user; never persisted in the vault.
//! - 8 numeric codes (format `XXXX-XXXX-XX`, 10 digits): hashed with
//!   Argon2id and stored in `~/.kvendra/recovery_codes.json` as
//!   `{ hash, used_at, used_for }` (single-use).

use crate::error::{KvendraError, KvendraResult};
use bip39::{Language, Mnemonic};
use rand::Rng;
use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCode {
    pub hash_b64: String,
    pub salt_b64: String,
    pub used_at: Option<String>,
    pub used_for: Option<String>,
}

/// Whole-file representation of `recovery_codes.json`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RecoveryCodesFile {
    pub codes: Vec<StoredCode>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

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
