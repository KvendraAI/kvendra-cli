//! On-disk blob format: header (KDF params + nonce) + ciphertext.
//!
//! Layout (JSON-serialized, base64 binary fields):
//! ```json
//! {
//!   "version": 1,
//!   "kdf": { "m_cost_kib", "t_cost", "p_cost", "salt": "<b64>" },
//!   "nonce": "<b64>",
//!   "ciphertext": "<b64>"
//! }
//! ```
//!
//! This format is opaque to anyone without the master password (per
//! REQ-KVD-002 AC-VAULT-2).

use crate::error::{KvendraError, KvendraResult};
use crate::vault::kdf::KdfParams;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Blob {
    pub version: u32,
    pub kdf: KdfParams,
    #[serde(with = "b64_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64_bytes")]
    pub ciphertext: Vec<u8>,
}

impl Blob {
    pub const VERSION: u32 = 1;

    pub fn new(kdf: KdfParams, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self {
            version: Self::VERSION,
            kdf,
            nonce,
            ciphertext,
        }
    }

    pub fn to_json(&self) -> KvendraResult<String> {
        serde_json::to_string_pretty(self).map_err(KvendraError::from)
    }

    pub fn from_json(s: &str) -> KvendraResult<Self> {
        serde_json::from_str(s).map_err(KvendraError::from)
    }
}

/// Helper module for base64-encoded binary fields in serde.
mod b64_bytes {
    use super::B64;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(&s).map_err(serde::de::Error::custom)
    }
}
