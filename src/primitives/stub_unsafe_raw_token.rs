//! `kvendra.unsafe.raw_token` — Pase B stub.
//!
//! The escape hatch returns the plaintext token of a profile. Wiring it
//! in Pase B requires the unlocked vault session and the `reason` field
//! validation per IF-KVD-CLI-008.

use crate::error::{KvendraError, KvendraResult};
use serde_json::Value;

pub async fn execute(_args: &Value) -> KvendraResult<Value> {
    Err(KvendraError::PrimitiveNotImplemented(
        "kvendra.unsafe.raw_token".into(),
    ))
}
