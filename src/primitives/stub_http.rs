//! `kvendra.http` — Pase B stub.

use crate::error::{KvendraError, KvendraResult};
use serde_json::Value;

pub async fn execute(_args: &Value) -> KvendraResult<Value> {
    Err(KvendraError::PrimitiveNotImplemented("kvendra.http".into()))
}
