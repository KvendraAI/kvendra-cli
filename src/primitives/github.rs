//! `kvendra.github` — GitHub REST broker.
//!
//! Pase A: skeletal. Builds a `reqwest` client with TLS and the public
//! base URL. Real PAT injection lands in Pase B (it requires the unlocked
//! vault session). This module already proves out shape, schema and
//! sanitization paths.

use crate::error::{KvendraError, KvendraResult};
use serde_json::{Value, json};

pub async fn execute(args: &Value) -> KvendraResult<Value> {
    let operation = args
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("operation missing".into()))?;
    let op_args = args.get("args").cloned().unwrap_or(Value::Null);

    // Build a TLS-only client even though we do not yet attach a token.
    let _client = reqwest::Client::builder()
        .user_agent(concat!("kvendra/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| KvendraError::PrimitiveFailed {
            primitive: "kvendra.github".into(),
            operation: operation.into(),
        })?;

    match operation {
        "read_issue" | "update_issue" | "update_repo" | "release" | "add_topics" => Ok(json!({
            "operation": operation,
            "stub": "Pase A scaffold. Real REST call lands when vault unlock attaches PAT.",
            "args_received": op_args,
        })),
        other => Err(KvendraError::InvalidArgs(format!(
            "unsupported github operation '{other}'"
        ))),
    }
}
