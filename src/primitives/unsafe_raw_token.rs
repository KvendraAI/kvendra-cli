//! `kvendra.unsafe.raw_token` — escape hatch (IF-KVD-CLI-008).
//!
//! Returns the plaintext credential associated with `profile_id`. This is
//! the **single documented exception** to AC-MCP-3 (otherwise no plaintext
//! ever rides on the MCP wire).
//!
//! Pre-conditions enforced here:
//!  - Profile metadata must declare `unsafe_raw_token_enabled: true`.
//!  - Per-profile per-session quota (`unsafe_max_uses_per_session`) is
//!    enforced by the dispatcher's quota counter (Pase B simplification:
//!    we read the profile-level constraint at execute time and the
//!    enforcer drops calls that exceed it).
//!
//! The audit row carries `flags = "unsafe_escape_hatch"` and never includes
//! the plaintext. `args_hash` covers `profile_id` only.

use crate::error::{KvendraError, KvendraResult};
use crate::vault::{SecretPlaintext, Vault};
use serde_json::{Value, json};

pub async fn execute(
    args: &Value,
    vault: &Vault,
    secret: Option<&SecretPlaintext>,
) -> KvendraResult<Value> {
    let profile_id = args
        .get("profile_id")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("profile_id required".into()))?;
    let reason = args
        .get("reason")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("reason required (min 10 chars)".into()))?;
    if reason.len() < 10 {
        return Err(KvendraError::InvalidArgs(
            "unsafe.raw_token: reason must be ≥ 10 chars".into(),
        ));
    }

    let meta = vault.load_profile_meta(profile_id)?;
    if !meta.unsafe_raw_token_enabled {
        return Err(KvendraError::UnsafeNotEnabled);
    }
    if meta.quarantined {
        return Err(KvendraError::AllowlistViolation(
            "profile is quarantined".into(),
        ));
    }

    let plaintext = match secret {
        Some(s) => s.as_str()?.to_string(),
        None => vault.get_secret(profile_id)?.as_str()?.to_string(),
    };

    // The plaintext rides on the MCP wire — exactly once, here. Documented
    // exception to AC-MCP-3 per IF-KVD-CLI-008.
    Ok(json!({
        "operation": "get",
        "profile_id": profile_id,
        "plaintext": plaintext,
    }))
}
