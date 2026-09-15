//! `kvendra.shell` — constrained binary execution broker (IF-KVD-CLI-007).
//!
//! Critical contract: this primitive **never** invokes a shell. We use
//! `tokio::process::Command::new(binary).args(argv)` directly — no `sh -c`,
//! no string interpolation, no glob expansion. This eliminates whole
//! classes of injection (semicolons, pipes, command substitution).

use crate::error::{KvendraError, KvendraResult};
use crate::vault::SecretPlaintext;
use serde_json::{Value, json};

/// Single source of truth for the wire field name that carries the binary to
/// execute. The allowlist enforcer (`allowlist::enforcer`) MUST read the
/// `binaries:` constraint against this exact key. Pre-0.6.4 the enforcer read
/// `"bin"` while this primitive emitted `"binary"`, so the `binaries:`
/// allowlist was never checked (audit finding C2 / PAT-KVD-CLI-1A99C5).
/// Keeping the field name here, referenced from both sides, makes a rename a
/// compile-time break rather than a silent security regression.
pub const BINARY_FIELD: &str = "binary";

/// Single source of truth for the wire field name that carries the argument
/// vector, used by both this primitive and the enforcer's `args_constraints`
/// check.
pub const ARGV_FIELD: &str = "argv";

pub async fn execute(args: &Value, _secret: Option<&SecretPlaintext>) -> KvendraResult<Value> {
    let op_args = args.get("args").cloned().unwrap_or(Value::Null);
    let binary = op_args
        .get(BINARY_FIELD)
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("shell.binary required".into()))?;
    let argv = op_args
        .get(ARGV_FIELD)
        .and_then(Value::as_array)
        .ok_or_else(|| KvendraError::InvalidArgs("shell.argv required".into()))?;
    let argv: Vec<String> = argv
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();

    // Direct binary invocation — never `sh -c`. Hardened spawn: scrub
    // KVENDRA_* env (N1) + sanitised PATH (A2) + stdin detached
    // (ISSUE-KVD-CLI-330251). The binary itself is gated by the allowlist's
    // `binaries:` constraint; argv are the binary's own arguments.
    let mut cmd = crate::primitives::spawn::hardened_command(binary);
    cmd.args(&argv);
    if let Some(cwd) = op_args.get("cwd").and_then(Value::as_str) {
        cmd.current_dir(cwd);
    }

    let output = cmd
        .output()
        .await
        .map_err(|_| KvendraError::PrimitiveFailed {
            primitive: "kvendra.shell".into(),
            operation: "exec".into(),
        })?;

    Ok(json!({
        "binary": binary,
        "exit_code": output.status.code().unwrap_or_default(),
        "stdout_sanitized": String::from_utf8_lossy(&output.stdout),
        "stderr_sanitized": String::from_utf8_lossy(&output.stderr),
    }))
}
