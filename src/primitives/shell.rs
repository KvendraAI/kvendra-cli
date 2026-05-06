//! `kvendra.shell` — constrained binary execution broker (IF-KVD-CLI-007).
//!
//! Critical contract: this primitive **never** invokes a shell. We use
//! `tokio::process::Command::new(binary).args(argv)` directly — no `sh -c`,
//! no string interpolation, no glob expansion. This eliminates whole
//! classes of injection (semicolons, pipes, command substitution).

use crate::error::{KvendraError, KvendraResult};
use serde_json::{Value, json};
use tokio::process::Command;

pub async fn execute(args: &Value) -> KvendraResult<Value> {
    let op_args = args.get("args").cloned().unwrap_or(Value::Null);
    let binary = op_args
        .get("binary")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("shell.binary required".into()))?;
    let argv = op_args
        .get("argv")
        .and_then(Value::as_array)
        .ok_or_else(|| KvendraError::InvalidArgs("shell.argv required".into()))?;
    let argv: Vec<String> = argv
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();

    // Direct binary invocation — never `sh -c`.
    let mut cmd = Command::new(binary);
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
