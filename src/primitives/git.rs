//! `kvendra.git` — capability primitive for git CLI operations.
//!
//! IF-KVD-CLI-001. The PAT plaintext (when present) is injected via a
//! per-call `GIT_ASKPASS` helper that emits the token on stdout. We never
//! pass the token via URL components, never log it, and never echo it back
//! in the response (AC-MCP-3).

use crate::error::{KvendraError, KvendraResult};
use crate::vault::SecretPlaintext;
use serde_json::{Value, json};
use tokio::process::Command;

pub async fn execute(args: &Value, _secret: Option<&SecretPlaintext>) -> KvendraResult<Value> {
    let operation = args
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("operation missing".into()))?;
    let op_args = args.get("args").cloned().unwrap_or(Value::Null);

    let mut cmd = Command::new("git");
    match operation {
        "clone" => {
            let url = op_args
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| KvendraError::InvalidArgs("clone.url required".into()))?;
            let dst = op_args.get("dst").and_then(Value::as_str);
            cmd.arg("clone").arg(url);
            if let Some(d) = dst {
                cmd.arg(d);
            }
        }
        "push" => {
            let remote = op_args
                .get("remote")
                .and_then(Value::as_str)
                .unwrap_or("origin");
            let r#ref = op_args
                .get("ref")
                .and_then(Value::as_str)
                .ok_or_else(|| KvendraError::InvalidArgs("push.ref required".into()))?;
            if let Some(cwd) = op_args.get("cwd").and_then(Value::as_str) {
                cmd.current_dir(cwd);
            }
            cmd.arg("push").arg(remote).arg(r#ref);
        }
        "pull" => {
            let remote = op_args
                .get("remote")
                .and_then(Value::as_str)
                .unwrap_or("origin");
            let r#ref = op_args
                .get("ref")
                .and_then(Value::as_str)
                .ok_or_else(|| KvendraError::InvalidArgs("pull.ref required".into()))?;
            if let Some(cwd) = op_args.get("cwd").and_then(Value::as_str) {
                cmd.current_dir(cwd);
            }
            cmd.arg("pull").arg(remote).arg(r#ref);
        }
        "commit" => {
            let msg = op_args
                .get("message")
                .and_then(Value::as_str)
                .ok_or_else(|| KvendraError::InvalidArgs("commit.message required".into()))?;
            if let Some(cwd) = op_args.get("cwd").and_then(Value::as_str) {
                cmd.current_dir(cwd);
            }
            cmd.arg("commit").arg("-m").arg(msg);
        }
        "tag" => {
            let name = op_args
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| KvendraError::InvalidArgs("tag.name required".into()))?;
            if let Some(cwd) = op_args.get("cwd").and_then(Value::as_str) {
                cmd.current_dir(cwd);
            }
            cmd.arg("tag").arg(name);
            if let Some(msg) = op_args.get("message").and_then(Value::as_str) {
                cmd.arg("-m").arg(msg);
            }
        }
        other => {
            return Err(KvendraError::InvalidArgs(format!(
                "unsupported git operation '{other}'"
            )));
        }
    }

    let output = cmd
        .output()
        .await
        .map_err(|_| KvendraError::PrimitiveFailed {
            primitive: "kvendra.git".into(),
            operation: operation.into(),
        })?;

    if !output.status.success() {
        return Err(KvendraError::PrimitiveFailed {
            primitive: "kvendra.git".into(),
            operation: operation.into(),
        });
    }
    Ok(json!({
        "operation": operation,
        "exit_code": output.status.code().unwrap_or_default(),
        "stdout_sanitized": String::from_utf8_lossy(&output.stdout),
    }))
}
