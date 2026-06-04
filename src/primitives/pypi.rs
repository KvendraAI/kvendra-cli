//! `kvendra.pypi` — PyPI broker (IF-KVD-CLI-004).
//!
//! Operations: `upload` (twine subprocess) + `read_metadata` (HTTP GET to
//! `pypi.org/pypi/<project>/json`). For `upload`, the token plaintext is
//! injected via the `TWINE_PASSWORD` env var with `TWINE_USERNAME=__token__`.

use crate::error::{KvendraError, KvendraResult};
use crate::vault::SecretPlaintext;
use serde_json::{Value, json};
use tokio::process::Command;

pub async fn execute(args: &Value, secret: Option<&SecretPlaintext>) -> KvendraResult<Value> {
    let operation = args
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("operation missing".into()))?;
    let op_args = args.get("args").cloned().unwrap_or(Value::Null);
    match operation {
        "upload" => upload(&op_args, secret).await,
        "read_metadata" => read_metadata(&op_args).await,
        other => Err(KvendraError::InvalidArgs(format!(
            "unsupported pypi operation '{other}'"
        ))),
    }
}

async fn upload(op_args: &Value, secret: Option<&SecretPlaintext>) -> KvendraResult<Value> {
    let dist = op_args
        .get("dist")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("pypi.upload.dist required".into()))?;
    let repository = op_args
        .get("repository")
        .and_then(Value::as_str)
        .unwrap_or("pypi");

    let mut cmd = Command::new("python");
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    cmd.arg("-m")
        .arg("twine")
        .arg("upload")
        .arg("--repository")
        .arg(repository)
        .arg(dist)
        .arg("--non-interactive");
    cmd.env("TWINE_USERNAME", "__token__");
    if let Some(s) = secret {
        cmd.env("TWINE_PASSWORD", s.as_str()?);
    }
    let output = cmd
        .output()
        .await
        .map_err(|_| KvendraError::PrimitiveFailed {
            primitive: "kvendra.pypi".into(),
            operation: "upload".into(),
        })?;
    Ok(json!({
        "operation": "upload",
        "exit_code": output.status.code().unwrap_or_default(),
        "success": output.status.success(),
        "stdout_sanitized": sanitize(&output.stdout),
        "stderr_sanitized": sanitize(&output.stderr),
    }))
}

async fn read_metadata(op_args: &Value) -> KvendraResult<Value> {
    let project = op_args
        .get("project")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("pypi.read_metadata.project required".into()))?;
    let url = format!("https://pypi.org/pypi/{project}/json");
    let client = reqwest::Client::builder()
        .user_agent(concat!("kvendra/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let resp = client.get(&url).send().await?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    Ok(json!({
        "operation": "read_metadata",
        "status_code": status.as_u16(),
        "project": project,
        "metadata": body,
    }))
}

fn sanitize(bytes: &[u8]) -> String {
    crate::detection::sanitize_output(&String::from_utf8_lossy(bytes))
}
