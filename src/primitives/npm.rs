//! `kvendra.npm` — npm registry broker (IF-KVD-CLI-003).
//!
//! Operations: `publish`, `deprecate`, `read_metadata`. The `npm` CLI
//! reads its registry token from the `NPM_TOKEN` env var (or via
//! `--//registry.npmjs.org/:_authToken=...` config), so the broker
//! injects the plaintext as `NPM_TOKEN` in the child process env. The
//! plaintext is wrapped in `SecretPlaintext` (ZeroizeOnDrop) and lives
//! only for the duration of the subprocess.

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
        "publish" => publish(&op_args, secret).await,
        "deprecate" => deprecate(&op_args, secret).await,
        "read_metadata" => read_metadata(&op_args).await,
        other => Err(KvendraError::InvalidArgs(format!(
            "unsupported npm operation '{other}'"
        ))),
    }
}

async fn publish(op_args: &Value, secret: Option<&SecretPlaintext>) -> KvendraResult<Value> {
    let cwd = op_args.get("cwd").and_then(Value::as_str).ok_or_else(|| {
        KvendraError::InvalidArgs("npm.publish.cwd required (path of package)".into())
    })?;
    let access = op_args
        .get("access")
        .and_then(Value::as_str)
        .unwrap_or("restricted");

    // Hardened spawn: scrub KVENDRA_* env (N1) + sanitised PATH (A2).
    let mut cmd = crate::primitives::spawn::hardened_command("npm");
    // ISSUE-KVD-CLI-B78ED5 finding N2 — `--ignore-scripts` is MANDATORY.
    // Without it, `npm publish` runs the package's `prepublishOnly` / `prepare`
    // / `prepack` lifecycle scripts from the caller-controlled `cwd`, which is
    // arbitrary code execution via a primitive that is meant to be a safe,
    // allowlisted "publish" — bypassing the whole allowlist/approval model and
    // the shell primitive's "no arbitrary exec" guarantee (PoC in the pentest).
    cmd.arg("publish")
        .arg("--ignore-scripts")
        .arg("--access")
        .arg(access)
        .current_dir(cwd);
    if let Some(s) = secret {
        cmd.env("NPM_TOKEN", s.as_str()?);
    }
    run_npm("publish", cmd).await
}

async fn deprecate(op_args: &Value, secret: Option<&SecretPlaintext>) -> KvendraResult<Value> {
    let package = op_args
        .get("package")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("npm.deprecate.package required".into()))?;
    // N5 — a package spec beginning with `-` is an option-injection vector.
    crate::primitives::spawn::reject_option_like("npm.deprecate.package", package)?;
    let message = op_args.get("message").and_then(Value::as_str).unwrap_or("");
    let mut cmd = crate::primitives::spawn::hardened_command("npm");
    cmd.arg("deprecate")
        .arg("--ignore-scripts")
        .arg("--")
        .arg(package)
        .arg(message);
    if let Some(s) = secret {
        cmd.env("NPM_TOKEN", s.as_str()?);
    }
    run_npm("deprecate", cmd).await
}

async fn read_metadata(op_args: &Value) -> KvendraResult<Value> {
    // Public read — no token required.
    let package = op_args
        .get("package")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("npm.read_metadata.package required".into()))?;
    let url = format!("https://registry.npmjs.org/{package}");
    let client = reqwest::Client::builder()
        .user_agent(concat!("kvendra/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let resp = client.get(&url).send().await?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    Ok(json!({
        "operation": "read_metadata",
        "status_code": status.as_u16(),
        "package": package,
        "metadata": body,
    }))
}

async fn run_npm(operation: &str, mut cmd: Command) -> KvendraResult<Value> {
    let output = cmd
        .output()
        .await
        .map_err(|_| KvendraError::PrimitiveFailed {
            primitive: "kvendra.npm".into(),
            operation: operation.into(),
        })?;
    Ok(json!({
        "operation": operation,
        "exit_code": output.status.code().unwrap_or_default(),
        "success": output.status.success(),
        "stdout_sanitized": sanitize(&output.stdout),
        "stderr_sanitized": sanitize(&output.stderr),
    }))
}

fn sanitize(bytes: &[u8]) -> String {
    crate::detection::sanitize_output(&String::from_utf8_lossy(bytes))
}
