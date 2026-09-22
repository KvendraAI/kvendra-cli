//! `kvendra.aws` — AWS CLI broker (IF-KVD-CLI-005).
//!
//! Operations: `s3_sync`, `s3_cp`, `cloudfront_invalidate`, `lambda_invoke`.
//!
//! Credentials are injected via `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
//! and (optional) `AWS_SESSION_TOKEN` env vars in the child process. The
//! plaintext shape is `key_id:secret[:session_token]` (colon-separated)
//! when stored in a single-blob profile, or arbitrary JSON shape when the
//! caller wants to pass a structured secret. We accept either:
//!  - JSON `{ "access_key_id": "...", "secret_access_key": "...", "session_token": "..." }`
//!  - Colon-separated string `<id>:<secret>` or `<id>:<secret>:<token>`.

use crate::error::{KvendraError, KvendraResult};
use crate::vault::SecretPlaintext;
use serde_json::{Value, json};
use tokio::process::Command;

struct AwsCreds {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    region: Option<String>,
}

fn parse_creds(
    secret: Option<&SecretPlaintext>,
    region_arg: Option<&str>,
) -> KvendraResult<AwsCreds> {
    let s = match secret {
        Some(s) => s.as_str()?,
        None => {
            return Err(KvendraError::InvalidArgs(
                "aws primitive requires a secret (vault must be unlocked)".into(),
            ));
        }
    };
    if s.starts_with('{') {
        // JSON shape.
        let v: Value = serde_json::from_str(s)?;
        let access_key_id = v
            .get("access_key_id")
            .and_then(Value::as_str)
            .ok_or_else(|| KvendraError::InvalidArgs("aws secret: access_key_id missing".into()))?
            .to_string();
        let secret_access_key = v
            .get("secret_access_key")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                KvendraError::InvalidArgs("aws secret: secret_access_key missing".into())
            })?
            .to_string();
        let session_token = v
            .get("session_token")
            .and_then(Value::as_str)
            .map(str::to_string);
        let region = v
            .get("region")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| region_arg.map(str::to_string));
        Ok(AwsCreds {
            access_key_id,
            secret_access_key,
            session_token,
            region,
        })
    } else {
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        if parts.len() < 2 {
            return Err(KvendraError::InvalidArgs(
                "aws secret must be JSON or `key_id:secret[:session_token]`".into(),
            ));
        }
        Ok(AwsCreds {
            access_key_id: parts[0].to_string(),
            secret_access_key: parts[1].to_string(),
            session_token: parts.get(2).map(|s| (*s).to_string()),
            region: region_arg.map(str::to_string),
        })
    }
}

pub async fn execute(args: &Value, secret: Option<&SecretPlaintext>) -> KvendraResult<Value> {
    let operation = args
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("operation missing".into()))?;
    let op_args = args.get("args").cloned().unwrap_or(Value::Null);
    let region = op_args
        .get("region")
        .and_then(Value::as_str)
        .map(str::to_string);
    let creds = parse_creds(secret, region.as_deref())?;

    match operation {
        "s3_sync" => s3_sync(&op_args, &creds).await,
        "s3_cp" => s3_cp(&op_args, &creds).await,
        "cloudfront_invalidate" => cloudfront_invalidate(&op_args, &creds).await,
        "lambda_invoke" => lambda_invoke(&op_args, &creds).await,
        other => Err(KvendraError::InvalidArgs(format!(
            "unsupported aws operation '{other}'"
        ))),
    }
}

fn aws_command(creds: &AwsCreds) -> Command {
    // Hardened spawn: sensitive KVENDRA_* env stripped (N1), PATH sanitised
    // (A2), stdin detached (ISSUE-KVD-CLI-330251), stdout/stderr piped. The
    // credential env vars are added AFTER the scrub so they survive.
    let mut cmd = crate::primitives::spawn::hardened_command("aws");
    cmd.env("AWS_ACCESS_KEY_ID", &creds.access_key_id)
        .env("AWS_SECRET_ACCESS_KEY", &creds.secret_access_key);
    if let Some(t) = &creds.session_token {
        cmd.env("AWS_SESSION_TOKEN", t);
    }
    if let Some(r) = &creds.region {
        cmd.env("AWS_REGION", r).env("AWS_DEFAULT_REGION", r);
    }
    cmd
}

fn classify_operand(field: &str, v: &str) -> KvendraResult<()> {
    crate::primitives::local_operand::classify_s3_operand(v)
        .map(|_| ())
        .map_err(|e| KvendraError::InvalidArgs(format!("{field}: {e}")))
}

async fn s3_sync(op_args: &Value, creds: &AwsCreds) -> KvendraResult<Value> {
    let src = op_args
        .get("src")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("aws.s3_sync.src required".into()))?;
    let dst = op_args
        .get("dst")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("aws.s3_sync.dst required".into()))?;
    // N5 — reject option-injection (e.g. src=`--endpoint-url=http://evil/`).
    crate::primitives::spawn::reject_option_like("aws.s3_sync.src", src)?;
    crate::primitives::spawn::reject_option_like("aws.s3_sync.dst", dst)?;
    // Same classifier as the enforcer (ISSUE-KVD-CLI-9D5CF5): a malformed
    // remote is never handed to the CLI as if it were a local path.
    classify_operand("aws.s3_sync.src", src)?;
    classify_operand("aws.s3_sync.dst", dst)?;
    let delete = op_args
        .get("delete")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut cmd = aws_command(creds);
    cmd.args(s3_transfer_argv("sync", src, dst, delete));
    run("s3_sync", cmd).await
}

async fn s3_cp(op_args: &Value, creds: &AwsCreds) -> KvendraResult<Value> {
    let src = op_args
        .get("src")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("aws.s3_cp.src required".into()))?;
    let dst = op_args
        .get("dst")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("aws.s3_cp.dst required".into()))?;
    // N5 — reject option-injection on the positional src/dst.
    crate::primitives::spawn::reject_option_like("aws.s3_cp.src", src)?;
    crate::primitives::spawn::reject_option_like("aws.s3_cp.dst", dst)?;
    // Same classifier as the enforcer (ISSUE-KVD-CLI-9D5CF5): a malformed
    // remote is never handed to the CLI as if it were a local path.
    classify_operand("aws.s3_cp.src", src)?;
    classify_operand("aws.s3_cp.dst", dst)?;
    let mut cmd = aws_command(creds);
    cmd.args(s3_transfer_argv("cp", src, dst, false));
    run("s3_cp", cmd).await
}

/// argv for `aws s3 <sync|cp>` (after the `aws` binary).
///
/// `--no-follow-symlinks` is ALWAYS passed (SA2 residual,
/// ISSUE-KVD-CLI-9D5CF5): the enforcer canonicalises only the top-level local
/// operand against the declared `local_roots`, but the AWS CLI follows
/// symlinks while walking a local source by default, so a symlink planted
/// under an allowed root would upload files from outside it. The flag is a
/// documented option of `s3 cp`/`s3 sync` that governs local-source walking;
/// for downloads and S3→S3 copies it is a no-op, so passing it
/// unconditionally keeps the argv valid and fails closed.
fn s3_transfer_argv(verb: &str, src: &str, dst: &str, delete: bool) -> Vec<String> {
    let mut argv = vec![
        "s3".to_string(),
        verb.to_string(),
        src.to_string(),
        dst.to_string(),
        "--no-follow-symlinks".to_string(),
    ];
    if delete {
        argv.push("--delete".to_string());
    }
    argv
}

async fn cloudfront_invalidate(op_args: &Value, creds: &AwsCreds) -> KvendraResult<Value> {
    let distribution_id = op_args
        .get("distribution_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            KvendraError::InvalidArgs("aws.cloudfront_invalidate.distribution_id required".into())
        })?;
    crate::primitives::spawn::reject_option_like(
        "aws.cloudfront_invalidate.distribution_id",
        distribution_id,
    )?;
    let paths_default = vec![Value::String("/*".into())];
    let paths = op_args
        .get("paths")
        .and_then(Value::as_array)
        .unwrap_or(&paths_default);
    let mut cmd = aws_command(creds);
    cmd.arg("cloudfront")
        .arg("create-invalidation")
        .arg("--distribution-id")
        .arg(distribution_id)
        .arg("--paths");
    for p in paths {
        if let Some(s) = p.as_str() {
            // Each path is agent-controlled and appended after `--paths` with no
            // `--` terminator (the AWS CLI treats a later `--endpoint-url=…` /
            // `--profile …` as a GLOBAL option → SSRF / redirect). Reject any
            // path shaped like an option. (N5 was applied to distribution_id but
            // not to these path elements.)
            crate::primitives::spawn::reject_option_like("aws.cloudfront_invalidate.paths", s)?;
            cmd.arg(s);
        }
    }
    run("cloudfront_invalidate", cmd).await
}

async fn lambda_invoke(op_args: &Value, creds: &AwsCreds) -> KvendraResult<Value> {
    let function = op_args
        .get("function_name")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            KvendraError::InvalidArgs("aws.lambda_invoke.function_name required".into())
        })?;
    crate::primitives::spawn::reject_option_like("aws.lambda_invoke.function_name", function)?;
    let payload = op_args
        .get("payload")
        .map(|v| v.to_string())
        .unwrap_or_else(|| "{}".to_string());
    let mut cmd = aws_command(creds);
    cmd.arg("lambda")
        .arg("invoke")
        .arg("--function-name")
        .arg(function)
        .arg("--payload")
        .arg(payload)
        .arg("/dev/stdout");
    run("lambda_invoke", cmd).await
}

async fn run(operation: &str, mut cmd: Command) -> KvendraResult<Value> {
    let output = cmd
        .output()
        .await
        .map_err(|_| KvendraError::PrimitiveFailed {
            primitive: "kvendra.aws".into(),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// SA2 residual (ISSUE-KVD-CLI-9D5CF5): symlinks inside a declared local
    /// root must never be followed by the AWS CLI walker.
    #[test]
    fn s3_sync_and_cp_always_pass_no_follow_symlinks() {
        for (verb, src, dst, delete) in [
            ("sync", "/work/site", "s3://bucket/prefix", false),
            ("sync", "/work/site", "s3://bucket/prefix", true),
            ("sync", "s3://bucket/prefix", "/work/site", false),
            ("cp", "/work/file.txt", "s3://bucket/file.txt", false),
            ("cp", "s3://bucket/file.txt", "/work/file.txt", false),
        ] {
            let argv = s3_transfer_argv(verb, src, dst, delete);
            assert_eq!(&argv[..4], ["s3", verb, src, dst], "{argv:?}");
            assert_eq!(
                argv.iter().filter(|a| *a == "--no-follow-symlinks").count(),
                1,
                "{argv:?}"
            );
            assert!(!argv.iter().any(|a| a == "--follow-symlinks"), "{argv:?}");
            assert_eq!(argv.iter().any(|a| a == "--delete"), delete, "{argv:?}");
        }
    }
}
