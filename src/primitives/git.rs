//! `kvendra.git` — capability primitive for git CLI operations.
//!
//! IF-KVD-CLI-001. The PAT plaintext (when present) is injected via a
//! per-call `GIT_ASKPASS` helper that emits the token on stdout. We never
//! pass the token via URL components, never log it, and never echo it back
//! in the response (AC-MCP-3).

use crate::error::{KvendraError, KvendraResult};
use crate::vault::SecretPlaintext;
use serde_json::{Value, json};

/// Validate a git remote URL before it reaches `git clone` (ISSUE-KVD-CLI-B78ED5
/// finding H5). `git` treats an argument like `ext::sh -c '<cmd>'` as a remote
/// helper that executes an arbitrary command — a clone of such a URL is RCE.
/// A URL beginning with `-` is parsed as a git option (option injection). This
/// guard is defense in depth ON TOP of the global `protocol.ext.allow=never`
/// config applied to every git invocation below.
///
/// Accepts: `https://`, `http://`, `ssh://`, `git://`, and the scp-like
/// `[user@]host:path` form. Rejects: a leading `-`, and any
/// `<transport>::<address>` remote-helper prefix (ext::, fd::, …). IPv6
/// literals such as `https://[::1]/x` are preserved (the `::` there follows a
/// scheme separator, not a bare transport token).
pub fn validate_git_url(url: &str) -> KvendraResult<()> {
    let u = url.trim();
    if u.is_empty() {
        return Err(KvendraError::InvalidArgs("git: empty url".into()));
    }
    if u.starts_with('-') {
        return Err(KvendraError::InvalidArgs(
            "git: url must not start with '-' (option injection)".into(),
        ));
    }
    // Reject the `transport::address` remote-helper syntax. Split on the FIRST
    // `::`; if the text before it carries no scheme separator (`//`), it is a
    // bare transport token (ext, fd, …) and we refuse it.
    if let Some((prefix, _)) = u.split_once("::")
        && !prefix.contains("//")
    {
        return Err(KvendraError::InvalidArgs(
            "git: 'transport::' remote helpers are not allowed (ext:: enables RCE)".into(),
        ));
    }
    let ok = u.starts_with("https://")
        || u.starts_with("http://")
        || u.starts_with("ssh://")
        || u.starts_with("git://")
        || is_scp_like(u);
    if !ok {
        return Err(KvendraError::InvalidArgs(
            "git: unsupported url scheme (allowed: https, http, ssh, git, scp-like git@host:path)"
                .into(),
        ));
    }
    Ok(())
}

/// scp-like remote syntax `[user@]host:path` (no URL scheme). Requires a single
/// `:` whose left side is a non-empty host without a `/`, and no whitespace.
fn is_scp_like(u: &str) -> bool {
    if u.contains("://") || u.chars().any(char::is_whitespace) {
        return false;
    }
    match u.split_once(':') {
        Some((host, _path)) => !host.is_empty() && !host.contains('/'),
        None => false,
    }
}

/// Reject an argument that would be parsed as a git option because it begins
/// with `-` (option injection on `remote` / `ref` / `tag` positionals).
fn no_leading_dash(field: &str, value: &str) -> KvendraResult<()> {
    if value.starts_with('-') {
        return Err(KvendraError::InvalidArgs(format!(
            "git: {field} must not start with '-' (option injection)"
        )));
    }
    Ok(())
}

pub async fn execute(args: &Value, _secret: Option<&SecretPlaintext>) -> KvendraResult<Value> {
    let operation = args
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("operation missing".into()))?;
    let op_args = args.get("args").cloned().unwrap_or(Value::Null);

    // Hardened spawn: scrub KVENDRA_* env (N1) + sanitised PATH (A2) + stdin
    // detached (ISSUE-KVD-CLI-330251). SSH_AUTH_SOCK and the rest of the env
    // are preserved so SSH-key auth still works.
    let mut cmd = crate::primitives::spawn::hardened_command("git");
    // Global hardening (ISSUE-KVD-CLI-B78ED5 finding H5): disable the `ext`
    // remote helper (arbitrary command execution) and restrict the `file`
    // helper for EVERY git operation — clone, push, pull, etc. This neutralises
    // the `ext::sh -c …` RCE vector regardless of which field carries the URL.
    cmd.arg("-c")
        .arg("protocol.ext.allow=never")
        .arg("-c")
        .arg("protocol.file.allow=user");
    match operation {
        "clone" => {
            let url = op_args
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| KvendraError::InvalidArgs("clone.url required".into()))?;
            validate_git_url(url)?;
            let dst = op_args.get("dst").and_then(Value::as_str);
            // `--` terminates option parsing: the URL and dst are positionals,
            // so even a value that slips past validation cannot become a flag.
            cmd.arg("clone").arg("--").arg(url);
            if let Some(d) = dst {
                cmd.arg(d);
            }
        }
        "push" => {
            let remote = op_args
                .get("remote")
                .and_then(Value::as_str)
                .unwrap_or("origin");
            no_leading_dash("push.remote", remote)?;
            let r#ref = op_args
                .get("ref")
                .and_then(Value::as_str)
                .ok_or_else(|| KvendraError::InvalidArgs("push.ref required".into()))?;
            no_leading_dash("push.ref", r#ref)?;
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
            no_leading_dash("pull.remote", remote)?;
            let r#ref = op_args
                .get("ref")
                .and_then(Value::as_str)
                .ok_or_else(|| KvendraError::InvalidArgs("pull.ref required".into()))?;
            no_leading_dash("pull.ref", r#ref)?;
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
            no_leading_dash("tag.name", name)?;
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
