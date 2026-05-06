//! Runtime enforcer — given a parsed `ProfileSpec`, check whether a
//! `(primitive, operation, args)` tuple is authorized.
//!
//! Returns `Ok(())` on allow, `Err(KvendraError::AllowlistViolation)` on
//! deny (REQ-KVD-002 AC-PRIM-2). Expired profiles return `ProfileExpired`
//! before any other check (AC-ALLOW-3).

use crate::allowlist::dsl::{OperationConstraints, ProfileSpec};
use crate::allowlist::validator::is_expired;
use crate::error::{KvendraError, KvendraResult};
use serde_json::Value;

/// Authorize a call against a profile's allowlist.
pub fn check(
    spec: &ProfileSpec,
    primitive: &str,
    operation: &str,
    args: &Value,
) -> KvendraResult<()> {
    if is_expired(spec) {
        return Err(KvendraError::ProfileExpired);
    }
    let prim = spec
        .allowlist
        .primitives
        .iter()
        .find(|p| p.name == primitive)
        .ok_or_else(|| {
            KvendraError::AllowlistViolation(format!("primitive '{primitive}' not allowed"))
        })?;

    // Escape hatch is checked by the primitive itself.
    if primitive == "kvendra.unsafe.raw_token" {
        if !prim.unsafe_raw_token_allowed {
            return Err(KvendraError::UnsafeNotEnabled);
        }
        return Ok(());
    }

    // Operation must appear in the per-primitive list.
    let constraints = prim
        .operations
        .iter()
        .flat_map(|m| m.iter())
        .find(|(name, _)| name.as_str() == operation)
        .map(|(_, c)| c)
        .ok_or_else(|| {
            KvendraError::AllowlistViolation(format!(
                "operation '{primitive}.{operation}' not in allowlist"
            ))
        })?;

    check_args(primitive, operation, constraints, args)
}

fn check_args(
    primitive: &str,
    operation: &str,
    c: &OperationConstraints,
    args: &Value,
) -> KvendraResult<()> {
    // Forbidden args (e.g. --force on git push).
    if let Some(forbidden) = &c.forbidden_args
        && let Some(argv) = args.get("argv").and_then(Value::as_array)
    {
        for a in argv {
            if let Some(s) = a.as_str()
                && forbidden.iter().any(|f| f == s)
            {
                return Err(KvendraError::AllowlistViolation(format!(
                    "{primitive}.{operation}: forbidden arg '{s}'"
                )));
            }
        }
    }

    // HTTP methods.
    if let Some(methods) = &c.methods
        && let Some(m) = args.get("method").and_then(Value::as_str)
        && !methods
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(m))
    {
        return Err(KvendraError::AllowlistViolation(format!(
            "{primitive}.{operation}: method '{m}' not allowed"
        )));
    }

    // Repos: simple glob "github.com/Foo/*" matches "github.com/Foo/bar".
    if let Some(repos) = &c.repos
        && let Some(repo) = args.get("repo").and_then(Value::as_str)
        && !repos.iter().any(|pat| glob_match(pat, repo))
    {
        return Err(KvendraError::AllowlistViolation(format!(
            "{primitive}.{operation}: repo '{repo}' not allowed"
        )));
    }

    Ok(())
}

/// Minimalist `*` glob: `prefix/*` matches anything with `prefix/`.
fn glob_match(pattern: &str, candidate: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/*") {
        candidate.starts_with(prefix) && candidate.len() > prefix.len()
    } else {
        pattern == candidate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_with(yaml: &str) -> ProfileSpec {
        ProfileSpec::from_yaml(yaml).unwrap()
    }

    #[test]
    fn allow_listed_op_passes() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - push:
            repos: ["github.com/Foo/*"]
"#,
        );
        let args = serde_json::json!({ "repo": "github.com/Foo/bar" });
        assert!(check(&s, "kvendra.git", "push", &args).is_ok());
    }

    #[test]
    fn forbidden_arg_blocks() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - push:
            repos: ["github.com/Foo/*"]
            forbidden_args: ["--force"]
"#,
        );
        let args = serde_json::json!({
            "repo": "github.com/Foo/bar",
            "argv": ["push", "--force"]
        });
        assert!(check(&s, "kvendra.git", "push", &args).is_err());
    }

    #[test]
    fn unknown_primitive_violates() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - push:
            repos: ["github.com/Foo/*"]
"#,
        );
        assert!(check(&s, "kvendra.aws", "s3_sync", &serde_json::json!({})).is_err());
    }
}
