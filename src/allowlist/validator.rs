//! Static validation of allowlist YAML — restrictive defaults.
//!
//! Implements REQ-KVD-002 AC-ALLOW-1: rejects profiles with empty `methods`
//! or wildcard `endpoints: ["*"]` without an explicit `accept_broad_scope`.

use crate::allowlist::catalog;
use crate::allowlist::dsl::{OperationConstraints, ProfileSpec};
use crate::error::{KvendraError, KvendraResult};

pub fn validate(spec: &ProfileSpec) -> KvendraResult<()> {
    if spec.profile_id.is_empty() {
        return Err(KvendraError::AllowlistParse("profile_id is empty".into()));
    }
    if spec.allowlist.primitives.is_empty() {
        return Err(KvendraError::AllowlistParse(
            "allowlist.primitives is empty (restrictive default rejects)".into(),
        ));
    }
    for prim in &spec.allowlist.primitives {
        if prim.name.is_empty() {
            return Err(KvendraError::AllowlistParse(
                "primitive name is empty".into(),
            ));
        }
        // Escape hatch: operations may be empty if unsafe_raw_token_allowed.
        if prim.name == "kvendra.unsafe.raw_token" {
            continue;
        }
        if prim.operations.is_empty() {
            return Err(KvendraError::AllowlistParse(format!(
                "primitive '{}' has no operations",
                prim.name
            )));
        }
        for op in &prim.operations {
            for (op_name, c) in op {
                check_constraints(&prim.name, op_name, c)?;
            }
        }
    }
    validate_destructive_opt_in(spec)?;
    Ok(())
}

/// REQ-KVD-004 — rechaza la allowlist si contiene operaciones destructive
/// (según el catálogo canónico OR `destructive: true` declarado por el user)
/// sin `accept_destructive: true` explícito.
///
/// Excepción: `kvendra.unsafe.raw_token` no entra aquí — su gate es
/// `unsafe_raw_token_allowed` + cuota per-session (REQ-KVD-002 AC-PRIM-3).
fn validate_destructive_opt_in(spec: &ProfileSpec) -> KvendraResult<()> {
    let mut violations = Vec::new();
    for prim in &spec.allowlist.primitives {
        if prim.name == "kvendra.unsafe.raw_token" {
            continue;
        }
        for op_map in &prim.operations {
            for (op_name, c) in op_map {
                let canonical_destructive = catalog::could_be_destructive(&prim.name, op_name, c);
                let user_declared = c.destructive.unwrap_or(false);
                let needs_opt_in = canonical_destructive || user_declared;
                let has_opt_in = c.accept_destructive.unwrap_or(false);
                if needs_opt_in && !has_opt_in {
                    violations.push(format!("{}.{op_name}", prim.name));
                }
            }
        }
    }
    if !violations.is_empty() {
        return Err(KvendraError::AllowlistParse(format!(
            "allowlist contains destructive operations without explicit opt-in:\n  - {}\n\nAdd 'accept_destructive: true' next to each operation to confirm intent.",
            violations.join("\n  - ")
        )));
    }
    Ok(())
}

fn check_constraints(primitive: &str, op: &str, c: &OperationConstraints) -> KvendraResult<()> {
    let accept_broad = c.accept_broad_scope.unwrap_or(false);

    if let Some(methods) = &c.methods
        && methods.is_empty()
        && !accept_broad
    {
        return Err(KvendraError::AllowlistParse(format!(
            "{primitive}.{op}: empty `methods` rejected without accept_broad_scope: true"
        )));
    }

    if let Some(endpoints) = &c.endpoints
        && endpoints.iter().any(|e| e == "*")
        && !accept_broad
    {
        return Err(KvendraError::AllowlistParse(format!(
            "{primitive}.{op}: wildcard `endpoints: [\"*\"]` rejected without accept_broad_scope"
        )));
    }

    // Extra-strict validation for `kvendra.http`: this primitive trades the
    // most blast radius. Reject empty `url_pattern_regex` (would allow any
    // URL) and obviously-broad regexes like `.*` without `accept_broad_scope`.
    if primitive == "kvendra.http" {
        match &c.url_pattern_regex {
            None => {
                if !accept_broad {
                    return Err(KvendraError::AllowlistParse(format!(
                        "{primitive}.{op}: url_pattern_regex required (or accept_broad_scope: true)"
                    )));
                }
            }
            Some(patterns) => {
                if patterns.is_empty() && !accept_broad {
                    return Err(KvendraError::AllowlistParse(format!(
                        "{primitive}.{op}: empty url_pattern_regex rejected"
                    )));
                }
                for pat in patterns {
                    let trimmed = pat.trim();
                    if (trimmed == ".*" || trimmed == "^.*$" || trimmed == ".+") && !accept_broad {
                        return Err(KvendraError::AllowlistParse(format!(
                            "{primitive}.{op}: wildcard regex '{pat}' rejected without accept_broad_scope"
                        )));
                    }
                    // Compile to validate well-formedness.
                    if regex::Regex::new(pat).is_err() {
                        return Err(KvendraError::AllowlistParse(format!(
                            "{primitive}.{op}: invalid url_pattern_regex '{pat}'"
                        )));
                    }
                }
            }
        }
        if c.methods.is_none() && !accept_broad {
            return Err(KvendraError::AllowlistParse(format!(
                "{primitive}.{op}: methods required (or accept_broad_scope: true)"
            )));
        }
    }
    Ok(())
}

/// Check whether a profile's expiration date is in the past.
/// Format: ISO-8601 date `YYYY-MM-DD` or full datetime; lenient on the format.
pub fn is_expired(spec: &ProfileSpec) -> bool {
    let Some(exp) = &spec.expiration else {
        return false;
    };
    let Ok(date) = time::Date::parse(
        exp.split('T').next().unwrap_or(exp),
        &time::macros::format_description!("[year]-[month]-[day]"),
    ) else {
        return false;
    };
    let now = time::OffsetDateTime::now_utc().date();
    date < now
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_profile_without_primitives() {
        let yaml = r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives: []
"#;
        let p = ProfileSpec::from_yaml(yaml).unwrap();
        assert!(validate(&p).is_err());
    }

    #[test]
    fn accepts_minimum_valid_profile() {
        // Post-REQ-KVD-004: kvendra.git.push está en el catálogo destructive,
        // así que requiere `accept_destructive: true` opt-in. Profile mínimo
        // válido se actualiza para reflejarlo.
        let yaml = r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - push:
            repos: ["github.com/foo/*"]
            accept_destructive: true
"#;
        let p = ProfileSpec::from_yaml(yaml).unwrap();
        assert!(validate(&p).is_ok());
    }

    #[test]
    fn rejects_wildcard_endpoint_without_accept_broad() {
        let yaml = r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.http
      operations:
        - request:
            endpoints: ["*"]
            methods: ["GET"]
            url_pattern_regex: ["^https://api\\.example\\.com/.*"]
"#;
        let p = ProfileSpec::from_yaml(yaml).unwrap();
        assert!(validate(&p).is_err());
    }

    #[test]
    fn http_requires_url_pattern() {
        let yaml = r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.http
      operations:
        - request:
            methods: ["GET"]
"#;
        let p = ProfileSpec::from_yaml(yaml).unwrap();
        assert!(
            validate(&p).is_err(),
            "http without url_pattern_regex must be rejected"
        );
    }

    #[test]
    fn http_rejects_dot_star_pattern() {
        let yaml = r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.http
      operations:
        - request:
            methods: ["GET"]
            url_pattern_regex: [".*"]
"#;
        let p = ProfileSpec::from_yaml(yaml).unwrap();
        assert!(validate(&p).is_err());
    }

    #[test]
    fn http_accepts_specific_pattern() {
        let yaml = r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.http
      operations:
        - request:
            methods: ["GET"]
            url_pattern_regex: ["^https://api\\.example\\.com/v1/.*"]
"#;
        let p = ProfileSpec::from_yaml(yaml).unwrap();
        assert!(validate(&p).is_ok());
    }

    #[test]
    fn rejects_s3_sync_destructive_without_opt_in() {
        let yaml = r#"
profile_id: x
secret:
  type: aws
allowlist:
  primitives:
    - name: kvendra.aws
      operations:
        - s3_sync:
            buckets: ["prod"]
"#;
        let p = ProfileSpec::from_yaml(yaml).unwrap();
        let err = validate(&p).expect_err("must reject without opt-in");
        let msg = err.to_string();
        assert!(msg.contains("kvendra.aws.s3_sync"), "got: {msg}");
        assert!(msg.contains("accept_destructive"), "got: {msg}");
    }

    #[test]
    fn accepts_s3_sync_destructive_with_opt_in() {
        let yaml = r#"
profile_id: x
secret:
  type: aws
allowlist:
  primitives:
    - name: kvendra.aws
      operations:
        - s3_sync:
            buckets: ["prod"]
            accept_destructive: true
"#;
        let p = ProfileSpec::from_yaml(yaml).unwrap();
        assert!(validate(&p).is_ok());
    }

    #[test]
    fn lists_all_violations_in_error_message() {
        let yaml = r#"
profile_id: x
secret:
  type: aws
allowlist:
  primitives:
    - name: kvendra.aws
      operations:
        - s3_sync:
            buckets: ["prod"]
        - s3_cp:
            buckets: ["prod"]
        - lambda_invoke:
            functions: ["fn-a"]
"#;
        let p = ProfileSpec::from_yaml(yaml).unwrap();
        let err = validate(&p).expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains("s3_sync"), "got: {msg}");
        assert!(msg.contains("s3_cp"), "got: {msg}");
        assert!(msg.contains("lambda_invoke"), "got: {msg}");
    }

    #[test]
    fn unsafe_raw_token_skipped_from_destructive_check() {
        // El catálogo lista kvendra.unsafe.raw_token como Destructive, pero
        // su gate es `unsafe_raw_token_allowed` (AC-PRIM-3). El validator
        // de destructive opt-in debe omitirlo para evitar doble friction.
        let yaml = r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.unsafe.raw_token
      unsafe_raw_token_allowed: true
"#;
        let p = ProfileSpec::from_yaml(yaml).unwrap();
        assert!(validate(&p).is_ok());
    }

    #[test]
    fn existing_readonly_profile_passes_validator() {
        // Reproduce el contenido canónico de
        // ~/.kvendra/allowlists/github.kvendraai.cli-readonly.yaml.
        let yaml = r#"
profile_id: github.kvendraai.cli-readonly
secret:
  type: github_pat
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - read_issue:
            repos: ["KvendraAI/kvendra-cli"]
        - read_repo:
            repos: ["KvendraAI/kvendra-cli"]
expiration: 2026-06-05
audit_level: full
"#;
        let p = ProfileSpec::from_yaml(yaml).unwrap();
        assert!(
            validate(&p).is_ok(),
            "existing readonly profile must keep passing post-REQ-KVD-004"
        );
    }

    #[test]
    fn http_request_with_post_method_requires_opt_in() {
        let yaml = r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.http
      operations:
        - request:
            url_pattern_regex: ["^https://api\\.example\\.com/.*"]
            methods: ["POST"]
"#;
        let p = ProfileSpec::from_yaml(yaml).unwrap();
        assert!(validate(&p).is_err());
    }

    #[test]
    fn http_request_with_only_get_does_not_require_opt_in() {
        let yaml = r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.http
      operations:
        - request:
            url_pattern_regex: ["^https://api\\.example\\.com/.*"]
            methods: ["GET"]
"#;
        let p = ProfileSpec::from_yaml(yaml).unwrap();
        assert!(validate(&p).is_ok());
    }
}
