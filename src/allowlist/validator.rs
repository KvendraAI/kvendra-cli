//! Static validation of allowlist YAML — restrictive defaults.
//!
//! Implements REQ-KVD-002 AC-ALLOW-1: rejects profiles with empty `methods`
//! or wildcard `endpoints: ["*"]` without an explicit `accept_broad_scope`.

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
}
