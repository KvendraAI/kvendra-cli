//! YAML DSL types for per-profile allowlists.
//!
//! Example (REQ-KVD-002 Bloque 5):
//! ```yaml
//! profile_id: github.kvendraai.org-admin
//! secret:
//!   type: github_pat
//!   encrypted_blob_b64: "<base64 ciphertext header>"
//! allowlist:
//!   primitives:
//!     - name: kvendra.git
//!       operations:
//!         - clone:
//!             repos: ["github.com/KvendraAI/*"]
//!         - push:
//!             repos: ["github.com/KvendraAI/*"]
//!             refs: ["refs/heads/main"]
//! expiration: 2026-08-04
//! audit_level: full
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApprovalProfileOverride {
    /// Override del modo de approval per-profile. Acepta `silent`, `ask` o
    /// `ask-destructive`. Aplica sólo a este profile; resto sigue el global.
    pub mode: Option<String>,
}

// `deny_unknown_fields` on every DSL struct (ISSUE-KVD-CLI-1B6440): an
// unknown key used to be silently dropped by serde, so a schema typo
// (`args_exact` instead of `args_constraints`) signed an allowlist LAXER
// than the owner wrote — the inversion of fail-closed. Unknown keys are now
// a hard parse error at sign time (`secret set-allowlist`), at validate
// time, and at broker runtime load (defense in depth).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSpec {
    pub profile_id: String,
    pub secret: SecretRef,
    pub allowlist: Allowlist,
    pub expiration: Option<String>,
    #[serde(default = "default_audit_level")]
    pub audit_level: String,
    /// Override del modo de approval per-profile (REQ-KVD-003).
    #[serde(default)]
    pub approval: Option<ApprovalProfileOverride>,
}

fn default_audit_level() -> String {
    "full".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    #[serde(rename = "type")]
    pub kind: String,
    pub encrypted_blob_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowlist {
    pub primitives: Vec<PrimitiveAllow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrimitiveAllow {
    pub name: String,
    #[serde(default)]
    pub operations: Vec<Operation>,
    /// Escape hatch toggle (only meaningful for `kvendra.unsafe.raw_token`).
    #[serde(default)]
    pub unsafe_raw_token_allowed: bool,
    #[serde(default = "default_unsafe_max")]
    pub unsafe_max_uses_per_session: u32,
    #[serde(default = "default_reason_min")]
    pub unsafe_reason_min_length: u32,
}

fn default_unsafe_max() -> u32 {
    1
}
fn default_reason_min() -> u32 {
    10
}

/// An `Operation` is a single-key map: `{ "<op_name>": <constraints> }`.
/// We model it as `BTreeMap<String, OperationConstraints>` to allow YAML
/// shape `- push: { repos: [...] }`.
pub type Operation = BTreeMap<String, OperationConstraints>;

/// Per-operation constraints. The semantics of every field below are enforced
/// at runtime by [`crate::allowlist::enforcer::check`] against the canonical
/// MCP envelope `{profile_id, operation, args:{...}}`.
///
/// # Decision register (D1..D8 — see also `enforcer.rs` module doc)
///
/// - **D1** `repo` (singular) is a literal-list alias for `repos` and unions
///   with it (any-match, glob-style).
/// - **D2** `args_constraints` is an array of allowed argv templates; the
///   call's argv must match at least one template (any-match, strict length).
/// - **D3** `forbidden_env_export_to_agent` denies env keys requested by the
///   call BEFORE any exec. Defense-in-depth doubled with the existing scrub
///   layer that sanitises env going OUT to the agent.
/// - **D4** `forbidden_methods` AND'ed with `methods` (denylist beats
///   allowlist; fail-closed — even if `methods` allows it).
/// - **D5** `buckets` extracts the bucket name from the leading `s3://NAME/...`
///   URI; bare bucket names also accepted.
/// - **D6** `endpoints` is a literal exact-match alias for HTTP urls,
///   union'd with `url_pattern_regex` (any-match).
/// - **D7** `accept_broad_scope` is checked at validator time only — never
///   in the enforcer.
/// - **D8** Order of checks in the enforcer:
///   `is_expired → primitive lookup → operation lookup → forbidden-first
///   denylists → allow-list constraints`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OperationConstraints {
    pub repos: Option<Vec<String>>,
    pub refs: Option<Vec<String>>,
    pub forbidden_args: Option<Vec<String>>,
    pub tag_pattern: Option<Vec<String>>,
    pub org: Option<Vec<String>>,
    /// Singular alias for [`OperationConstraints::repos`] (D1 — union semantics).
    pub repo: Option<Vec<String>>,
    pub fields_allowed: Option<Vec<String>>,
    pub forbidden_fields: Option<Vec<String>>,
    pub binaries: Option<Vec<String>>,
    pub args_constraints: Option<Vec<ArgvConstraint>>,
    pub cwd_pattern: Option<String>,
    pub env_vars_to_inject: Option<Vec<String>>,
    pub forbidden_env_export_to_agent: Option<Vec<String>>,
    pub url_pattern_regex: Option<Vec<String>>,
    pub methods: Option<Vec<String>>,
    pub forbidden_methods: Option<Vec<String>>,
    pub buckets: Option<Vec<String>>,
    pub distributions: Option<Vec<String>>,
    pub functions: Option<Vec<String>>,
    pub packages: Option<Vec<String>>,
    pub projects: Option<Vec<String>>,
    /// Literal exact-match alias for HTTP url checks (D6 — union'd with
    /// `url_pattern_regex`).
    pub endpoints: Option<Vec<String>>,
    /// Validator-time gate (D7 — NOT enforced at runtime). Marks an
    /// allowlist as opting in to broad-scope patterns at YAML load.
    pub accept_broad_scope: Option<bool>,
    /// Marca explícita de operación destructiva (REQ-KVD-003). Cuando es
    /// `true`, modo `ask-destructive` dispara prompt. Ausencia = `false`.
    pub destructive: Option<bool>,
    /// Opt-in del owner para ejecutar una operación marcada `Destructive`
    /// por el catálogo canónico (REQ-KVD-004 / ADR-KVD-017). Ausencia →
    /// `false` → la allowlist es rechazada al `secret set-allowlist`.
    pub accept_destructive: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgvConstraint {
    pub allowed: Vec<String>,
}

impl ProfileSpec {
    pub fn from_yaml(s: &str) -> Result<Self, serde_yaml_ng::Error> {
        serde_yaml_ng::from_str(s)
    }

    pub fn to_yaml(&self) -> Result<String, serde_yaml_ng::Error> {
        serde_yaml_ng::to_string(self)
    }
}

/// Every field name accepted anywhere in the allowlist DSL. Keep in sync
/// with the structs above — used only to build "did you mean" hints
/// (ISSUE-KVD-CLI-1B6440), never for enforcement.
const KNOWN_FIELDS: &[&str] = &[
    // ProfileSpec
    "profile_id",
    "secret",
    "allowlist",
    "expiration",
    "audit_level",
    "approval",
    // SecretRef
    "type",
    "encrypted_blob_b64",
    // Allowlist / PrimitiveAllow
    "primitives",
    "name",
    "operations",
    "unsafe_raw_token_allowed",
    "unsafe_max_uses_per_session",
    "unsafe_reason_min_length",
    // ApprovalProfileOverride
    "mode",
    // ArgvConstraint
    "allowed",
    // OperationConstraints
    "repos",
    "refs",
    "forbidden_args",
    "tag_pattern",
    "org",
    "repo",
    "fields_allowed",
    "forbidden_fields",
    "binaries",
    "args_constraints",
    "cwd_pattern",
    "env_vars_to_inject",
    "forbidden_env_export_to_agent",
    "url_pattern_regex",
    "methods",
    "forbidden_methods",
    "buckets",
    "distributions",
    "functions",
    "packages",
    "projects",
    "endpoints",
    "accept_broad_scope",
    "destructive",
    "accept_destructive",
];

/// Closest known DSL field for an unknown key, by longest common prefix
/// (>= 4 shared leading chars). Catches the real-world pairs that signed a
/// laxer allowlist (`args_exact` → `args_constraints`, `cwd_allowed` →
/// `cwd_pattern`) without pulling an edit-distance dependency.
pub fn suggest_known_field(unknown: &str) -> Option<&'static str> {
    let mut best: Option<(&'static str, usize)> = None;
    for &known in KNOWN_FIELDS {
        let lcp = unknown
            .bytes()
            .zip(known.bytes())
            .take_while(|(a, b)| a == b)
            .count();
        if lcp >= 4 && best.is_none_or(|(_, b)| lcp > b) {
            best = Some((known, lcp));
        }
    }
    best.map(|(k, _)| k)
}

/// Extract the offending key from a serde "unknown field `X`, ..." message
/// and pair it with the closest known DSL field, if any.
pub fn unknown_field_hint(err_msg: &str) -> Option<(String, &'static str)> {
    const MARKER: &str = "unknown field `";
    let start = err_msg.find(MARKER)? + MARKER.len();
    let rest = &err_msg[start..];
    let unknown = &rest[..rest.find('`')?];
    suggest_known_field(unknown).map(|s| (unknown.to_string(), s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_yaml() {
        let yaml = r#"
profile_id: github.example
secret:
  type: github_pat
  encrypted_blob_b64: "Zm9v"
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - clone:
            repos: ["github.com/example/*"]
        - push:
            repos: ["github.com/example/*"]
            refs: ["refs/heads/main"]
expiration: "2026-12-31"
audit_level: full
"#;
        let p = ProfileSpec::from_yaml(yaml).unwrap();
        assert_eq!(p.profile_id, "github.example");
        assert_eq!(p.allowlist.primitives.len(), 1);
        assert_eq!(p.allowlist.primitives[0].operations.len(), 2);
    }

    #[test]
    fn round_trip_yaml() {
        let yaml = r#"
profile_id: test
secret:
  type: api_token
allowlist:
  primitives:
    - name: kvendra.http
      operations:
        - request:
            url_pattern_regex: ["^https://api\\.example\\.com/.*"]
            methods: ["GET"]
"#;
        let p = ProfileSpec::from_yaml(yaml).unwrap();
        let out = p.to_yaml().unwrap();
        let p2 = ProfileSpec::from_yaml(&out).unwrap();
        assert_eq!(p2.profile_id, "test");
    }

    // -----------------------------------------------------------------
    // BLOQUE — deny_unknown_fields (ISSUE-KVD-CLI-1B6440). El fixture del
    // primer test es literalmente la clase de YAML que firmó una allowlist
    // sin constraint de argv/cwd en el caso EF451D.
    // -----------------------------------------------------------------

    #[test]
    fn unknown_field_args_exact_rejected() {
        let yaml = r#"
profile_id: aws.kvendra.staging-deploy
secret:
  type: generic
allowlist:
  primitives:
    - name: kvendra.shell
      operations:
        - exec:
            binaries: ["sam"]
            args_exact:
              - ["deploy", "--profile", "aws_kvendra"]
            destructive: true
            accept_destructive: true
"#;
        let err = ProfileSpec::from_yaml(yaml).unwrap_err().to_string();
        assert!(err.contains("unknown field"), "got: {err}");
        assert!(err.contains("args_exact"), "got: {err}");
    }

    #[test]
    fn unknown_field_cwd_allowed_rejected() {
        let yaml = r#"
profile_id: x
secret:
  type: generic
allowlist:
  primitives:
    - name: kvendra.shell
      operations:
        - exec:
            binaries: ["sam"]
            cwd_allowed: ["/tmp"]
"#;
        let err = ProfileSpec::from_yaml(yaml).unwrap_err().to_string();
        assert!(err.contains("unknown field"), "got: {err}");
        assert!(err.contains("cwd_allowed"), "got: {err}");
    }

    #[test]
    fn unknown_field_top_level_rejected() {
        let yaml = r#"
profile_id: x
secret:
  type: generic
allowlist:
  primitives: []
expirations: "2026-12-31"
"#;
        let err = ProfileSpec::from_yaml(yaml).unwrap_err().to_string();
        assert!(err.contains("unknown field"), "got: {err}");
        assert!(err.contains("expirations"), "got: {err}");
    }

    #[test]
    fn suggest_known_field_pairs() {
        assert_eq!(suggest_known_field("args_exact"), Some("args_constraints"));
        assert_eq!(suggest_known_field("cwd_allowed"), Some("cwd_pattern"));
        assert_eq!(suggest_known_field("expirations"), Some("expiration"));
        assert_eq!(suggest_known_field("zzz"), None);
    }

    #[test]
    fn unknown_field_hint_extracts_key() {
        let msg = "allowlist.primitives[0].operations[0].exec: unknown field `args_exact`, expected one of `repos`, `refs`";
        let (unknown, suggestion) = unknown_field_hint(msg).unwrap();
        assert_eq!(unknown, "args_exact");
        assert_eq!(suggestion, "args_constraints");
        assert!(unknown_field_hint("some other parse error").is_none());
    }
}
