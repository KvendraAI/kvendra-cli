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
#[serde(default)]
pub struct ApprovalProfileOverride {
    /// Override del modo de approval per-profile. Acepta `silent`, `ask` o
    /// `ask-destructive`. Aplica sólo a este profile; resto sigue el global.
    pub mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct SecretRef {
    #[serde(rename = "type")]
    pub kind: String,
    pub encrypted_blob_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Allowlist {
    pub primitives: Vec<PrimitiveAllow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[serde(default)]
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
pub struct ArgvConstraint {
    pub allowed: Vec<String>,
}

impl ProfileSpec {
    pub fn from_yaml(s: &str) -> Result<Self, serde_yml::Error> {
        serde_yml::from_str(s)
    }

    pub fn to_yaml(&self) -> Result<String, serde_yml::Error> {
        serde_yml::to_string(self)
    }
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
}
