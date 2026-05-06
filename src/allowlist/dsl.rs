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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSpec {
    pub profile_id: String,
    pub secret: SecretRef,
    pub allowlist: Allowlist,
    pub expiration: Option<String>,
    #[serde(default = "default_audit_level")]
    pub audit_level: String,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OperationConstraints {
    pub repos: Option<Vec<String>>,
    pub refs: Option<Vec<String>>,
    pub forbidden_args: Option<Vec<String>>,
    pub tag_pattern: Option<Vec<String>>,
    pub org: Option<Vec<String>>,
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
    pub endpoints: Option<Vec<String>>,
    pub accept_broad_scope: Option<bool>,
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
