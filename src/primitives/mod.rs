//! Capability primitives — the 7 canonical brokers + escape hatch.
//!
//! Each primitive is a small async free function. Pase B-and-on signature:
//! `execute(args: &Value, secret: Option<&SecretPlaintext>) -> KvendraResult<Value>`.
//! The MCP dispatcher loads the profile-bound secret from the unlocked
//! vault and passes it in (ZeroizeOnDrop wraps it for the call duration).
//!
//! AC-MCP-3 invariant: no primitive embeds the plaintext in the JSON
//! response. Documented exception: `kvendra.unsafe.raw_token` (IF-KVD-CLI-008).

pub mod aws;
pub mod git;
pub mod github;
pub mod http;
pub mod npm;
pub mod pypi;
pub mod shell;
pub mod unsafe_raw_token;

use serde_json::{Value, json};

/// Static metadata for a primitive (used by the catalog, `tools/list` and
/// the `kvendra primitive list` CLI).
pub struct PrimitiveInfo {
    pub name: &'static str,
    pub summary: &'static str,
    pub operations: &'static [&'static str],
    pub is_unsafe: bool,
    /// REQ-KVD-005 fix B — multi-line description con args expected per
    /// operation. Se concatena al `summary` en `tools_list_description` para
    /// que el LLM consume directo desde `tools/list` sin tener que adivinar
    /// la shape de `args` (cierra el retry pattern documentado en
    /// ISSUE-KVD-CLI-014). Empty string si no hay doc adicional.
    pub operations_doc: &'static str,
}

impl PrimitiveInfo {
    pub fn tools_list_description(&self) -> String {
        let head = if self.is_unsafe {
            format!("[UNSAFE] {}", self.summary)
        } else {
            self.summary.to_string()
        };
        if self.operations_doc.is_empty() {
            head
        } else {
            format!("{head}\n\n{}", self.operations_doc)
        }
    }

    /// JSON Schema for the `arguments` field of a `tools/call`.
    pub fn input_schema(&self) -> Value {
        if self.is_unsafe {
            json!({
                "type": "object",
                "properties": {
                    "profile_id": { "type": "string" },
                    "reason": { "type": "string", "description": "Why the unsafe escape hatch is needed (audit-logged)." },
                },
                "required": ["profile_id", "reason"],
            })
        } else {
            json!({
                "type": "object",
                "properties": {
                    "profile_id": {
                        "type": "string",
                        "description": "Stored credential profile id."
                    },
                    "operation": {
                        "type": "string",
                        "enum": self.operations,
                        "description": "Sub-operation. See description for args shape per operation."
                    },
                    "args": {
                        "type": "object",
                        "description": "Operation-specific arguments. Shape varies per operation; see the description."
                    },
                },
                "required": ["profile_id", "operation", "args"],
            })
        }
    }
}

/// Catalog of capability primitives exposed via MCP `tools/list`.
pub fn catalog() -> &'static [PrimitiveInfo] {
    &CATALOG
}

const CATALOG: [PrimitiveInfo; 8] = [
    PrimitiveInfo {
        name: "kvendra.git",
        summary: "Run git operations (clone/push/pull/commit/tag) using a stored credential profile. Token plaintext never returned.",
        operations: &["clone", "push", "pull", "commit", "tag"],
        is_unsafe: false,
        operations_doc: "Operations:\n  clone:  args: { url: \"<git url>\", dst?: \"<path>\" }\n  push:   args: { cwd: \"<path>\", remote?: \"origin\", ref: \"refs/heads/<branch>\" }\n  pull:   args: { cwd: \"<path>\", remote?: \"origin\", ref: \"refs/heads/<branch>\" }\n  commit: args: { cwd: \"<path>\", message: \"<msg>\" }\n  tag:    args: { cwd: \"<path>\", name: \"<tag>\", message?: \"<msg>\" }\nAll operations require profile_id at the top level.",
    },
    PrimitiveInfo {
        name: "kvendra.github",
        summary: "GitHub REST/GraphQL operations using a stored PAT profile. Token plaintext never returned.",
        operations: &[
            "update_repo",
            "release",
            "read_repo",
            "read_issue",
            "update_issue",
            "add_topics",
        ],
        is_unsafe: false,
        operations_doc: "Operations (`repo` accepts `owner/name` or `github.com/owner/name`):\n  read_repo:    args: { repo: \"owner/name\" }\n  read_issue:   args: { repo: \"owner/name\", number: 42 }\n  update_issue: args: { repo: \"owner/name\", number: 42, title?, body?, state?, labels?, assignees? }\n  update_repo:  args: { repo: \"owner/name\", description?, homepage?, private?, default_branch? }\n  add_topics:   args: { repo: \"owner/name\", topics: [\"a\", \"b\"] }   # APPENDS (REQ-KVD-005)\n  release:      args: { repo: \"owner/name\", tag_name, name?, body?, draft?, prerelease?, target_commitish? }\nAll operations require profile_id at the top level.",
    },
    PrimitiveInfo {
        name: "kvendra.npm",
        summary: "npm registry operations (publish/deprecate/read_metadata).",
        operations: &["publish", "deprecate", "read_metadata"],
        is_unsafe: false,
        operations_doc: "Operations:\n  publish:       args: { cwd: \"<path>\", access?: \"public\"|\"restricted\", tag?: \"latest\" }\n  deprecate:     args: { package: \"<name>\", version: \"<semver>\", message: \"<reason>\" }\n  read_metadata: args: { package: \"<name>\" }\nAll operations require profile_id at the top level.",
    },
    PrimitiveInfo {
        name: "kvendra.pypi",
        summary: "PyPI operations (upload/read_metadata).",
        operations: &["upload", "read_metadata"],
        is_unsafe: false,
        operations_doc: "Operations:\n  upload:        args: { dist_path: \"<path>\", repository_url?: \"https://upload.pypi.org/legacy/\" }\n  read_metadata: args: { project: \"<name>\" }\nAll operations require profile_id at the top level.",
    },
    PrimitiveInfo {
        name: "kvendra.aws",
        summary: "AWS CLI brokered operations (s3_sync/s3_cp/cloudfront_invalidate/lambda_invoke).",
        operations: &["s3_sync", "s3_cp", "cloudfront_invalidate", "lambda_invoke"],
        is_unsafe: false,
        operations_doc: "Operations:\n  s3_sync:               args: { src: \"<src>\", dst: \"<dst>\", delete?: false }   # delete=true is destructive\n  s3_cp:                 args: { src: \"<src>\", dst: \"<dst>\" }\n  cloudfront_invalidate: args: { distribution_id: \"<id>\", paths: [\"/*\"] }\n  lambda_invoke:         args: { function_name: \"<name>\", payload?: <object>, invocation_type?: \"RequestResponse\" }\nAll operations require profile_id at the top level.",
    },
    PrimitiveInfo {
        name: "kvendra.http",
        summary: "Generic HTTP request brokered through a stored credential profile.",
        operations: &["request"],
        is_unsafe: false,
        operations_doc: "Operations:\n  request: args: { url: \"<url>\", method: \"GET\"|\"POST\"|\"PUT\"|\"PATCH\"|\"DELETE\"|\"HEAD\"|\"OPTIONS\", headers?: <object>, body?: <object|string> }\nThe profile's allowlist constrains url_pattern_regex + methods. POST/PUT/PATCH/DELETE require accept_destructive: true on the operation.\nRequires profile_id at the top level.",
    },
    PrimitiveInfo {
        name: "kvendra.shell",
        summary: "Run an allowed binary with constrained args. Not shell-script execution. No `sh -c`.",
        operations: &["exec"],
        is_unsafe: false,
        operations_doc: "Operations:\n  exec: args: { binary: \"<name>\", args: [\"<arg1>\", ...], cwd?: \"<path>\", env?: <object> }\nThe profile's allowlist constrains binary names + arg patterns. Always destructive (requires accept_destructive: true).\nRequires profile_id at the top level.",
    },
    PrimitiveInfo {
        name: "kvendra.unsafe.raw_token",
        summary: "Returns the plaintext credential. Use only when no canonical primitive covers your case. Audit-flagged.",
        operations: &["get"],
        is_unsafe: true,
        operations_doc: "Args: { profile_id: \"<id>\", reason: \"<why this escape hatch is necessary, audit-logged>\" }\nThis primitive deliberately exposes the plaintext credential. Each call is logged with severity=warn and flag=unsafe_escape_hatch. Use ONLY when no canonical primitive can perform the action and you have approved the risk in the profile metadata.",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn description_concatenates_summary_and_operations_doc() {
        let info = PrimitiveInfo {
            name: "test",
            summary: "Summary line",
            operations: &["op_a", "op_b"],
            is_unsafe: false,
            operations_doc: "Operations:\n  op_a: ...\n  op_b: ...",
        };
        let d = info.tools_list_description();
        assert!(d.starts_with("Summary line"));
        assert!(d.contains("Operations:"));
        assert!(d.contains("op_a:"));
    }

    #[test]
    fn description_handles_empty_operations_doc() {
        let info = PrimitiveInfo {
            name: "test",
            summary: "Just a summary",
            operations: &["op"],
            is_unsafe: false,
            operations_doc: "",
        };
        assert_eq!(info.tools_list_description(), "Just a summary");
    }

    #[test]
    fn unsafe_primitive_description_has_unsafe_prefix() {
        let info = PrimitiveInfo {
            name: "test.unsafe",
            summary: "Plaintext access.",
            operations: &["get"],
            is_unsafe: true,
            operations_doc: "",
        };
        assert!(
            info.tools_list_description().starts_with("[UNSAFE] "),
            "got: {}",
            info.tools_list_description()
        );
    }

    #[test]
    fn catalog_descriptions_are_richer_post_req_kvd_005() {
        // Cada primitive del catálogo (excepto unsafe.raw_token que tiene
        // su propia forma) debe tener operations_doc con líneas para sus
        // operations canónicas.
        for entry in catalog() {
            if entry.is_unsafe {
                continue;
            }
            let desc = entry.tools_list_description();
            for op in entry.operations {
                assert!(
                    desc.contains(op),
                    "tools_list_description for {} must mention operation '{op}'; got:\n{desc}",
                    entry.name
                );
            }
        }
    }

    #[test]
    fn catalog_input_schema_exposes_descriptions_for_required_fields() {
        for entry in catalog() {
            let schema = entry.input_schema();
            let props = schema.get("properties").unwrap();
            assert!(props.get("profile_id").is_some());
            if !entry.is_unsafe {
                let op = props.get("operation").unwrap();
                assert!(op.get("description").is_some());
                let args = props.get("args").unwrap();
                assert!(args.get("description").is_some());
            }
        }
    }
}
