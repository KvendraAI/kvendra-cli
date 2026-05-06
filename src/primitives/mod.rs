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
}

impl PrimitiveInfo {
    pub fn tools_list_description(&self) -> String {
        if self.is_unsafe {
            format!("[UNSAFE] {}", self.summary)
        } else {
            self.summary.to_string()
        }
    }

    /// JSON Schema for the `arguments` field of a `tools/call`.
    pub fn input_schema(&self) -> Value {
        if self.is_unsafe {
            json!({
                "type": "object",
                "properties": {
                    "profile_id": { "type": "string" },
                    "reason": { "type": "string" },
                },
                "required": ["profile_id", "reason"],
            })
        } else {
            json!({
                "type": "object",
                "properties": {
                    "profile_id": { "type": "string" },
                    "operation": { "type": "string", "enum": self.operations },
                    "args": { "type": "object" },
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
    },
    PrimitiveInfo {
        name: "kvendra.npm",
        summary: "npm registry operations (publish/deprecate/read_metadata).",
        operations: &["publish", "deprecate", "read_metadata"],
        is_unsafe: false,
    },
    PrimitiveInfo {
        name: "kvendra.pypi",
        summary: "PyPI operations (upload/read_metadata).",
        operations: &["upload", "read_metadata"],
        is_unsafe: false,
    },
    PrimitiveInfo {
        name: "kvendra.aws",
        summary: "AWS CLI brokered operations (s3_sync/s3_cp/cloudfront_invalidate/lambda_invoke).",
        operations: &["s3_sync", "s3_cp", "cloudfront_invalidate", "lambda_invoke"],
        is_unsafe: false,
    },
    PrimitiveInfo {
        name: "kvendra.http",
        summary: "Generic HTTP request brokered through a stored credential profile.",
        operations: &["request"],
        is_unsafe: false,
    },
    PrimitiveInfo {
        name: "kvendra.shell",
        summary: "Run an allowed binary with constrained args. Not shell-script execution. No `sh -c`.",
        operations: &["exec"],
        is_unsafe: false,
    },
    PrimitiveInfo {
        name: "kvendra.unsafe.raw_token",
        summary: "Returns the plaintext credential. Use only when no canonical primitive covers your case. Audit-flagged.",
        operations: &["get"],
        is_unsafe: true,
    },
];
