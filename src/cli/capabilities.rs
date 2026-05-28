//! `kvendra capabilities` — emit the canonical broker capabilities manifest
//! as JSON on stdout.
//!
//! Wire-public, read-only, auth-less subcommand. Per `REQ-KVD-ECDAE9` (Piece A,
//! AC-CLI-1..9) this is the runtime discovery surface consumed by:
//!
//! 1. `kvendra-skills:release-manager` post-release hook → upserts
//!    `IF-<PROJ>-CLI-PRIMITIVES-MANIFEST` in the Kvendra KB.
//! 2. `kvendra-skills:onboard-project` Step 1.5 → diffs the local broker
//!    against the KB IF-MANIFEST.
//! 3. `kvendra-skills:lint-claudemd` → cross-checks
//!    `STD-<PROJ>-BROKER-POLICY.require_broker[].primitive` against the
//!    manifest.
//!
//! Invariants (AC-CLI-3): zero vault unlock, zero network IO, zero
//! filesystem writes. The handler builds a static manifest from
//! `crate::primitives::catalog()` plus a small ancillary table for
//! metadata (`destructive_ops`, `vault_profile_pattern`, `since_version`).
//!
//! Schema version contract (AC-CLI-4 / AC-CLI-8): `schema_version: 1` is
//! the stable wire contract. Consumers MUST verify
//! `schema_version == 1`. Bumping the version requires a major REQ and an
//! IF-MANIFEST schema bump in lockstep.

use crate::error::KvendraResult;
use crate::primitives::catalog;
use serde::Serialize;

/// Stable wire schema version of the manifest. Bumping requires a major REQ
/// + IF-MANIFEST schema bump in lockstep.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize)]
pub struct CapabilitiesManifest {
    pub broker_version: String,
    pub schema_version: u32,
    pub primitives: Vec<PrimitiveSpec>,
}

#[derive(Debug, Serialize)]
pub struct PrimitiveSpec {
    pub id: String,
    pub ops: Vec<String>,
    pub destructive_ops: Vec<String>,
    pub vault_profile_pattern: String,
    pub since_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprecated_in: Option<String>,
}

/// Per-primitive metadata not carried in `PrimitiveInfo`: the subset of
/// `ops` that mutate external state, the canonical vault profile id
/// pattern, and the `since_version` (when the primitive first shipped).
///
/// Source of truth: `CMP-KVD-CLI.content` § "Primitives MCP canónicas"
/// + per-primitive `operations_doc` in `src/primitives/mod.rs`.
fn metadata_for(name: &str) -> (Vec<&'static str>, &'static str, &'static str) {
    match name {
        // git: push/commit/tag mutate; clone/pull are read-only.
        "kvendra.git" => (vec!["push", "commit", "tag"], "github.*", "0.1.0"),
        // github: write/POST/PATCH endpoints are destructive; read_* + list_issues are read-only.
        "kvendra.github" => (
            vec![
                "update_repo",
                "release",
                "update_issue",
                "add_topics",
                "create_issue",
            ],
            "github.*",
            "0.1.0",
        ),
        // npm: publish/deprecate mutate the registry; read_metadata is read-only.
        "kvendra.npm" => (vec!["publish", "deprecate"], "npm.*", "0.1.0"),
        // pypi: upload mutates; read_metadata is read-only.
        "kvendra.pypi" => (vec!["upload"], "pypi.*", "0.1.0"),
        // aws: every op mutates external state (s3, cloudfront, lambda invoke side effects).
        "kvendra.aws" => (
            vec!["s3_sync", "s3_cp", "cloudfront_invalidate", "lambda_invoke"],
            "aws.*",
            "0.1.0",
        ),
        // http: profile allowlist gates destructive-method opt-in; every request is treated destructive
        // by default per the operations_doc note. Surface as such for consumer planning.
        "kvendra.http" => (vec!["request"], "http.*", "0.1.0"),
        // shell: always destructive per operations_doc.
        "kvendra.shell" => (vec!["exec"], "shell.*", "0.1.0"),
        // unsafe escape hatch: the only op exposes plaintext — destructive in audit terms.
        "kvendra.unsafe.raw_token" => (vec!["get"], "*", "0.1.0"),
        _ => (vec![], "*", "0.1.0"),
    }
}

/// Build the canonical capabilities manifest. Pure function: no IO, no
/// vault, no network. Deterministic in primitive order (matches the
/// declaration order of the static `CATALOG`).
pub fn build_manifest() -> CapabilitiesManifest {
    let primitives = catalog()
        .iter()
        .map(|p| {
            let (destructive, pattern, since) = metadata_for(p.name);
            let destructive_ops: Vec<String> = destructive.into_iter().map(String::from).collect();
            PrimitiveSpec {
                id: p.name.to_string(),
                ops: p.operations.iter().map(|o| (*o).to_string()).collect(),
                destructive_ops,
                vault_profile_pattern: pattern.to_string(),
                since_version: since.to_string(),
                deprecated_in: None,
            }
        })
        .collect();
    CapabilitiesManifest {
        broker_version: env!("CARGO_PKG_VERSION").to_string(),
        schema_version: SCHEMA_VERSION,
        primitives,
    }
}

#[derive(clap::Args, Debug)]
pub struct CapabilitiesArgs {
    /// Pretty-print JSON (multi-line, indented) instead of the default
    /// compact single-line output.
    #[arg(long)]
    pub pretty: bool,
}

pub fn run(args: &CapabilitiesArgs) -> KvendraResult<()> {
    let manifest = build_manifest();
    let out = if args.pretty {
        serde_json::to_string_pretty(&manifest)?
    } else {
        serde_json::to_string(&manifest)?
    };
    println!("{out}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AC-CLI-1 + AC-CLI-2: 8 primitives × 25 ops total; root has the
    /// three required keys with the right types.
    ///
    /// Note: REQ-KVD-ECDAE9 (Piece A) + CMP-KVD-CLI.content state "24 ops".
    /// That figure is stale — predates the `kvendra.github` extension to
    /// 8 ops (REL-KVD-CLI-0.4.1.1). The canonical catalog in
    /// `crate::primitives::catalog()` exposes 25 ops total today
    /// (5+8+3+2+4+1+1+1). The KB-side reconciliation is queued for the
    /// updater (PHASE 6) — see `IF-KVD-CLI-PRIMITIVES-MANIFEST` content.
    #[test]
    fn manifest_covers_eight_primitives_twentyfive_ops() {
        let m = build_manifest();
        assert_eq!(m.schema_version, 1, "AC-CLI-4: schema_version must be 1");
        assert_eq!(m.primitives.len(), 8, "AC-CLI-2: must expose 8 primitives");
        let total_ops: usize = m.primitives.iter().map(|p| p.ops.len()).sum();
        assert_eq!(
            total_ops, 25,
            "AC-CLI-2 (reconciled): catalog exposes 25 ops post-0.4.1.1"
        );
    }

    /// AC-CLI-2 invariant: destructive_ops ⊆ ops for every primitive.
    #[test]
    fn destructive_ops_subset_of_ops() {
        let m = build_manifest();
        for p in &m.primitives {
            for d in &p.destructive_ops {
                assert!(
                    p.ops.contains(d),
                    "primitive {}: destructive op '{d}' not in ops list {:?}",
                    p.id,
                    p.ops
                );
            }
        }
    }

    /// Primitive id set is the canonical catalog. Future additions land
    /// here when the catalog is extended.
    #[test]
    fn primitive_ids_match_canonical_catalog() {
        let m = build_manifest();
        let ids: Vec<&str> = m.primitives.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "kvendra.git",
                "kvendra.github",
                "kvendra.npm",
                "kvendra.pypi",
                "kvendra.aws",
                "kvendra.http",
                "kvendra.shell",
                "kvendra.unsafe.raw_token",
            ],
        );
    }

    /// AC-CLI-1: compact JSON serialization is valid + parseable.
    #[test]
    fn compact_serialization_is_valid_json() {
        let m = build_manifest();
        let s = serde_json::to_string(&m).unwrap();
        assert!(!s.contains('\n'), "compact output must be single-line");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v.get("broker_version").is_some());
        assert!(v.get("schema_version").is_some());
        assert!(v.get("primitives").and_then(|x| x.as_array()).is_some());
    }

    /// AC-CLI-9: pretty serialization is multi-line + indented.
    #[test]
    fn pretty_serialization_is_indented() {
        let m = build_manifest();
        let s = serde_json::to_string_pretty(&m).unwrap();
        assert!(s.contains('\n'), "pretty output must be multi-line");
        // Re-parse to confirm fidelity.
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["schema_version"], 1);
    }

    /// AC-CLI-1: `broker_version` matches the crate version (and tracks
    /// future bumps automatically).
    #[test]
    fn broker_version_matches_crate_version() {
        let m = build_manifest();
        assert_eq!(m.broker_version, env!("CARGO_PKG_VERSION"));
    }

    /// `deprecated_in` is `None` for all current primitives (no
    /// deprecations yet) and is skipped on serialization (no `null` keys
    /// in the wire output).
    #[test]
    fn deprecated_in_absent_from_wire_output() {
        let m = build_manifest();
        let s = serde_json::to_string(&m).unwrap();
        assert!(
            !s.contains("deprecated_in"),
            "deprecated_in must be omitted when None"
        );
        for p in &m.primitives {
            assert!(p.deprecated_in.is_none());
        }
    }
}
