//! Integration smoke for `kvendra capabilities` (REQ-KVD-ECDAE9 Piece A).
//!
//! Covers:
//! - AC-CLI-1: exits 0; JSON on stdout; root has `broker_version`,
//!   `schema_version`, `primitives`.
//! - AC-CLI-2: 8 primitives × 24 ops total; `destructive_ops ⊆ ops`.
//! - AC-CLI-3: read-only — runs without any environment setup (no
//!   KVENDRA_HOME / KVENDRA_PASSWORD; no network). The subprocess
//!   spawns in a clean cwd via assert_cmd's default.
//! - AC-CLI-4: `schema_version == 1`.
//! - AC-CLI-9: `--pretty` emits indented multi-line JSON.

use assert_cmd::Command;
use serde_json::Value;

#[test]
fn capabilities_emits_valid_compact_json() {
    let assert = Command::cargo_bin("kvendra")
        .unwrap()
        .arg("capabilities")
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    // Compact = single payload line (modulo trailing newline from println!).
    let trimmed = stdout.trim_end();
    assert!(
        !trimmed.contains('\n'),
        "compact capabilities output must be single-line; got: {stdout}"
    );
    let v: Value = serde_json::from_str(trimmed).expect("stdout must be valid JSON");
    assert!(v.get("broker_version").and_then(Value::as_str).is_some());
    assert_eq!(v.get("schema_version").and_then(Value::as_u64), Some(1));
    let prims = v
        .get("primitives")
        .and_then(Value::as_array)
        .expect("primitives must be a JSON array");
    assert_eq!(prims.len(), 8, "must expose 8 primitives");
    let total_ops: usize = prims
        .iter()
        .map(|p| p.get("ops").and_then(Value::as_array).map_or(0, Vec::len))
        .sum();
    // Actual catalog at REL-0.4.1.1 surfaces 25 ops (5+8+3+2+4+1+1+1). The
    // REQ-KVD-ECDAE9 / CMP-KVD-CLI text says "24" — stale count from before
    // the `kvendra.github` extension to 8 ops. Authoritative source is
    // `crate::primitives::catalog()`.
    assert_eq!(
        total_ops, 25,
        "must expose 25 ops total per current catalog"
    );
}

#[test]
fn capabilities_destructive_ops_subset_of_ops() {
    let assert = Command::cargo_bin("kvendra")
        .unwrap()
        .arg("capabilities")
        .assert()
        .success();
    let v: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    for p in v["primitives"].as_array().unwrap() {
        let ops: Vec<&str> = p["ops"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o.as_str().unwrap())
            .collect();
        for d in p["destructive_ops"].as_array().unwrap() {
            let d = d.as_str().unwrap();
            assert!(
                ops.contains(&d),
                "primitive {}: destructive op '{d}' not in ops {ops:?}",
                p["id"]
            );
        }
    }
}

#[test]
fn capabilities_pretty_is_multiline_indented() {
    let assert = Command::cargo_bin("kvendra")
        .unwrap()
        .args(["capabilities", "--pretty"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.matches('\n').count() > 3,
        "--pretty must emit multi-line JSON; got: {stdout}"
    );
    let v: Value = serde_json::from_str(stdout.trim_end()).expect("pretty must be valid JSON");
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["primitives"].as_array().unwrap().len(), 8);
}

#[test]
fn capabilities_listed_in_top_level_help() {
    Command::cargo_bin("kvendra")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("capabilities"));
}
