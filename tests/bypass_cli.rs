//! Integration tests for the break-glass bypass CLI surface
//! (REQ-KVD-SKILLS-41032D / ISSUE-KVD-CLI-238B54).
//!
//! These exercise the binary end-to-end: `init` → `bypass` → `grant-pubkey`
//! → `verify-grant` (apply / out-of-scope / tamper) → `protect`. The full
//! flow pays the real Argon2id unlock cost, so the heavy test is `#[ignore]`
//! per the repo convention (`cargo test -- --include-ignored`). The cheap
//! arg-validation tests (no vault) run by default.

use assert_cmd::Command;
use predicates::str::contains;

const PW: &str = "hunter2-bypass-cli";

fn init_vault(home: &std::path::Path) {
    Command::cargo_bin("kvendra")
        .unwrap()
        .args(["init", "--no-verify"])
        .env("KVENDRA_HOME", home)
        .env("KVENDRA_INIT_PASSWORD", PW)
        .env("KVENDRA_INIT_CONFIRM_CODE", "0")
        .assert()
        .success();
}

/// `kvendra bypass` with no `--ops` must be rejected (OQ-3 secure default).
/// This needs no vault — clap requires `--ttl`, and our handler rejects the
/// missing scope before touching the vault.
#[test]
fn bypass_without_ops_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("kvendra")
        .unwrap()
        .args(["bypass", "--ttl", "15m"])
        .env("KVENDRA_HOME", dir.path())
        .env("KVENDRA_PASSWORD", PW)
        .assert()
        .failure()
        .stderr(contains("scope"));
}

/// `kvendra protect` is credential-less and idempotent even with no grant.
#[test]
fn protect_without_grant_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("kvendra")
        .unwrap()
        .args(["protect", "--workspace-root", dir.path().to_str().unwrap()])
        .env("KVENDRA_HOME", dir.path())
        .assert()
        .success()
        .stdout(contains("already in effect"));
}

/// `grant-pubkey` before any keypair exists fails cleanly (no panic, no
/// fail-open).
#[test]
fn grant_pubkey_without_key_fails_clean() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("kvendra")
        .unwrap()
        .arg("grant-pubkey")
        .env("KVENDRA_HOME", dir.path())
        .assert()
        .failure();
}

/// `verify-grant` with no grant present must exit 2 (fail-closed) and report
/// `no_grant`. Needs no vault and no keypair material beyond a syntactically
/// valid (dummy) pubkey.
#[test]
fn verify_grant_no_grant_is_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    // 32 zero bytes, base64 — a structurally valid ed25519 pubkey.
    let dummy_pub = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let req = serde_json::json!({
        "workspace_root": dir.path().to_str().unwrap(),
        "op": "kvendra.git.push",
        "pubkey": dummy_pub,
    })
    .to_string();
    Command::cargo_bin("kvendra")
        .unwrap()
        .arg("verify-grant")
        .env("KVENDRA_HOME", dir.path())
        .write_stdin(req)
        .assert()
        .code(2)
        .stdout(contains("no_grant"));
}

/// Full happy-path + negative-path flow. Heavy (real Argon2id), so opt-in.
#[test]
#[ignore = "slow argon2 cost — opt-in via `cargo test -- --include-ignored`"]
fn full_bypass_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    // The workspace root must be a real, canonicalizable path; reuse a temp
    // dir so `canonicalize` succeeds on both the CLI and verify sides.
    let ws = tempfile::tempdir().unwrap();
    let ws_root = ws.path().canonicalize().unwrap();
    let ws_str = ws_root.to_str().unwrap();

    init_vault(home);

    // Establish a live local session (active.blob) — the grant's TOCTOU
    // defence-in-depth requires an active session at verify time, and in
    // real use the operator has already run `kvendra unlock`.
    Command::cargo_bin("kvendra")
        .unwrap()
        .args(["unlock", "--ttl", "1h"])
        .env("KVENDRA_HOME", home)
        .env("KVENDRA_PASSWORD", PW)
        .assert()
        .success();

    // Grant a bypass for git.push only.
    Command::cargo_bin("kvendra")
        .unwrap()
        .args([
            "bypass",
            "--ttl",
            "15m",
            "--ops",
            "kvendra.git.push",
            "--workspace-root",
            ws_str,
        ])
        .env("KVENDRA_HOME", home)
        .env("KVENDRA_PASSWORD", PW)
        .assert()
        .success()
        .stdout(contains("Bypass granted"));

    // Export the pinned public key.
    let out = Command::cargo_bin("kvendra")
        .unwrap()
        .arg("grant-pubkey")
        .env("KVENDRA_HOME", home)
        .assert()
        .success();
    let pubkey = String::from_utf8_lossy(&out.get_output().stdout)
        .trim()
        .to_string();
    assert!(!pubkey.is_empty(), "pubkey must be non-empty");

    let verify = |op: &str| -> assert_cmd::assert::Assert {
        let req = serde_json::json!({
            "workspace_root": ws_str,
            "op": op,
            "pubkey": pubkey,
        })
        .to_string();
        Command::cargo_bin("kvendra")
            .unwrap()
            .arg("verify-grant")
            .env("KVENDRA_HOME", home)
            .write_stdin(req)
            .assert()
    };

    // In-scope op applies (exit 0).
    verify("kvendra.git.push").code(0).stdout(contains("apply"));
    // Out-of-scope op is fail-closed (exit 2).
    verify("kvendra.shell.exec")
        .code(2)
        .stdout(contains("out_of_scope"));

    // Wrong pubkey ⇒ fail-closed (AC-SEC-1 attacker without the private key).
    let bad_pub = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let req = serde_json::json!({
        "workspace_root": ws_str,
        "op": "kvendra.git.push",
        "pubkey": bad_pub,
    })
    .to_string();
    Command::cargo_bin("kvendra")
        .unwrap()
        .arg("verify-grant")
        .env("KVENDRA_HOME", home)
        .write_stdin(req)
        .assert()
        .code(2);

    // Tamper the on-disk grant: widen scope by hand ⇒ signature invalid.
    let bypass_file = std::fs::read_dir(home.join("sessions"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.extension().map(|x| x == "bypass").unwrap_or(false))
        .expect("a .bypass grant file must exist");
    let raw = std::fs::read_to_string(&bypass_file).unwrap();
    let tampered = raw.replace(
        "\"kvendra.git.push\"",
        "\"kvendra.git.push\",\"kvendra.shell.exec\"",
    );
    assert_ne!(raw, tampered, "tamper must alter the bytes");
    std::fs::write(&bypass_file, tampered).unwrap();
    verify("kvendra.shell.exec")
        .code(2)
        .stdout(contains("signature_invalid"));

    // protect revokes; verify then reports no_grant.
    Command::cargo_bin("kvendra")
        .unwrap()
        .args(["protect", "--workspace-root", ws_str])
        .env("KVENDRA_HOME", home)
        .assert()
        .success()
        .stdout(contains("Protection restored"));
    verify("kvendra.git.push")
        .code(2)
        .stdout(contains("no_grant"));
}
