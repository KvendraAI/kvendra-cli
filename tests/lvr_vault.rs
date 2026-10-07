//! REQ-KVD-11F906 — storage:
//! - TEST-KVD-CLI-NEW-5 (AC-LVR-5): `vars.blob` and secret blobs are not
//!   interchangeable (dedicated HKDF sub-key + AAD).
//! - TEST-KVD-CLI-NEW-6 (AC-LVR-6): the backup bundle carries `vars.blob`,
//!   a restore leaves every variable unverified, and only `verify` lifts it.

mod lvr_common;

use kvendra::vars::{self, VarType};
use lvr_common::*;
use serde_json::json;

// ───────────────────────── TEST-5 / AC-LVR-5 ─────────────────────────

#[tokio::test]
async fn vars_blob_and_secret_blob_are_not_interchangeable() {
    let f = fixture("profile_id: p\nsecret:\n  type: t\nallowlist:\n  primitives:\n    - name: kvendra.shell\n      operations:\n        - exec:\n            binaries: [\"pwd\"]\n").await;
    let v = &f.ctx.vault;

    // vars.blob copied over a secret blob → get_secret fails.
    std::fs::copy(v.vars_blob_path(), v.profile_blob_path("x")).unwrap();
    assert!(
        v.get_secret("x").is_err(),
        "a vars blob must not open as a secret"
    );

    // A secret blob installed as vars.blob → load fails.
    let backup = std::fs::read(v.vars_blob_path()).unwrap();
    std::fs::copy(v.profile_blob_path("p"), v.vars_blob_path()).unwrap();
    assert!(
        vars::load(v).is_err(),
        "a secret blob must not open as vars"
    );
    std::fs::write(v.vars_blob_path(), &backup).unwrap();
    assert!(vars::load(v).is_ok());

    // Sealed with the right sub-key but WITHOUT the AAD → fails.
    let key = v.local_vars_key().unwrap();
    let nonce = kvendra::vault::crypto::random_nonce();
    let ct = kvendra::vault::crypto::seal(key.as_bytes(), &nonce, br#"{"v":1,"vars":{}}"#).unwrap();
    let blob = kvendra::vault::blob::Blob::new(
        kvendra::vault::kdf::KdfParams::high_cost(vec![]),
        nonce.to_vec(),
        ct,
    );
    std::fs::write(v.vars_blob_path(), blob.to_json().unwrap()).unwrap();
    assert!(vars::load(v).is_err(), "no-AAD ciphertext must be refused");

    // Sealed with the MASTER key and the right AAD → fails (sub-key bound).
    let master = v.peek_session_derived_key().unwrap();
    let ct =
        kvendra::vault::crypto::seal_aad(&master, &nonce, &vars::aad(), br#"{"v":1,"vars":{}}"#)
            .unwrap();
    let blob = kvendra::vault::blob::Blob::new(
        kvendra::vault::kdf::KdfParams::high_cost(vec![]),
        nonce.to_vec(),
        ct,
    );
    std::fs::write(v.vars_blob_path(), blob.to_json().unwrap()).unwrap();
    assert!(
        vars::load(v).is_err(),
        "master-key ciphertext must be refused"
    );
}

// ───────────────────────── TEST-6 / AC-LVR-6 ─────────────────────────

const YAML: &str = r#"profile_id: p
secret:
  type: github_pat
allowlist:
  primitives:
    - name: kvendra.shell
      operations:
        - exec:
            binaries: ["pwd"]
            cwd_pattern: "^{WS_RE}(/.*)?$"
            accept_destructive: true
"#;

#[tokio::test]
async fn backup_carries_vars_and_restore_leaves_them_unverified() {
    let f = fixture(YAML).await;

    // The bundle includes vars.blob but not its rotated copies.
    let tar_bytes = kvendra::backup::bundle::build_bundle(&f.home).unwrap();
    let mut archive = tar::Archive::new(tar_bytes.as_slice());
    let names: Vec<String> = archive
        .entries()
        .unwrap()
        .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
        .collect();
    assert!(names.iter().any(|n| n == "vars.blob"), "{names:?}");
    assert!(
        !names.iter().any(|n| n.starts_with("vars.blob.")),
        "{names:?}"
    );

    // Restore into staging → every variable verified:false, origin:restore.
    let staging = f.root.join("staging_restore");
    kvendra::backup::bundle::extract_bundle(&tar_bytes, &staging).unwrap();
    let n = vars::mark_restored_unverified(&staging, PASSWORD).unwrap();
    assert!(n >= 4);
    // A wrong password does not re-seal.
    assert!(vars::mark_restored_unverified(&staging, b"kvd-sentinel-wrong").is_err());

    let staged = kvendra::vault::Vault::new(staging.clone());
    let key = staged.local_vars_key_from_password(PASSWORD).unwrap();
    let doc = vars::load_with_key(&staged.vars_blob_path(), key.as_bytes()).unwrap();
    assert!(doc.vars.values().all(|v| !v.verified));
    assert!(
        doc.vars
            .values()
            .all(|v| v.origin == vars::VarOrigin::Restore)
    );

    // Put the restored blob in place: the broker refuses until verify.
    std::fs::copy(staged.vars_blob_path(), f.ctx.vault.vars_blob_path()).unwrap();
    let req = || {
        call(
            "kvendra.shell",
            "exec",
            json!({"binary": "pwd", "argv": [], "cwd": "{{lvr:ws}}"}),
        )
    };
    let resp = run(&f, req()).await;
    assert_eq!(
        error_type(&resp).as_deref(),
        Some("lvr_unverified"),
        "{resp}"
    );

    // `verify` (internal API — the CLI wraps it with TTY + password).
    vars::mark_verified(&f.ctx.vault, "ws").unwrap();
    let doc = vars::load(&f.ctx.vault).unwrap();
    assert!(doc.vars["ws"].verified);
    let resp = run(&f, req()).await;
    assert!(resp.get("result").is_some(), "{resp}");
}

#[tokio::test]
async fn verify_refuses_a_value_that_no_longer_validates() {
    let f = fixture(YAML).await;
    let gone = f.ws.join("gone");
    std::fs::create_dir_all(&gone).unwrap();
    vars::set_var(
        &f.ctx.vault,
        "gone",
        VarType::Path,
        &gone.to_string_lossy(),
        false,
    )
    .unwrap();
    std::fs::remove_dir(&gone).unwrap();
    assert!(vars::mark_verified(&f.ctx.vault, "gone").is_err());
    assert!(!vars::load(&f.ctx.vault).unwrap().vars["gone"].verified);
}
