//! REQ-KVD-CLI-CFB449 F3 (ISSUE-KVD-CLI-5917B9) — the `kvendra recover`
//! binary with fault and crash injection (AC-REC-5/6) and output hygiene.
//!
//! Only with `--features test-hooks`: the binary is pointed at a FAKE
//! keychain (`KVENDRA_TEST_KEYCHAIN_DIR`); a test-hooks build refuses to run
//! the re-key without it, so the machine's real keychain is never touched.
#![cfg(feature = "test-hooks")]

mod rec_common;

use assert_cmd::Command;
use rec_common::*;
use std::path::Path;

const STEPS: &[&str] = &[
    "rekey.before_invalidate",
    "rekey.after_invalidate",
    "rekey.after_pre_copy",
    "rekey.after_tmp",
    "rekey.after_rename",
    "rekey.after_dir_fsync",
    "rekey.after_verify",
    "rekey.before_audit",
    "rekey.before_cleanup",
];

fn base(f: &Fixture, sub: &str) -> Command {
    let mut c = Command::cargo_bin("kvendra").unwrap();
    c.arg(sub)
        .env("KVENDRA_HOME", &f.home)
        .env("HOME", f.dir.path())
        .env("KVENDRA_TEST_KEYCHAIN_DIR", &f.keychain)
        .env_remove("KVENDRA_TEST_FAIL_AT")
        .env_remove("KVENDRA_TEST_CRASH_AT")
        .env_remove("KVENDRA_PASSWORD")
        .env_remove("KVENDRA_NEW_PASSWORD")
        .env_remove("KVENDRA_RECOVERY_MNEMONIC");
    c
}

fn recover_cmd(f: &Fixture, phrase: &str) -> Command {
    let mut c = base(f, "recover");
    c.env("KVENDRA_RECOVERY_MNEMONIC", phrase)
        .env("KVENDRA_NEW_PASSWORD", NEW_PW);
    c
}

fn assert_clean_output(out: &std::process::Output, f: &Fixture) {
    assert_no_secret_text(&out.stdout, f, "stdout");
    assert_no_secret_text(&out.stderr, f, "stderr");
}

fn assert_no_leftovers(home: &Path) {
    assert!(!home.join("sentinel.blob.pre-recover").exists());
    assert!(!home.join("sentinel.blob.recover-tmp").exists());
}

#[tokio::test]
async fn success_output_and_message() {
    let f = setup().await;
    let out = recover_cmd(&f, &f.phrase).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Master password reset."));
    assert!(stdout.contains("restart it"));
    assert!(stdout.contains("create a new vault"));
    assert_clean_output(&out, &f);
    assert_all_intact(&f, NEW_PW);
    assert_no_leftovers(&f.home);
}

/// A test-hooks build never falls back to the real keychain.
#[tokio::test]
async fn refuses_without_fake_keychain() {
    let f = setup().await;
    let before = hashes(&f.home);
    let out = recover_cmd(&f, &f.phrase)
        .env_remove("KVENDRA_TEST_KEYCHAIN_DIR")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("KVENDRA_TEST_KEYCHAIN_DIR"));
    assert_eq!(before, hashes(&f.home));
}

/// AC-REC-3 — malformed phrase: error says so and the new-password prompt
/// is never reached (no prompt text, no confirmation request).
#[tokio::test]
async fn malformed_phrase_never_reaches_password_prompt() {
    let f = setup().await;
    let out = base(&f, "recover")
        .env("KVENDRA_RECOVERY_MNEMONIC", "abandon abandon abandon")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not a valid BIP-39"), "{stderr}");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("master password"));
    assert_eq!(opening_password(&f.home), OLD_PW);
}

/// AC-REC-4 — v1 vault: refused, output never mentions backup.
#[tokio::test]
async fn v1_vault_refusal_does_not_mention_backup() {
    let f = setup().await;
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vault-v1/sentinel.blob"),
        f.home.join("sentinel.blob"),
    )
    .unwrap();
    std::fs::remove_file(f.home.join("recovery.blob")).unwrap();
    let out = base(&f, "recover").output().unwrap();
    assert!(!out.status.success());
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(all.contains("created before Kvendra 0.9"), "{all}");
    assert!(!all.to_lowercase().contains("backup"), "{all}");
    assert!(
        !all.contains("recovery phrase (will not echo)"),
        "phrase was asked"
    );
}

/// AC-REC-5 — injected failure at every commit step: the vault opens with
/// exactly one of the two passwords, everything stays readable, and a
/// retry ends with the new password and no leftovers.
#[tokio::test]
async fn injected_failure_at_each_step() {
    for step in STEPS {
        let f = setup().await;
        let out = recover_cmd(&f, &f.phrase)
            .env("KVENDRA_TEST_FAIL_AT", step)
            .output()
            .unwrap();
        assert_clean_output(&out, &f);
        let pw = opening_password(&f.home);
        if *step == "rekey.before_cleanup" {
            assert!(out.status.success(), "{step}: committed, cleanup deferred");
            assert_eq!(pw, NEW_PW, "{step}");
        } else {
            assert!(!out.status.success(), "{step}");
            assert_eq!(pw, OLD_PW, "{step}: an error must mean the old password");
            assert!(!f.home.join("sentinel.blob.recover-tmp").exists(), "{step}");
        }
        assert_all_intact(&f, pw);
        let retry = recover_cmd(&f, &f.phrase).output().unwrap();
        assert!(
            retry.status.success(),
            "{step}: retry {}",
            String::from_utf8_lossy(&retry.stderr)
        );
        assert_eq!(opening_password(&f.home), NEW_PW, "{step}");
        assert_all_intact(&f, NEW_PW);
        assert_no_leftovers(&f.home);
    }
}

/// AC-REC-5/6 — crash (no rollback) at every step: one password opens,
/// everything readable; the next `kvendra unlock` removes the leftovers and
/// a retried recover succeeds.
#[tokio::test]
async fn crash_at_each_step() {
    for step in STEPS {
        let f = setup().await;
        let out = recover_cmd(&f, &f.phrase)
            .env("KVENDRA_TEST_CRASH_AT", step)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(kvendra::fault::CRASH_EXIT_CODE),
            "{step}"
        );
        let pw = opening_password(&f.home);
        assert_all_intact(&f, pw);
        let unlock = base(&f, "unlock")
            .env("KVENDRA_PASSWORD", pw)
            .arg("--no-keychain")
            .output()
            .unwrap();
        assert!(
            unlock.status.success(),
            "{step}: {}",
            String::from_utf8_lossy(&unlock.stderr)
        );
        assert_no_leftovers(&f.home);
        if f.home.join("audit.db").exists() {
            let rows = audit_rows(&f.home);
            let cleaned = rows.iter().any(|r| r.flags == "recover_cleanup");
            let committed_row = rows.iter().any(|r| r.action == "recover");
            if pw == NEW_PW && !committed_row {
                assert!(
                    cleaned,
                    "{step}: an unaudited password change must leave recover_cleanup"
                );
            }
        }
        let retry = recover_cmd(&f, &f.phrase).output().unwrap();
        assert!(retry.status.success(), "{step}");
        assert_eq!(opening_password(&f.home), NEW_PW);
        assert_all_intact(&f, NEW_PW);
    }
}

/// AC-REC-9 — a fake keychain that refuses to delete the mcp-password entry
/// aborts the recovery before the commit.
#[tokio::test]
async fn keychain_refusal_aborts() {
    let f = setup().await;
    let out = recover_cmd(&f, &f.phrase)
        .env("KVENDRA_TEST_KEYCHAIN_FAIL", "kvendra/mcp-password/v1")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(opening_password(&f.home), OLD_PW);
    assert_no_leftovers(&f.home);
}
