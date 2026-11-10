//! REQ-KVD-CLI-CFB449 F5 (ISSUE-KVD-CLI-80887F) — `kvendra passwd`
//! (AC-REC-14). Library tests run in every build with the fake keychain;
//! binary tests need `--features test-hooks`.

mod rec_common;

use kvendra::error::KvendraError;
use kvendra::rekey::{
    KEYCHAIN_DERIVED_KEY_LABEL, KEYCHAIN_MCP_PASSWORD_LABEL, PASSWD_V1_UNSUPPORTED, change_password,
};
use kvendra::vault::Vault;
use rec_common::*;
use std::path::Path;
use zeroize::Zeroizing;

const PREAUTH: &str = "audit.preauth.jsonl";

async fn passwd(f: &Fixture, current: &str, new: Option<&str>) -> Result<(), KvendraError> {
    let current = current.to_string();
    let new = new.map(str::to_string);
    change_password(
        &f.vault(),
        move || Ok(Zeroizing::new(current)),
        move || match new {
            Some(p) => Ok(Zeroizing::new(p)),
            None => panic!("new password must not be requested"),
        },
        &f.caches(),
    )
    .await
    .map(|_| ())
}

#[tokio::test]
async fn correct_current_password_changes_it_and_keeps_everything() {
    let f = setup().await;
    passwd(&f, OLD_PW, Some(NEW_PW)).await.unwrap();
    assert_eq!(opening_password(&f.home), NEW_PW);
    assert_all_intact(&f, NEW_PW);
    let rows: Vec<_> = audit_rows(&f.home)
        .into_iter()
        .filter(|r| r.action == "passwd")
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].flags, "passwd_ok");
    assert!(!f.home.join("sessions/active.blob").exists());
    assert!(!f.caches().entry_path(KEYCHAIN_DERIVED_KEY_LABEL).exists());
    assert!(!f.caches().entry_path(KEYCHAIN_MCP_PASSWORD_LABEL).exists());
    assert!(!f.home.join("sentinel.blob.pre-recover").exists());
    // recovery.blob untouched and still opens after the change.
    let mk = f
        .vault()
        .open_recovery(&kvendra::vault::envelope::parse_phrase(&f.phrase).unwrap())
        .unwrap();
    assert!(
        mk.ct_eq(
            &f.vault()
                .master_key_from_password(NEW_PW.as_bytes())
                .unwrap()
        )
    );
}

#[tokio::test]
async fn wrong_current_password_changes_nothing_but_preauth() {
    let f = setup().await;
    let before = hashes_except(&f.home, &[PREAUTH]);
    let err = passwd(&f, "kvd-rec-wrong-password", None)
        .await
        .unwrap_err();
    assert!(matches!(err, KvendraError::InvalidMasterPassword));
    assert_eq!(before, hashes_except(&f.home, &[PREAUTH]));
    let raw = std::fs::read(f.home.join(PREAUTH)).unwrap();
    assert!(String::from_utf8_lossy(&raw).contains("\"passwd\""));
    assert!(String::from_utf8_lossy(&raw).contains("password_invalid"));
    assert!(!String::from_utf8_lossy(&raw).contains("kvd-rec-wrong-password"));
    assert_no_secret_text(&raw, &f, "preauth");
    assert_eq!(opening_password(&f.home), OLD_PW);
}

#[tokio::test]
async fn same_or_short_new_password_is_refused() {
    let f = setup().await;
    let before = hashes(&f.home);
    assert!(passwd(&f, OLD_PW, Some(OLD_PW)).await.is_err());
    assert!(passwd(&f, OLD_PW, Some("short")).await.is_err());
    assert_eq!(before, hashes(&f.home));
}

#[tokio::test]
async fn v1_vault_is_refused_without_changes() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("v1");
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vault-v1");
    std::fs::create_dir_all(home.join("secrets")).unwrap();
    std::fs::copy(fx.join("sentinel.blob"), home.join("sentinel.blob")).unwrap();
    let before = hashes(&home);
    let err = change_password(
        &Vault::new(home.clone()),
        || panic!("current password must not be requested"),
        || panic!("new password must not be requested"),
        &kvendra::rekey::FileCredentialCaches {
            dir: dir.path().join("kc"),
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("vault error: {PASSWD_V1_UNSUPPORTED}")
    );
    assert_eq!(before, hashes(&home));
}

#[cfg(feature = "test-hooks")]
mod binary {
    use super::*;
    use assert_cmd::Command;

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

    fn cmd(f: &Fixture) -> Command {
        let mut c = Command::cargo_bin("kvendra").unwrap();
        c.arg("passwd")
            .env("KVENDRA_HOME", &f.home)
            .env("HOME", f.dir.path())
            .env("KVENDRA_TEST_KEYCHAIN_DIR", &f.keychain)
            .env("KVENDRA_PASSWORD", OLD_PW)
            .env("KVENDRA_NEW_PASSWORD", NEW_PW)
            .env_remove("KVENDRA_TEST_FAIL_AT")
            .env_remove("KVENDRA_TEST_CRASH_AT");
        c
    }

    #[tokio::test]
    async fn binary_success_and_clean_output() {
        let f = setup().await;
        let out = cmd(&f).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("Master password changed."));
        assert_no_secret_text(&out.stdout, &f, "stdout");
        assert_no_secret_text(&out.stderr, &f, "stderr");
        assert_all_intact(&f, NEW_PW);
    }

    /// AC-REC-5 / AC-REC-14 — fault injection at every commit step.
    #[tokio::test]
    async fn binary_injected_failure_at_each_step() {
        for step in STEPS {
            let f = setup().await;
            let out = cmd(&f).env("KVENDRA_TEST_FAIL_AT", step).output().unwrap();
            let pw = opening_password(&f.home);
            if *step == "rekey.before_cleanup" {
                assert!(out.status.success(), "{step}");
                assert_eq!(pw, NEW_PW, "{step}");
            } else {
                assert!(!out.status.success(), "{step}");
                assert_eq!(pw, OLD_PW, "{step}");
            }
            assert_all_intact(&f, pw);
        }
    }

    /// Crash (no rollback) at every step: exactly one password opens.
    #[tokio::test]
    async fn binary_crash_at_each_step() {
        for step in STEPS {
            let f = setup().await;
            let out = cmd(&f).env("KVENDRA_TEST_CRASH_AT", step).output().unwrap();
            assert_eq!(
                out.status.code(),
                Some(kvendra::fault::CRASH_EXIT_CODE),
                "{step}"
            );
            let pw = opening_password(&f.home);
            assert_all_intact(&f, pw);
        }
    }
}
