//! REQ-KVD-CLI-CFB449 F3 (ISSUE-KVD-CLI-5917B9) — `recover_with_phrase` at
//! the library level, fake keychain only. Runs with and without test-hooks.

mod rec_common;

use kvendra::error::{KvendraError, PhraseInvalidReason};
use kvendra::rekey::{
    FileCredentialCaches, KEYCHAIN_DERIVED_KEY_LABEL, KEYCHAIN_MCP_PASSWORD_LABEL,
    LEGACY_WRAPPER_NAME, recover_with_phrase,
};
use kvendra::vault::Vault;
use rec_common::*;
use zeroize::Zeroizing;

const PREAUTH: &str = "audit.preauth.jsonl";

async fn recover(f: &Fixture, phrase: &str, new_pw: Option<&str>) -> Result<(), KvendraError> {
    let phrase = phrase.to_string();
    let new_pw = new_pw.map(str::to_string);
    recover_with_phrase(
        &f.vault(),
        move || Ok(Zeroizing::new(phrase)),
        move || match new_pw {
            Some(p) => Ok(Zeroizing::new(p)),
            None => panic!("new password must not be requested"),
        },
        &f.caches(),
    )
    .await
}

/// AC-REC-1 + AC-REC-6 + AC-REC-7 (ok row) + AC-REC-9.
#[tokio::test]
async fn correct_phrase_resets_password_and_keeps_everything() {
    let f = setup().await;
    let before = hashes_except(
        &f.home,
        &["sentinel.blob", "audit.db", "sessions/", "wrappers/"],
    );
    recover(&f, &f.phrase.to_uppercase(), Some(NEW_PW))
        .await
        .unwrap();

    assert_eq!(opening_password(&f.home), NEW_PW);
    assert!(matches!(
        Vault::new(f.home.clone()).unlock(OLD_PW.as_bytes(), 30),
        Err(KvendraError::InvalidMasterPassword)
    ));
    assert_all_intact(&f, NEW_PW);

    // AC-REC-6: only sentinel.blob (and audit.db*, removed caches) changed.
    let after = hashes_except(
        &f.home,
        &["sentinel.blob", "audit.db", "sessions/", "wrappers/"],
    );
    assert_eq!(before, after);
    assert!(!f.home.join("sentinel.blob.pre-recover").exists());
    assert!(!f.home.join("sentinel.blob.recover-tmp").exists());

    // AC-REC-7: exactly one `recover` ok row, payload-free.
    let rows: Vec<_> = audit_rows(&f.home)
        .into_iter()
        .filter(|r| r.action == "recover")
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, "ok");
    assert_eq!(rows[0].flags, "recover_ok");
    assert_no_secret_text(
        &std::fs::read(f.home.join("audit.db")).unwrap(),
        &f,
        "audit.db",
    );

    // AC-REC-9: session blob, fake keychain entries and wrapper are gone.
    assert!(!f.home.join("sessions/active.blob").exists());
    assert!(!f.home.join("sessions/active.blob.hmac").exists());
    let c = f.caches();
    assert!(!c.entry_path(KEYCHAIN_DERIVED_KEY_LABEL).exists());
    assert!(!c.entry_path(KEYCHAIN_MCP_PASSWORD_LABEL).exists());
    assert!(!f.home.join("wrappers").join(LEGACY_WRAPPER_NAME).exists());

    // recovery.blob still works for a second recovery.
    recover(&f, &f.phrase, Some("kvd-rec-third-password"))
        .await
        .unwrap();
    assert!(f.vault().unlock(b"kvd-rec-third-password", 30).is_ok());
}

/// AC-REC-2 — another vault's phrase: mismatch, nothing changes but the
/// pre-auth log, the old password still opens.
#[tokio::test]
async fn foreign_phrase_is_rejected_without_changes() {
    let f = setup().await;
    let before = hashes_except(&f.home, &[PREAUTH]);
    let err = recover(&f, &foreign_phrase(), None).await.unwrap_err();
    assert!(matches!(err, KvendraError::RecoveryPhraseMismatch));
    assert!(err.to_string().contains("does not belong to this vault"));
    assert_eq!(before, hashes_except(&f.home, &[PREAUTH]));
    assert_eq!(opening_password(&f.home), OLD_PW);
    assert!(f.caches().entry_path(KEYCHAIN_MCP_PASSWORD_LABEL).exists());
}

/// AC-REC-3 — malformed phrases: specific error, no new-password prompt
/// (the closure panics if called), no changes.
#[tokio::test]
async fn malformed_phrases_are_rejected_before_new_password() {
    let f = setup().await;
    let words: Vec<&str> = f.phrase.split(' ').collect();
    let unknown = {
        let mut w = words.clone();
        w[2] = "kvdnotaword";
        w.join(" ")
    };
    let eleven = words[..11].join(" ");
    let thirteen = format!("{} {}", f.phrase, words[0]);
    let mut swapped = words.clone();
    // A reordered valid-word phrase: checksum fails (or, rarely, is valid
    // and becomes a mismatch — both are refusals without changes).
    swapped.swap(0, 11);
    let cases = [
        (
            unknown,
            Some(PhraseInvalidReason::UnknownWord { position: 3 }),
        ),
        (eleven, Some(PhraseInvalidReason::WordCount { got: 11 })),
        (thirteen, Some(PhraseInvalidReason::WordCount { got: 13 })),
        (swapped.join(" "), None),
    ];
    let before = hashes_except(&f.home, &[PREAUTH]);
    for (phrase, reason) in cases {
        let err = recover(&f, &phrase, None).await.unwrap_err();
        match (reason, &err) {
            (Some(r), KvendraError::RecoveryPhraseInvalid { reason }) => assert_eq!(*reason, r),
            (None, KvendraError::RecoveryPhraseInvalid { reason }) => {
                assert_eq!(*reason, PhraseInvalidReason::Checksum)
            }
            (None, KvendraError::RecoveryPhraseMismatch) => {}
            _ => panic!("unexpected {err:?}"),
        }
        assert!(!err.to_string().contains("kvdnotaword"));
        assert_eq!(before, hashes_except(&f.home, &[PREAUTH]));
    }
    // Deterministic checksum case: all-zero entropy with the wrong last word.
    let bad_checksum = "abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon";
    assert!(matches!(
        recover(&f, bad_checksum, None).await,
        Err(KvendraError::RecoveryPhraseInvalid {
            reason: PhraseInvalidReason::Checksum
        })
    ));
    assert_eq!(opening_password(&f.home), OLD_PW);
}

/// AC-REC-4 — no recovery.blob (v2) and a 0.8.0 vault (v1): refused before
/// the phrase is asked, nothing changes, no `backup` advice.
#[tokio::test]
async fn vault_without_recovery_blob_is_refused_before_the_phrase() {
    let f = setup().await;
    std::fs::remove_file(f.home.join("recovery.blob")).unwrap();
    let v1_dir = tempfile::tempdir().unwrap();
    let v1_home = v1_dir.path().join("v1");
    std::fs::create_dir_all(v1_home.join("secrets")).unwrap();
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vault-v1");
    std::fs::copy(fixture.join("sentinel.blob"), v1_home.join("sentinel.blob")).unwrap();
    std::fs::copy(
        fixture.join("secrets/fixture.profile.blob"),
        v1_home.join("secrets/fixture.profile.blob"),
    )
    .unwrap();

    for home in [f.home.clone(), v1_home] {
        let before = hashes_except(&home, &[PREAUTH]);
        let err = recover_with_phrase(
            &Vault::new(home.clone()),
            || panic!("phrase must not be requested"),
            || panic!("new password must not be requested"),
            &FileCredentialCaches {
                dir: f.keychain.clone(),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, KvendraError::RecoveryUnavailable));
        let msg = err.to_string();
        assert!(msg.contains("created before Kvendra 0.9") && msg.contains("kvendra init"));
        assert!(!msg.to_lowercase().contains("backup"), "{msg}");
        assert_eq!(before, hashes_except(&home, &[PREAUTH]));
        assert!(home.join(PREAUTH).exists());
    }
}

/// AC-REC-8 — an unknown recovery.blob version fails closed before the
/// phrase is asked.
#[tokio::test]
async fn unknown_recovery_version_is_refused_before_the_phrase() {
    let f = setup().await;
    let p = f.home.join("recovery.blob");
    let mut j: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    j["version"] = 2.into();
    std::fs::write(&p, j.to_string()).unwrap();
    let err = recover_with_phrase(
        &f.vault(),
        || panic!("phrase must not be requested"),
        || panic!("new password must not be requested"),
        &f.caches(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, KvendraError::RecoveryMaterialCorrupt(_)),
        "{err:?}"
    );
}

/// AC-REC-7 — every rejection leaves one secret-free preauth line; the next
/// successful recovery imports them as `preauth_unauthenticated` rows and
/// the chain still verifies.
#[tokio::test]
async fn rejections_are_logged_preauth_and_imported_on_success() {
    let f = setup().await;
    let _ = recover(&f, &foreign_phrase(), None).await;
    let _ = recover(&f, "abandon abandon", None).await;
    let raw = std::fs::read(f.home.join(PREAUTH)).unwrap();
    assert_eq!(String::from_utf8_lossy(&raw).lines().count(), 2);
    assert!(String::from_utf8_lossy(&raw).contains("phrase_mismatch"));
    assert!(String::from_utf8_lossy(&raw).contains("phrase_invalid"));
    assert_no_secret_text(&raw, &f, "preauth");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(f.home.join(PREAUTH))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    recover(&f, &f.phrase, Some(NEW_PW)).await.unwrap();
    assert!(!f.home.join(PREAUTH).exists(), "preauth file emptied");
    let imported: Vec<_> = audit_rows(&f.home)
        .into_iter()
        .filter(|r| r.flags.contains("preauth_unauthenticated"))
        .collect();
    assert_eq!(imported.len(), 2);
    assert!(
        imported
            .iter()
            .all(|r| r.action == "recover" && r.status == "error")
    );
    assert_all_intact(&f, NEW_PW);
    assert_no_secret_text(
        &std::fs::read(f.home.join("audit.db")).unwrap(),
        &f,
        "audit.db",
    );
}

/// AC-REC-9 — a keychain entry that cannot be removed aborts BEFORE the
/// commit: nothing changes, the old password still opens.
#[tokio::test]
async fn keychain_failure_aborts_without_commit() {
    let f = setup().await;
    let caches = FailingMcp;
    let phrase = f.phrase.clone();
    let err = recover_with_phrase(
        &f.vault(),
        move || Ok(Zeroizing::new(phrase)),
        || Ok(Zeroizing::new(NEW_PW.to_string())),
        &caches,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, KvendraError::Keychain(_)), "{err:?}");
    assert_eq!(opening_password(&f.home), OLD_PW);
    assert!(!f.home.join("sentinel.blob.pre-recover").exists());
}

struct FailingMcp;
impl kvendra::rekey::CredentialCaches for FailingMcp {
    fn delete_derived_key(&self) -> kvendra::error::KvendraResult<()> {
        Ok(())
    }
    fn delete_mcp_password(&self) -> kvendra::error::KvendraResult<()> {
        Err(KvendraError::Keychain("fake refusal".into()))
    }
}

/// New password shorter than 8 is refused after the phrase, nothing changes.
#[tokio::test]
async fn short_new_password_is_refused() {
    let f = setup().await;
    let before = hashes(&f.home);
    assert!(recover(&f, &f.phrase, Some("short")).await.is_err());
    assert_eq!(before, hashes(&f.home));
}
