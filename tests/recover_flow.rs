//! REQ-KVD-CLI-CFB449 F3 (ISSUE-KVD-CLI-5917B9) — `recover_with_phrase` at
//! the library level, fake keychain only. Runs with and without test-hooks.

mod rec_common;

use kvendra::error::{KvendraError, PhraseInvalidReason};
use kvendra::rekey::CredentialCaches;
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
    .map(|_| ())
}

/// AC-REC-1 + AC-REC-6 + AC-REC-7 (ok row) + AC-REC-9.
#[tokio::test]
async fn correct_phrase_resets_password_and_keeps_everything() {
    let f = setup().await;
    let before = hashes_except(
        &f.home,
        &[
            "sentinel.blob",
            "audit.db",
            "sessions/",
            "wrappers/",
            ".rekey.lock",
        ],
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
        &[
            "sentinel.blob",
            "audit.db",
            "sessions/",
            "wrappers/",
            ".rekey.lock",
        ],
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
        let msg = err.to_string();
        if home == f.home {
            // B8 — a 0.9 vault without recovery.blob is NOT "created before 0.9".
            assert!(matches!(err, KvendraError::RecoveryBlobMissing), "{err:?}");
            assert!(msg.contains("has no recovery.blob") && !msg.contains("before Kvendra 0.9"));
        } else {
            assert!(matches!(err, KvendraError::RecoveryUnavailable), "{err:?}");
            assert!(msg.contains("created before Kvendra 0.9"));
        }
        assert!(msg.contains("kvendra init"));
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
    let caches = Faulty {
        inner: f.caches(),
        fail_delete: Some(KEYCHAIN_MCP_PASSWORD_LABEL),
        fail_owner: None,
    };
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

/// Fake keychain wrapper with switchable failures (no env vars: tests in
/// this binary run in parallel).
struct Faulty {
    inner: FileCredentialCaches,
    fail_delete: Option<&'static str>,
    fail_owner: Option<&'static str>,
}
impl kvendra::rekey::CredentialCaches for Faulty {
    fn owner(&self, label: &str) -> kvendra::error::KvendraResult<Option<String>> {
        if self.fail_owner == Some(label) {
            return Err(KvendraError::Keychain("fake backend failure".into()));
        }
        self.inner.owner(label)
    }
    fn exists(&self, label: &str) -> kvendra::error::KvendraResult<bool> {
        self.inner.exists(label)
    }
    fn set_owner(&self, label: &str, id: &str) -> kvendra::error::KvendraResult<()> {
        self.inner.set_owner(label, id)
    }
    fn delete_entry(&self, label: &str) -> kvendra::error::KvendraResult<bool> {
        if self.fail_delete == Some(label) {
            return Err(KvendraError::Keychain("fake refusal".into()));
        }
        self.inner.delete_entry(label)
    }
    fn delete_owner(&self, label: &str) -> kvendra::error::KvendraResult<()> {
        self.inner.delete_owner(label)
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

/// M3 — the keychain is global: recover on vault A must not remove entries
/// bound to vault B, nor untagged (pre-0.9) entries. Entries bound to A go.
#[tokio::test]
async fn keychain_entries_of_another_vault_are_left_untouched() {
    let a = setup().await;
    let b = setup().await;
    // One shared fake keychain (A's dir), entries owned by B.
    let shared = a.caches();
    let b_id = {
        let kvendra::vault::envelope::Sentinel::V2(s) = b.vault().read_sentinel().unwrap() else {
            unreachable!()
        };
        s.vault_id().unwrap().to_hex()
    };
    shared
        .set_owner(KEYCHAIN_MCP_PASSWORD_LABEL, &b_id)
        .unwrap();
    // derived-key/v1 untagged (as written by a release before 0.9).
    shared.delete_owner(KEYCHAIN_DERIVED_KEY_LABEL).unwrap();

    recover(&a, &a.phrase, Some(NEW_PW)).await.unwrap();
    assert!(
        shared.entry_path(KEYCHAIN_MCP_PASSWORD_LABEL).exists(),
        "B's entry removed"
    );
    assert_eq!(
        shared
            .owner(KEYCHAIN_MCP_PASSWORD_LABEL)
            .unwrap()
            .as_deref(),
        Some(b_id.as_str())
    );
    assert!(
        shared.entry_path(KEYCHAIN_DERIVED_KEY_LABEL).exists(),
        "untagged entry removed"
    );
    assert_eq!(opening_password(&a.home), NEW_PW);

    // Now bind both to A: the next passwd-style commit (recover again)
    // removes them and their tags.
    let a_id = {
        let kvendra::vault::envelope::Sentinel::V2(s) = a.vault().read_sentinel().unwrap() else {
            unreachable!()
        };
        s.vault_id().unwrap().to_hex()
    };
    shared
        .set_owner(KEYCHAIN_MCP_PASSWORD_LABEL, &a_id)
        .unwrap();
    shared.set_owner(KEYCHAIN_DERIVED_KEY_LABEL, &a_id).unwrap();
    recover(&a, &a.phrase, Some("kvd-rec-third-password"))
        .await
        .unwrap();
    assert!(!shared.entry_path(KEYCHAIN_MCP_PASSWORD_LABEL).exists());
    assert!(!shared.entry_path(KEYCHAIN_DERIVED_KEY_LABEL).exists());
    assert!(shared.owner(KEYCHAIN_MCP_PASSWORD_LABEL).unwrap().is_none());
    // B is still intact with its own password.
    assert_eq!(opening_password(&b.home), OLD_PW);
}

/// B9 — recover and passwd share one per-vault lock: while it is held a
/// commit refuses without changes, and the leftover cleanup never deletes
/// the other command's `.pre-recover` / `.recover-tmp`.
#[tokio::test]
async fn rekey_lock_serializes_commits_and_protects_leftovers() {
    let f = setup().await;
    let lock = kvendra::rekey::try_lock_rekey(&f.home)
        .unwrap()
        .expect("free");
    assert!(kvendra::rekey::try_lock_rekey(&f.home).unwrap().is_none());
    let before = hashes_except(&f.home, &[PREAUTH]);
    let err = recover(&f, &f.phrase, Some(NEW_PW)).await.unwrap_err();
    assert!(err.to_string().contains("in progress"), "{err}");
    assert_eq!(before, hashes_except(&f.home, &[PREAUTH]));

    let v = f.vault();
    std::fs::copy(v.sentinel_path(), kvendra::rekey::pre_recover_path(&v)).unwrap();
    std::fs::write(kvendra::rekey::recover_tmp_path(&v), b"half").unwrap();
    kvendra::rekey::cleanup_before_auth(&v).unwrap();
    assert!(
        kvendra::rekey::recover_tmp_path(&v).exists(),
        "tmp deleted under lock"
    );
    kvendra::rekey::finish_after_auth(
        &f.home,
        v.audit_hmac_key_from_password(OLD_PW.as_bytes()).unwrap(),
    )
    .await
    .unwrap();
    assert!(
        kvendra::rekey::pre_recover_path(&v).exists(),
        "pre-recover deleted under lock"
    );

    drop(lock);
    kvendra::rekey::cleanup_before_auth(&v).unwrap();
    assert!(!kvendra::rekey::recover_tmp_path(&v).exists());
    recover(&f, &f.phrase, Some(NEW_PW)).await.unwrap();
    assert!(!kvendra::rekey::pre_recover_path(&v).exists());
    assert_eq!(opening_password(&f.home), NEW_PW);
}

async fn recover_report(
    f: &Fixture,
    caches: &dyn kvendra::rekey::CredentialCaches,
) -> kvendra::rekey::RekeyReport {
    let phrase = f.phrase.clone();
    recover_with_phrase(
        &f.vault(),
        move || Ok(Zeroizing::new(phrase)),
        || Ok(Zeroizing::new(NEW_PW.to_string())),
        caches,
    )
    .await
    .unwrap()
}

/// M1 — removed entries are reported as removed, and the message lists
/// exactly what was cleared.
#[tokio::test]
async fn report_and_message_when_everything_was_bound() {
    use kvendra::rekey::{CacheOutcome, RekeyAction, success_message};
    let f = setup().await;
    let r = recover_report(&f, &f.caches()).await;
    assert!(r.session_removed && r.wrapper_removed);
    assert_eq!(
        r.keychain,
        vec![
            (KEYCHAIN_DERIVED_KEY_LABEL, CacheOutcome::Removed),
            (KEYCHAIN_MCP_PASSWORD_LABEL, CacheOutcome::Removed)
        ]
    );
    let msg = success_message(RekeyAction::Recover, &r);
    assert!(msg.contains("The local session (sessions/active.blob) was cleared."));
    assert!(msg.contains("The legacy MCP wrapper script was removed."));
    assert!(msg.contains("Keychain entry kvendra/derived-key/v1 was removed."));
    assert!(msg.contains("Keychain entry kvendra/mcp-password/v1 was removed."));
    assert!(!msg.contains("left untouched"));
}

/// M1 — on a machine with no keychain entries and no session there is no
/// false warning and no false "cleared": the exact message.
#[tokio::test]
async fn report_and_exact_message_when_nothing_exists() {
    use kvendra::rekey::{CacheOutcome, RekeyAction, success_message};
    let f = setup().await;
    std::fs::remove_dir_all(&f.keychain).unwrap();
    std::fs::create_dir_all(&f.keychain).unwrap();
    std::fs::remove_file(f.home.join("sessions/active.blob")).unwrap();
    std::fs::remove_file(f.home.join("sessions/active.blob.hmac")).unwrap();
    std::fs::remove_file(f.home.join("wrappers").join(LEGACY_WRAPPER_NAME)).unwrap();
    let r = recover_report(&f, &f.caches()).await;
    assert_eq!(
        r.keychain,
        vec![
            (KEYCHAIN_DERIVED_KEY_LABEL, CacheOutcome::Absent),
            (KEYCHAIN_MCP_PASSWORD_LABEL, CacheOutcome::Absent)
        ]
    );
    assert_eq!(
        success_message(RekeyAction::Recover, &r),
        "Master password reset. Your secrets, local variables, allowlists, grants and backups \
         keep working.\n\
         There was no local session to clear.\n\
         No kvendra keychain entries were found.\n\
         Any running `kvendra mcp serve` keeps its in-memory session until it expires — \
         restart it.\n\
         If you suspect the old password was stolen, recovery is not enough: create a new vault."
    );
}

/// M1 — entries of another vault and untagged entries are kept, each with
/// its own notice (and the `disable` command for the untagged one).
#[tokio::test]
async fn report_and_message_for_kept_entries() {
    use kvendra::rekey::{CacheOutcome, KeptReason, RekeyAction, success_message};
    let f = setup().await;
    let c = f.caches();
    c.set_owner(
        KEYCHAIN_MCP_PASSWORD_LABEL,
        "00112233445566778899aabbccddeeff",
    )
    .unwrap();
    c.delete_owner(KEYCHAIN_DERIVED_KEY_LABEL).unwrap();
    let r = recover_report(&f, &c).await;
    assert_eq!(
        r.keychain,
        vec![
            (
                KEYCHAIN_DERIVED_KEY_LABEL,
                CacheOutcome::Kept(KeptReason::NoOwner)
            ),
            (
                KEYCHAIN_MCP_PASSWORD_LABEL,
                CacheOutcome::Kept(KeptReason::OtherVault)
            )
        ]
    );
    let msg = success_message(RekeyAction::Recover, &r);
    assert!(msg.contains(
        "Keychain entry kvendra/mcp-password/v1 was left untouched: it belongs to another vault."
    ));
    assert!(
        msg.contains("Keychain entry kvendra/derived-key/v1 was left untouched: it is not bound")
    );
    assert!(msg.contains("`kvendra config keychain disable`"));
    assert!(!msg.contains("v1 was removed"), "{msg}");
    assert!(!msg.contains("No kvendra keychain entries were found"));
    assert!(c.entry_path(KEYCHAIN_MCP_PASSWORD_LABEL).exists());
    assert!(c.entry_path(KEYCHAIN_DERIVED_KEY_LABEL).exists());
}

/// B4 — a backend error reading the owner of mcp-password/v1 aborts the
/// commit (fail-closed); for derived-key/v1 it is best effort with notice.
#[tokio::test]
async fn owner_read_failure_is_fail_closed_for_mcp_password_only() {
    use kvendra::rekey::{CacheOutcome, KeptReason};
    let f = setup().await;
    let before = hashes_except(&f.home, &[PREAUTH]);
    let phrase = f.phrase.clone();
    let err = recover_with_phrase(
        &f.vault(),
        move || Ok(Zeroizing::new(phrase)),
        || Ok(Zeroizing::new(NEW_PW.to_string())),
        &Faulty {
            inner: f.caches(),
            fail_delete: None,
            fail_owner: Some(KEYCHAIN_MCP_PASSWORD_LABEL),
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err, KvendraError::Keychain(_)), "{err:?}");
    assert_eq!(opening_password(&f.home), OLD_PW);
    assert!(f.caches().entry_path(KEYCHAIN_MCP_PASSWORD_LABEL).exists());
    // Only caches that never hold a key may have gone (session blob).
    let after = hashes_except(&f.home, &[PREAUTH, "sessions/", ".rekey.lock"]);
    let before: std::collections::BTreeMap<_, _> = before
        .into_iter()
        .filter(|(k, _)| !k.starts_with("sessions/"))
        .collect();
    assert_eq!(before, after);

    let r = recover_report(
        &f,
        &Faulty {
            inner: f.caches(),
            fail_delete: None,
            fail_owner: Some(KEYCHAIN_DERIVED_KEY_LABEL),
        },
    )
    .await;
    assert!(matches!(
        r.keychain[0],
        (
            KEYCHAIN_DERIVED_KEY_LABEL,
            CacheOutcome::Kept(KeptReason::BackendError(_))
        )
    ));
    assert_eq!(
        r.keychain[1],
        (KEYCHAIN_MCP_PASSWORD_LABEL, CacheOutcome::Removed)
    );
    assert_eq!(opening_password(&f.home), NEW_PW);
}

/// B2 — a stale `.pre-recover` removed by a later recover is audited as
/// `recover_cleanup` before the new `recover` row.
#[tokio::test]
async fn stale_pre_recover_removed_by_recover_is_audited() {
    let f = setup().await;
    let v = f.vault();
    std::fs::copy(v.sentinel_path(), kvendra::rekey::pre_recover_path(&v)).unwrap();
    recover(&f, &f.phrase, Some(NEW_PW)).await.unwrap();
    assert!(!kvendra::rekey::pre_recover_path(&v).exists());
    let actions: Vec<String> = audit_rows(&f.home)
        .into_iter()
        .filter(|r| r.action == "recover" || r.action == "recover_cleanup")
        .map(|r| r.action)
        .collect();
    assert_eq!(actions, vec!["recover_cleanup", "recover"]);
    assert_all_intact(&f, NEW_PW);
}

/// B5 — a leftover `sentinel.blob.init-tmp` next to a sentinel: removed when
/// byte-identical, quarantined (never deleted) when different.
#[tokio::test]
async fn init_tmp_leftover_is_removed_or_quarantined() {
    let f = setup().await;
    let v = f.vault();
    let tmp = f.home.join(kvendra::rekey::INIT_TMP_NAME);
    std::fs::copy(v.sentinel_path(), &tmp).unwrap();
    kvendra::rekey::cleanup_before_auth(&v).unwrap();
    assert!(!tmp.exists());
    assert!(!std::fs::read_dir(&f.home).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".init-orphans-")
    }));

    std::fs::write(&tmp, b"kvd-different-bytes").unwrap();
    let dir = kvendra::rekey::cleanup_init_tmp(&f.home)
        .unwrap()
        .expect("quarantined");
    assert!(!tmp.exists());
    assert_eq!(
        std::fs::read(dir.join(kvendra::rekey::INIT_TMP_NAME)).unwrap(),
        b"kvd-different-bytes"
    );
    assert_eq!(opening_password(&f.home), OLD_PW);
}
