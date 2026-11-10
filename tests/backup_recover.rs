//! REQ-KVD-CLI-CFB449 F4 (ISSUE-KVD-CLI-043B2B) — backup bundle carries
//! recovery.blob (AC-REC-11) and a restore after `recover` opens with the
//! CURRENT password (AC-REC-9 backups). Fake keychain only.

mod rec_common;

use kvendra::backup::{bundle, crypto, restore::restore_into_staging};
use kvendra::cli::backup::backup_key_from_master_key;
use kvendra::error::KvendraError;
use kvendra::rekey::recover_with_phrase;
use kvendra::vault::Vault;
use rec_common::*;
use std::path::Path;
use zeroize::Zeroizing;

const V1_PASSWORD: &[u8] = b"kvd-fixture-v1-password";
const V1_BACKUP_KEY_HEX: &str = "e5ccfd035da2c36a4357a55b6fe4f7e5dd9245245c422c459d082d70757e590f";

fn entries(tar_bytes: &[u8]) -> Vec<String> {
    tar::Archive::new(tar_bytes)
        .entries()
        .unwrap()
        .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
        .collect()
}

/// AC-REC-11 — recovery.blob is in the bundle and extracts byte-identical.
#[tokio::test]
async fn bundle_carries_recovery_blob_byte_identical() {
    let f = setup().await;
    let tar_bytes = bundle::build_bundle(&f.home).unwrap();
    assert!(entries(&tar_bytes).iter().any(|n| n == "recovery.blob"));
    let out = tempfile::tempdir().unwrap();
    bundle::extract_bundle(&tar_bytes, out.path()).unwrap();
    assert_eq!(
        std::fs::read(out.path().join("recovery.blob")).unwrap(),
        std::fs::read(f.home.join("recovery.blob")).unwrap()
    );
}

/// AC-REC-9 / AC-REC-11 — a backup made BEFORE recover decrypts with the
/// NEW password, the restored staging opens with the NEW password (not the
/// forgotten one), secrets are readable, vars come back unverified.
#[tokio::test]
async fn backup_before_recover_restores_with_new_password() {
    let f = setup().await;
    let mk_old = f
        .vault()
        .master_key_from_password(OLD_PW.as_bytes())
        .unwrap();
    let key_before = backup_key_from_master_key(&mk_old);
    let ciphertext =
        crypto::encrypt_bundle(&key_before, &bundle::build_bundle(&f.home).unwrap()).unwrap();

    let phrase = f.phrase.clone();
    recover_with_phrase(
        &f.vault(),
        move || Ok(Zeroizing::new(phrase)),
        || Ok(Zeroizing::new(NEW_PW.to_string())),
        &f.caches(),
    )
    .await
    .unwrap();

    let local = f.vault();
    let mk_new = local.master_key_from_password(NEW_PW.as_bytes()).unwrap();
    let key_after = backup_key_from_master_key(&mk_new);
    assert_eq!(
        key_before, key_after,
        "backup key hangs from MK, not the password"
    );
    let tar_bytes = crypto::decrypt_bundle(&key_after, &ciphertext).unwrap();

    let target = f.dir.path().join("staging_restore");
    let report = restore_into_staging(&local, &mk_new, &tar_bytes, &target).unwrap();
    assert!(report.sentinel_replaced);
    assert_eq!(report.vars_reset, 1);
    let staged = Vault::new(target.clone());
    assert!(matches!(
        staged.unlock(OLD_PW.as_bytes(), 30),
        Err(KvendraError::InvalidMasterPassword)
    ));
    staged.unlock(NEW_PW.as_bytes(), 30).unwrap();
    assert_eq!(staged.get_secret("p1").unwrap().as_bytes(), SECRET_1);
    assert_eq!(staged.get_secret("p2").unwrap().as_bytes(), SECRET_2);
    let doc = kvendra::vars::load(&staged).unwrap();
    assert!(!doc.vars["ws"].verified);
    assert_eq!(
        std::fs::read(target.join("sentinel.blob")).unwrap(),
        std::fs::read(f.home.join("sentinel.blob")).unwrap()
    );
    assert_eq!(
        std::fs::read(target.join("recovery.blob")).unwrap(),
        std::fs::read(f.home.join("recovery.blob")).unwrap()
    );
    assert!(no_partial_dirs(f.dir.path()));
}

/// A v2 staging whose vault_id / check does not match the local MK is
/// refused fail-closed and nothing is left behind.
#[tokio::test]
async fn foreign_v2_staging_is_refused_and_not_left_half_built() {
    let a = setup().await;
    let b = setup().await;
    let tar_b = bundle::build_bundle(&b.home).unwrap();
    let local = a.vault();
    let mk_a = local.master_key_from_password(OLD_PW.as_bytes()).unwrap();
    let target = a.dir.path().join("staging_restore");
    let err = restore_into_staging(&local, &mk_a, &tar_b, &target).unwrap_err();
    assert!(
        matches!(err, KvendraError::RecoveryMaterialCorrupt(_)),
        "{err:?}"
    );
    assert!(!target.exists());
    assert!(no_partial_dirs(a.dir.path()));

    // Existing target (`--yes`): untouched on refusal.
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("keep.txt"), b"keep").unwrap();
    assert!(restore_into_staging(&local, &mk_a, &tar_b, &target).is_err());
    assert_eq!(std::fs::read_dir(&target).unwrap().count(), 1);
    assert!(no_partial_dirs(a.dir.path()));
}

/// The backup key of a 0.8.0 (v1) vault is unchanged (frozen vector) and a
/// v1 staging restores as before (sentinel kept as is).
#[test]
fn v1_backup_key_vector_and_v1_restore_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("v1");
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vault-v1");
    std::fs::create_dir_all(home.join("secrets")).unwrap();
    std::fs::copy(fx.join("sentinel.blob"), home.join("sentinel.blob")).unwrap();
    std::fs::copy(
        fx.join("secrets/fixture.profile.blob"),
        home.join("secrets/fixture.profile.blob"),
    )
    .unwrap();
    let local = Vault::new(home.clone());
    let mk = local.master_key_from_password(V1_PASSWORD).unwrap();
    assert_eq!(
        hex::encode(backup_key_from_master_key(&mk)),
        V1_BACKUP_KEY_HEX
    );

    let tar_bytes = bundle::build_bundle(&home).unwrap();
    let target = dir.path().join("staging");
    let report = restore_into_staging(&local, &mk, &tar_bytes, &target).unwrap();
    assert!(!report.sentinel_replaced);
    let staged = Vault::new(target);
    staged.unlock(V1_PASSWORD, 30).unwrap();
    assert_eq!(
        staged.get_secret("fixture.profile").unwrap().as_bytes(),
        b"kvd-fixture-v1-secret-plaintext"
    );
}

fn no_partial_dirs(dir: &Path) -> bool {
    !std::fs::read_dir(dir).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".partial-")
    })
}
