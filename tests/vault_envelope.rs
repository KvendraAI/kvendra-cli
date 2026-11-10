//! REQ-KVD-CLI-CFB449 F1 (ISSUE-KVD-CLI-4D253B) — envelope key hierarchy at
//! the `Vault` level: v1 fixture compatibility (AC-REC-12), v2 sub-key
//! equality across unlock paths, recovery material on disk (AC-REC-2/8).
//!
//! Every vault lives in a fresh tempdir; the v1 fixture is COPIED there so
//! the checked-in files are never touched. All values are invented.

use kvendra::error::KvendraError;
use kvendra::vault::Vault;
use kvendra::vault::envelope::{Sentinel, parse_phrase};
use kvendra::vault::kdf::KdfParams;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const V1_PASSWORD: &[u8] = b"kvd-fixture-v1-password";
const V1_SECRET: &[u8] = b"kvd-fixture-v1-secret-plaintext";
const V1_AUDIT_HMAC_HEX: &str = "d9b3588b2fdb8aecd8beb8497614312aaf3237d9ddfc90d0f2e96a4a6450a75a";
const V1_LOCAL_VARS_HEX: &str = "1ec6e3e8ccbf085a8e0063c03445d99cd8eed8f55eba5a483a318d670eeb1afa";

fn fast_params() -> KdfParams {
    KdfParams {
        m_cost_kib: 19_456,
        t_cost: 2,
        p_cost: 1,
        salt: vec![5u8; 16],
    }
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for e in std::fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        let to = dst.join(e.file_name());
        if e.path().is_dir() {
            copy_dir(&e.path(), &to);
        } else {
            std::fs::copy(e.path(), &to).unwrap();
        }
    }
}

fn v1_fixture() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    copy_dir(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vault-v1"),
        &home,
    );
    std::fs::remove_file(home.join("README.txt")).unwrap();
    (dir, home)
}

fn sha(path: &Path) -> String {
    hex::encode(Sha256::digest(std::fs::read(path).unwrap()))
}

/// AC-REC-12 — a vault written by 0.8.0 opens with its password, its secret
/// decrypts, its sub-keys are the 0.8.0 ones, and nothing on disk changes.
#[test]
fn v1_fixture_opens_unchanged() {
    let (_d, home) = v1_fixture();
    let before = sha(&home.join("sentinel.blob"));
    let v = Vault::new(home.clone());
    assert!(matches!(v.read_sentinel().unwrap(), Sentinel::V1(_)));
    v.unlock(V1_PASSWORD, 30).unwrap();
    assert_eq!(
        v.get_secret("fixture.profile").unwrap().as_bytes(),
        V1_SECRET
    );
    assert_eq!(hex::encode(v.audit_hmac_key().unwrap()), V1_AUDIT_HMAC_HEX);
    assert_eq!(
        hex::encode(v.local_vars_key().unwrap().as_bytes()),
        V1_LOCAL_VARS_HEX
    );
    assert_eq!(
        hex::encode(v.audit_hmac_key_from_password(V1_PASSWORD).unwrap()),
        V1_AUDIT_HMAC_HEX
    );
    // Session-blob path on v1: the derived key still verifies.
    let k = v.peek_session_derived_key().unwrap();
    v.lock();
    v.unlock_from_derived_key(&k, 30).unwrap();
    assert!(matches!(
        Vault::new(home.clone()).unlock(b"kvd-wrong-password", 30),
        Err(KvendraError::InvalidMasterPassword)
    ));
    assert_eq!(
        before,
        sha(&home.join("sentinel.blob")),
        "sentinel rewritten"
    );
    assert!(!home.join("recovery.blob").exists());
    assert!(!v.recovery_available().unwrap());
    assert!(matches!(
        v.open_recovery(
            &parse_phrase(
                &kvendra::vault::envelope::generate_mnemonic()
                    .unwrap()
                    .to_string()
            )
            .unwrap()
        ),
        Err(KvendraError::RecoveryUnavailable)
    ));
}

/// The 7 HKDF sub-keys hang from MK identically whether the session came
/// from the password or from the raw key (session blob path).
#[test]
fn v2_subkeys_identical_across_unlock_paths() {
    let dir = tempfile::tempdir().unwrap();
    let v = Vault::new(dir.path().to_path_buf());
    let m = v
        .create_with_params_returning_material(b"kvd-env-pw-1", fast_params())
        .unwrap();
    v.unlock(b"kvd-env-pw-1", 30).unwrap();
    let a = (
        v.audit_hmac_key().unwrap(),
        v.allowlist_hmac_key().unwrap(),
        v.config_hmac_key().unwrap(),
        v.local_vars_key().unwrap().to_vec(),
        v.peek_session_derived_key().unwrap(),
    );
    v.lock();
    v.unlock_from_derived_key(m.master_key.as_bytes(), 30)
        .unwrap();
    let b = (
        v.audit_hmac_key().unwrap(),
        v.allowlist_hmac_key().unwrap(),
        v.config_hmac_key().unwrap(),
        v.local_vars_key().unwrap().to_vec(),
        v.peek_session_derived_key().unwrap(),
    );
    assert_eq!(a, b);
    assert_eq!(&a.4, m.master_key.as_bytes(), "session key IS the MK");
    // A random key is refused like a wrong password.
    v.lock();
    assert!(matches!(
        v.unlock_from_derived_key(&[7u8; 32], 30),
        Err(KvendraError::InvalidMasterPassword)
    ));
}

/// AC-REC-8 — files are 0600, versions are explicit, the same vault_id is
/// in both files, and nothing derived from the phrase is stored apart from
/// the ciphertext.
#[test]
fn v2_files_format_and_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let v = Vault::new(dir.path().to_path_buf());
    let m = v
        .create_with_params_returning_material(b"kvd-env-pw-1", fast_params())
        .unwrap();
    let s: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(v.sentinel_path()).unwrap()).unwrap();
    let r: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(v.recovery_blob_path()).unwrap()).unwrap();
    assert_eq!(s["version"], 2);
    assert_eq!(r["version"], 1);
    assert_eq!(r["format"], "kvendra-recovery");
    assert_eq!(s["vault_id"], r["vault_id"]);
    let keys: Vec<&String> = r.as_object().unwrap().keys().collect();
    assert_eq!(
        keys.len(),
        6,
        "recovery.blob must only hold format/version/vault_id/kdf/nonce/ciphertext: {keys:?}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [v.sentinel_path(), v.recovery_blob_path()] {
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    let raw = std::fs::read_to_string(v.recovery_blob_path()).unwrap()
        + &std::fs::read_to_string(v.sentinel_path()).unwrap();
    for w in m.mnemonic.to_string().split(' ') {
        assert!(!raw.contains(&format!("\"{w}\"")));
    }
    assert!(!raw.contains(&hex::encode(m.master_key.as_bytes())));
}

/// AC-REC-2 — on disk: the right phrase opens; another vault's phrase is a
/// mismatch; another vault's recovery.blob copied over is corrupt material.
#[test]
fn recovery_on_disk_right_wrong_and_foreign_blob() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let a = Vault::new(a_dir.path().to_path_buf());
    let b = Vault::new(b_dir.path().to_path_buf());
    let ma = a
        .create_with_params_returning_material(b"kvd-env-pw-a", fast_params())
        .unwrap();
    let mb = b
        .create_with_params_returning_material(b"kvd-env-pw-b", fast_params())
        .unwrap();
    assert!(a.recovery_available().unwrap());
    let mk = a
        .open_recovery(&parse_phrase(&ma.mnemonic.to_string()).unwrap())
        .unwrap();
    assert!(mk.ct_eq(&ma.master_key));
    assert!(matches!(
        a.open_recovery(&mb.mnemonic),
        Err(KvendraError::RecoveryPhraseMismatch)
    ));
    std::fs::copy(b.recovery_blob_path(), a.recovery_blob_path()).unwrap();
    assert!(matches!(
        a.open_recovery(&mb.mnemonic),
        Err(KvendraError::RecoveryMaterialCorrupt(_))
    ));
    std::fs::remove_file(a.recovery_blob_path()).unwrap();
    assert!(!a.recovery_available().unwrap());
    assert!(matches!(
        a.open_recovery(&ma.mnemonic),
        Err(KvendraError::RecoveryUnavailable)
    ));
}

/// AC-REC-8 — a sentinel with an unknown version refuses every entry point.
#[test]
fn unknown_sentinel_version_refuses_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let v = Vault::new(dir.path().to_path_buf());
    v.create_with_params(b"kvd-env-pw-1", fast_params())
        .unwrap();
    let raw = std::fs::read_to_string(v.sentinel_path()).unwrap();
    let mut j: serde_json::Value = serde_json::from_str(&raw).unwrap();
    j["version"] = 3.into();
    std::fs::write(v.sentinel_path(), j.to_string()).unwrap();
    for r in [
        v.unlock(b"kvd-env-pw-1", 30).map(|_| ()),
        v.unlock_from_derived_key(&[0u8; 32], 30),
        v.audit_hmac_key_from_password(b"kvd-env-pw-1").map(|_| ()),
        v.local_vars_key_from_password(b"kvd-env-pw-1").map(|_| ()),
    ] {
        let e = r.unwrap_err();
        assert!(
            e.to_string()
                .contains("unsupported sentinel format version 3"),
            "{e}"
        );
    }
}
