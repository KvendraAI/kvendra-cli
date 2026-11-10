//! Shared fixture for the recovery / passwd tests (REQ-KVD-CLI-CFB449).
//! Every vault lives in a fresh tempdir; the keychain is ALWAYS the
//! file-backed fake (`FileCredentialCaches`): no test reads or deletes the
//! machine's real `kvendra/derived-key/v1` / `kvendra/mcp-password/v1`.
//! All values are invented (`kvd-rec-*`).

#![allow(dead_code)]

use kvendra::config::Config;
use kvendra::rekey::{
    FileCredentialCaches, KEYCHAIN_DERIVED_KEY_LABEL, KEYCHAIN_MCP_PASSWORD_LABEL,
    LEGACY_WRAPPER_NAME,
};
use kvendra::vars::{self, VarType};
use kvendra::vault::kdf::KdfParams;
use kvendra::vault::{Profile, Vault, compute_allowlist_hmac};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const OLD_PW: &str = "kvd-rec-old-password";
pub const NEW_PW: &str = "kvd-rec-new-password";
pub const SECRET_1: &[u8] = b"kvd-rec-secret-one-7f3a";
pub const SECRET_2: &[u8] = b"kvd-rec-secret-two-91c2";
pub const VAR_VALUE: &str = "kvd-rec-var-value";
pub const ALLOWLIST: &[u8] = b"version: 1\nprofile_id: p1\n";

pub fn fast_params() -> KdfParams {
    KdfParams {
        m_cost_kib: 19_456,
        t_cost: 2,
        p_cost: 1,
        salt: vec![9u8; 16],
    }
}

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub home: PathBuf,
    pub keychain: PathBuf,
    pub phrase: String,
    pub grant_pubkey: Vec<u8>,
}

impl Fixture {
    pub fn vault(&self) -> Vault {
        Vault::new(self.home.clone())
    }

    pub fn caches(&self) -> FileCredentialCaches {
        FileCredentialCaches {
            dir: self.keychain.clone(),
        }
    }
}

/// init (v2) → 2 secrets + signed allowlist + 1 local var + signed config +
/// audit row + grant keypair + live session blob + fake keychain entries +
/// legacy wrapper. Vault left locked.
pub async fn setup() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    kvendra::config::ensure_layout(&home).unwrap();
    let v = Vault::new(home.clone());
    let m = v
        .create_with_params_returning_material(OLD_PW.as_bytes(), fast_params())
        .unwrap();
    v.unlock(OLD_PW.as_bytes(), 30).unwrap();
    v.put_secret("p1", SECRET_1).unwrap();
    v.put_secret("p2", SECRET_2).unwrap();
    std::fs::write(v.profile_allowlist_path("p1"), ALLOWLIST).unwrap();
    v.save_profile_meta(&Profile {
        profile_id: "p1".into(),
        secret_type: "generic".into(),
        created_at: "2026-11-10".into(),
        expiration: None,
        unsafe_raw_token_enabled: false,
        quarantined: false,
        allowlist_hmac_hex: Some(compute_allowlist_hmac(
            &v.allowlist_hmac_key().unwrap(),
            ALLOWLIST,
        )),
    })
    .unwrap();
    vars::set_var(&v, "ws", VarType::String, VAR_VALUE, true).unwrap();
    Config::default().save(&home, &v).unwrap();
    kvendra::audit::bootstrap::write_vault_created_event(
        &v.audit_db_path(),
        v.audit_hmac_key().unwrap(),
        "test",
    )
    .await
    .unwrap();
    let grant = kvendra::grant::keypair::load_or_generate(&home, &v).unwrap();
    let state = kvendra::session::local::build_state_for_current_machine(
        v.peek_session_derived_key().unwrap(),
        std::time::Duration::from_secs(3600),
        &home,
    )
    .unwrap();
    kvendra::session::local::persist_atomic(&state, &home).unwrap();
    v.lock();

    let keychain = dir.path().join("fake-keychain");
    std::fs::create_dir_all(&keychain).unwrap();
    let fake = FileCredentialCaches {
        dir: keychain.clone(),
    };
    std::fs::write(fake.entry_path(KEYCHAIN_DERIVED_KEY_LABEL), "flag").unwrap();
    std::fs::write(fake.entry_path(KEYCHAIN_MCP_PASSWORD_LABEL), OLD_PW).unwrap();
    // Both entries are bound to THIS vault (owner tag = its vault_id).
    use kvendra::rekey::CredentialCaches;
    let id = m.vault_id.to_hex();
    fake.set_owner(KEYCHAIN_DERIVED_KEY_LABEL, &id).unwrap();
    fake.set_owner(KEYCHAIN_MCP_PASSWORD_LABEL, &id).unwrap();
    std::fs::create_dir_all(home.join("wrappers")).unwrap();
    std::fs::write(
        home.join("wrappers").join(LEGACY_WRAPPER_NAME),
        "#!/bin/sh\n",
    )
    .unwrap();

    Fixture {
        dir,
        home,
        keychain,
        phrase: m.mnemonic.to_string(),
        grant_pubkey: grant.verifying_key().to_bytes().to_vec(),
    }
}

/// SHA-256 of every file under `root`, keyed by relative path.
pub fn hashes(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            // Empty advisory lock files (`.rekey.lock`, `.init.lock`,
            // `sessions/active.blob.lock`) hold no vault data, and on Windows
            // a file locked by another handle cannot be read.
            if p.extension().is_some_and(|e| e == "lock") {
                continue;
            }
            if p.is_dir() {
                walk(root, &p, out);
            } else {
                // Forward slashes on every OS, so prefixes like "sessions/"
                // in `hashes_except` also match on Windows.
                let rel = p
                    .strip_prefix(root)
                    .unwrap()
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                out.insert(rel, hex::encode(Sha256::digest(std::fs::read(&p).unwrap())));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// `hashes` without the entries the AC lets change.
pub fn hashes_except(root: &Path, skip: &[&str]) -> BTreeMap<String, String> {
    hashes(root)
        .into_iter()
        .filter(|(k, _)| !skip.iter().any(|s| k.starts_with(s)))
        .collect()
}

/// Which password opens the vault now (exactly one must).
pub fn opening_password(home: &Path) -> &'static str {
    let old = Vault::new(home.to_path_buf())
        .unlock(OLD_PW.as_bytes(), 30)
        .is_ok();
    let new = Vault::new(home.to_path_buf())
        .unlock(NEW_PW.as_bytes(), 30)
        .is_ok();
    match (old, new) {
        (true, false) => OLD_PW,
        (false, true) => NEW_PW,
        other => panic!("vault opens with (old, new) = {other:?}: mixed or bricked state"),
    }
}

/// Everything the fixture stored is intact under `pw` (AC-REC-1 / 14).
pub fn assert_all_intact(f: &Fixture, pw: &str) {
    let v = f.vault();
    v.unlock(pw.as_bytes(), 30).unwrap();
    assert_eq!(v.get_secret("p1").unwrap().as_bytes(), SECRET_1);
    assert_eq!(v.get_secret("p2").unwrap().as_bytes(), SECRET_2);
    let meta = v.load_profile_meta("p1").unwrap();
    assert_eq!(
        meta.allowlist_hmac_hex.unwrap(),
        compute_allowlist_hmac(&v.allowlist_hmac_key().unwrap(), ALLOWLIST),
        "allowlist HMAC"
    );
    Config::load(&f.home, Some(&v)).expect("signed config verifies");
    let doc = vars::load(&v).unwrap();
    assert_eq!(doc.vars["ws"].value.as_str(), VAR_VALUE);
    let conn = kvendra::audit::reader::open_readonly(&v.audit_db_path()).unwrap();
    kvendra::audit::reader::verify_chain(&conn, &v.audit_hmac_key().unwrap())
        .expect("audit chain verifies");
    let grant = kvendra::grant::keypair::load_or_generate(&f.home, &v).unwrap();
    assert_eq!(
        grant.verifying_key().to_bytes().to_vec(),
        f.grant_pubkey,
        "grant key"
    );
}

pub fn audit_rows(home: &Path) -> Vec<kvendra::audit::reader::StoredEvent> {
    let conn = kvendra::audit::reader::open_readonly(&home.join("audit.db")).unwrap();
    kvendra::audit::reader::list_all(&conn).unwrap()
}

/// Grep helper for AC-REC-7: no phrase word sequence, no password.
pub fn assert_no_secret_text(bytes: &[u8], f: &Fixture, label: &str) {
    let s = String::from_utf8_lossy(bytes);
    for needle in [OLD_PW, NEW_PW, f.phrase.as_str()] {
        assert!(!s.contains(needle), "{label} contains a secret");
    }
    let words: Vec<&str> = f.phrase.split(' ').collect();
    for pair in words.windows(2) {
        assert!(
            !s.contains(&pair.join(" ")),
            "{label} contains phrase words"
        );
    }
}

/// Another vault's valid phrase.
pub fn foreign_phrase() -> String {
    kvendra::vault::envelope::generate_mnemonic()
        .unwrap()
        .to_string()
}
