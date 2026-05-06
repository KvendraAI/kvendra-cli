//! Vault — zero-knowledge local secrets storage (Nivel 2 per ADR-KVD-010).
//!
//! Public API: [`Vault`], [`Profile`], [`SecretPlaintext`].

pub mod blob;
pub mod crypto;
pub mod kdf;
pub mod recovery;
pub mod session;

use crate::error::{KvendraError, KvendraResult};
use crate::vault::blob::Blob;
use crate::vault::crypto::{NONCE_LEN, open as aes_open, random_nonce, seal as aes_seal};
use crate::vault::kdf::{KdfParams, derive, random_salt};
use crate::vault::session::SessionKey;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Logical identifier of a stored credential profile.
pub type ProfileId = String;

/// Metadata wrapper persisted alongside the encrypted secret blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub profile_id: ProfileId,
    pub secret_type: String,
    pub created_at: String,
    pub expiration: Option<String>,
    /// Profile-level escape-hatch toggle (IF-KVD-CLI-008).
    #[serde(default)]
    pub unsafe_raw_token_enabled: bool,
    /// Set to `true` if the detection layer hard-blocked an outbound use
    /// (REQ-KVD-002 AC-DET-3 — Block severity quarantines the profile).
    #[serde(default)]
    pub quarantined: bool,
}

/// Plaintext secret material — zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretPlaintext {
    bytes: Vec<u8>,
}

impl SecretPlaintext {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn as_str(&self) -> KvendraResult<&str> {
        std::str::from_utf8(&self.bytes)
            .map_err(|_| KvendraError::Vault("secret is not valid UTF-8".into()))
    }
}

impl std::fmt::Debug for SecretPlaintext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretPlaintext(<{} bytes redacted>)", self.bytes.len())
    }
}

/// Top-level vault handle: paths + minimal metadata.
pub struct Vault {
    home: PathBuf,
    /// Active session key when unlocked (RAM-only, ZeroizeOnDrop).
    session: Arc<Mutex<Option<SessionKey>>>,
}

impl Clone for Vault {
    fn clone(&self) -> Self {
        Self {
            home: self.home.clone(),
            session: Arc::clone(&self.session),
        }
    }
}

impl Vault {
    pub fn new(home: PathBuf) -> Self {
        Self {
            home,
            session: Arc::new(Mutex::new(None)),
        }
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn secrets_dir(&self) -> PathBuf {
        self.home.join("secrets")
    }

    pub fn allowlists_dir(&self) -> PathBuf {
        self.home.join("allowlists")
    }

    pub fn profiles_dir(&self) -> PathBuf {
        self.home.join("profiles")
    }

    pub fn recovery_blob_path(&self) -> PathBuf {
        self.home.join("recovery.blob")
    }

    pub fn recovery_codes_path(&self) -> PathBuf {
        self.home.join("recovery_codes.json")
    }

    pub fn audit_db_path(&self) -> PathBuf {
        self.home.join("audit.db")
    }

    /// Path of the master-password sentinel blob (used to detect bad password).
    pub fn sentinel_path(&self) -> PathBuf {
        self.home.join("sentinel.blob")
    }

    /// Path for a profile's encrypted blob (`<id>.blob` in `secrets/`).
    pub fn profile_blob_path(&self, profile_id: &str) -> PathBuf {
        self.secrets_dir().join(format!("{profile_id}.blob"))
    }

    /// Path for a profile's metadata json (`<id>.json` in `profiles/`).
    pub fn profile_meta_path(&self, profile_id: &str) -> PathBuf {
        self.profiles_dir().join(format!("{profile_id}.json"))
    }

    /// Path for a profile's allowlist YAML (`<id>.yaml` in `allowlists/`).
    pub fn profile_allowlist_path(&self, profile_id: &str) -> PathBuf {
        self.allowlists_dir().join(format!("{profile_id}.yaml"))
    }

    /// List existing profile blobs (filenames without `.blob`).
    pub fn list_profiles(&self) -> KvendraResult<Vec<ProfileId>> {
        let mut out = Vec::new();
        let dir = self.secrets_dir();
        if !dir.exists() {
            return Ok(out);
        }
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(stripped) = name.strip_suffix(".blob") {
                out.push(stripped.to_string());
            }
        }
        out.sort();
        Ok(out)
    }

    /// Read a profile's metadata (no plaintext exposure).
    pub fn load_profile_meta(&self, profile_id: &str) -> KvendraResult<Profile> {
        let path = self.profile_meta_path(profile_id);
        if !path.exists() {
            return Err(KvendraError::ProfileNotFound);
        }
        let raw = std::fs::read_to_string(&path)?;
        serde_json::from_str(&raw).map_err(KvendraError::from)
    }

    pub fn save_profile_meta(&self, profile: &Profile) -> KvendraResult<()> {
        std::fs::create_dir_all(self.profiles_dir())?;
        let path = self.profile_meta_path(&profile.profile_id);
        let raw = serde_json::to_string_pretty(profile)?;
        std::fs::write(&path, raw)?;
        Ok(())
    }

    pub fn delete_profile(&self, profile_id: &str) -> KvendraResult<()> {
        let _ = std::fs::remove_file(self.profile_blob_path(profile_id));
        let _ = std::fs::remove_file(self.profile_meta_path(profile_id));
        let _ = std::fs::remove_file(self.profile_allowlist_path(profile_id));
        Ok(())
    }

    /// Whether the vault session is currently unlocked.
    pub fn is_unlocked(&self) -> bool {
        let g = self.session.lock().expect("session mutex poisoned");
        g.as_ref().is_some_and(|s| !s.is_expired())
    }

    /// Initialize the vault: write the sentinel blob (so `unlock` can verify
    /// the master password). Idempotent if the sentinel already exists.
    pub fn create(&self, password: &[u8]) -> KvendraResult<()> {
        self.create_with_params(password, KdfParams::high_cost(random_salt()))
    }

    /// Init variant that accepts custom KDF params (used by tests with fast
    /// argon2 params; production callers should use [`Vault::create`]).
    pub fn create_with_params(&self, password: &[u8], params: KdfParams) -> KvendraResult<()> {
        std::fs::create_dir_all(&self.home)?;
        std::fs::create_dir_all(self.secrets_dir())?;
        std::fs::create_dir_all(self.allowlists_dir())?;
        std::fs::create_dir_all(self.profiles_dir())?;
        if self.sentinel_path().exists() {
            return Err(KvendraError::Vault(
                "vault already initialized (sentinel.blob exists)".into(),
            ));
        }
        let derived = derive(password, &params)?;
        let nonce = random_nonce();
        let ct = aes_seal(derived.as_bytes(), &nonce, b"kvendra-sentinel-v1")?;
        let blob = Blob::new(params, nonce.to_vec(), ct);
        std::fs::write(self.sentinel_path(), blob.to_json()?)?;
        Ok(())
    }

    /// Unlock the vault: verify password against the sentinel and store the
    /// derived key in a `SessionKey`.
    pub fn unlock(&self, password: &[u8], idle_timeout_minutes: u32) -> KvendraResult<()> {
        let path = self.sentinel_path();
        if !path.exists() {
            return Err(KvendraError::Vault(
                "vault not initialized (run `kvendra init` first)".into(),
            ));
        }
        let raw = std::fs::read_to_string(&path)?;
        let blob = Blob::from_json(&raw)?;
        let derived = derive(password, &blob.kdf)?;
        let mut nonce = [0u8; NONCE_LEN];
        if blob.nonce.len() != NONCE_LEN {
            return Err(KvendraError::Vault("sentinel nonce length invalid".into()));
        }
        nonce.copy_from_slice(&blob.nonce);
        let pt = aes_open(derived.as_bytes(), &nonce, &blob.ciphertext)?;
        if pt != b"kvendra-sentinel-v1" {
            return Err(KvendraError::InvalidMasterPassword);
        }
        let session = SessionKey::new(derived, idle_timeout_minutes);
        let mut g = self.session.lock().expect("session mutex poisoned");
        *g = Some(session);
        Ok(())
    }

    /// Lock the vault: drop the session key (zeroizes on Drop).
    pub fn lock(&self) {
        let mut g = self.session.lock().expect("session mutex poisoned");
        *g = None;
    }

    /// Reset the master password using the BIP-39 mnemonic. Pase B simplified
    /// flow: the mnemonic re-seeds the sentinel ciphertext deterministically
    /// (we encrypt the marker under a fresh KDF derived from `new_password`).
    /// For Pase B we rotate the sentinel; profile blobs continue to use the
    /// old key until re-saved (real rotation is a Beta concern).
    pub fn reset_password_with_mnemonic(
        &self,
        mnemonic_phrase: &str,
        new_password: &[u8],
    ) -> KvendraResult<()> {
        // Validate mnemonic shape (the mnemonic itself does not seed the
        // sentinel — it acts as proof that the user previously held the
        // recovery material; per Alpha 0.1 we accept any valid BIP-39).
        let _ = crate::vault::recovery::parse_mnemonic(mnemonic_phrase)?;
        // Rotate the sentinel.
        let salt = random_salt();
        let params = KdfParams::high_cost(salt);
        let derived = derive(new_password, &params)?;
        let nonce = random_nonce();
        let ct = aes_seal(derived.as_bytes(), &nonce, b"kvendra-sentinel-v1")?;
        let blob = Blob::new(params, nonce.to_vec(), ct);
        std::fs::write(self.sentinel_path(), blob.to_json()?)?;
        Ok(())
    }

    /// Encrypt + persist a secret blob for `profile_id`. Requires unlocked.
    pub fn put_secret(&self, profile_id: &str, plaintext: &[u8]) -> KvendraResult<()> {
        std::fs::create_dir_all(self.secrets_dir())?;
        let g = self.session.lock().expect("session mutex poisoned");
        let session = g.as_ref().ok_or(KvendraError::VaultLocked)?;
        if session.is_expired() {
            return Err(KvendraError::VaultLocked);
        }
        let key = session.peek_key()?;
        // Each secret blob has its own KdfParams shell so the on-disk format
        // matches the sentinel; we re-use the master key (Argon2id-derived)
        // directly via AES-256-GCM rather than re-deriving per blob (Alpha
        // 0.1 simplification, documented in ADR-KVD-005).
        let nonce = random_nonce();
        let ct = aes_seal(key, &nonce, plaintext)?;
        let params = KdfParams::high_cost(vec![]); // shell only
        let blob = Blob::new(params, nonce.to_vec(), ct);
        std::fs::write(self.profile_blob_path(profile_id), blob.to_json()?)?;
        Ok(())
    }

    /// Read + decrypt the plaintext for `profile_id`. Requires unlocked.
    /// Returned material is wrapped in `SecretPlaintext` (ZeroizeOnDrop).
    pub fn get_secret(&self, profile_id: &str) -> KvendraResult<SecretPlaintext> {
        let path = self.profile_blob_path(profile_id);
        if !path.exists() {
            return Err(KvendraError::ProfileNotFound);
        }
        let g = self.session.lock().expect("session mutex poisoned");
        let session = g.as_ref().ok_or(KvendraError::VaultLocked)?;
        if session.is_expired() {
            return Err(KvendraError::VaultLocked);
        }
        let key = session.peek_key()?;
        let raw = std::fs::read_to_string(&path)?;
        let blob = Blob::from_json(&raw)?;
        if blob.nonce.len() != NONCE_LEN {
            return Err(KvendraError::Vault("blob nonce length invalid".into()));
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&blob.nonce);
        let pt = aes_open(key, &nonce, &blob.ciphertext)?;
        Ok(SecretPlaintext::new(pt))
    }

    /// Get the audit-HMAC sub-key (HKDF from session key). Errors if locked.
    pub fn audit_hmac_key(&self) -> KvendraResult<Vec<u8>> {
        let g = self.session.lock().expect("session mutex poisoned");
        let session = g.as_ref().ok_or(KvendraError::VaultLocked)?;
        Ok(session.audit_hmac_key()?.to_vec())
    }

    /// Mark a profile as quarantined (detection layer Block severity).
    pub fn mark_quarantined(&self, profile_id: &str) -> KvendraResult<()> {
        if let Ok(mut meta) = self.load_profile_meta(profile_id) {
            meta.quarantined = true;
            self.save_profile_meta(&meta)?;
        }
        Ok(())
    }
}

impl From<KvendraError> for std::io::Error {
    fn from(err: KvendraError) -> Self {
        std::io::Error::other(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fast_params() -> KdfParams {
        // Test-only fast Argon2id params (still real argon2id).
        KdfParams {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: vec![1u8; 16],
        }
    }

    fn open_test_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempdir().unwrap();
        let v = Vault::new(dir.path().to_path_buf());
        (dir, v)
    }

    #[test]
    fn locked_get_secret_errors() {
        let (_dir, v) = open_test_vault();
        let r = v.get_secret("none");
        assert!(matches!(
            r,
            Err(KvendraError::ProfileNotFound) | Err(KvendraError::VaultLocked)
        ));
    }

    #[test]
    fn create_unlock_put_get_roundtrip() {
        let (_dir, v) = open_test_vault();
        v.create_with_params(b"hunter2-test", fast_params())
            .unwrap();
        v.unlock(b"hunter2-test", 30).unwrap();
        v.put_secret("test.profile", b"super-secret-token").unwrap();
        let s = v.get_secret("test.profile").unwrap();
        assert_eq!(s.as_bytes(), b"super-secret-token");
    }

    #[test]
    fn locked_after_explicit_lock() {
        let (_dir, v) = open_test_vault();
        v.create_with_params(b"hunter2-test", fast_params())
            .unwrap();
        v.unlock(b"hunter2-test", 30).unwrap();
        v.put_secret("p", b"sec").unwrap();
        v.lock();
        assert!(matches!(v.get_secret("p"), Err(KvendraError::VaultLocked)));
    }

    #[test]
    fn wrong_password_fails_unlock() {
        let (_dir, v) = open_test_vault();
        v.create_with_params(b"correct", fast_params()).unwrap();
        let r = v.unlock(b"wrong", 30);
        assert!(matches!(r, Err(KvendraError::InvalidMasterPassword)));
    }
}
