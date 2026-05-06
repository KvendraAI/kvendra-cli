//! Vault — zero-knowledge local secrets storage (Nivel 2 per ADR-KVD-010).
//!
//! Public API: [`Vault`], [`Profile`].

pub mod blob;
pub mod crypto;
pub mod kdf;
pub mod recovery;
pub mod session;

use crate::error::{KvendraError, KvendraResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Logical identifier of a stored credential profile.
pub type ProfileId = String;

/// Metadata wrapper persisted alongside the encrypted secret blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub profile_id: ProfileId,
    pub secret_type: String,
    pub created_at: String,
    pub expiration: Option<String>,
}

/// Top-level vault handle: paths + minimal metadata.
pub struct Vault {
    home: PathBuf,
}

impl Vault {
    pub fn new(home: PathBuf) -> Self {
        Self { home }
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

    pub fn recovery_blob_path(&self) -> PathBuf {
        self.home.join("recovery.blob")
    }

    pub fn recovery_codes_path(&self) -> PathBuf {
        self.home.join("recovery_codes.json")
    }

    pub fn audit_db_path(&self) -> PathBuf {
        self.home.join("audit.db")
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
}

impl From<KvendraError> for std::io::Error {
    fn from(err: KvendraError) -> Self {
        std::io::Error::other(err.to_string())
    }
}
