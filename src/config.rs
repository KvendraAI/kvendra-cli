//! Configuration loaded from `~/.kvendra/config.toml`.
//!
//! Per ADR-KVD-012, `master_password.cache` defaults to `ram-only` and
//! `idle_timeout_minutes` defaults to 30. Detection severity defaults to
//! `warn` (REQ-KVD-002 AC-DET-2).

use crate::error::{KvendraError, KvendraResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Cache mode for the derived master key (ADR-KVD-012).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MasterPasswordCache {
    #[default]
    RamOnly,
    OsKeychain,
}

/// Detection layer severity (REQ-KVD-002 Bloque 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectionSeverity {
    #[default]
    Warn,
    Error,
    Block,
}

/// Top-level configuration document.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub vault: VaultConfig,
    pub detection: DetectionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VaultConfig {
    pub master_password_cache: MasterPasswordCache,
    pub idle_timeout_minutes: u32,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            master_password_cache: MasterPasswordCache::default(),
            idle_timeout_minutes: 30,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DetectionConfig {
    pub severity: DetectionSeverity,
}

impl Config {
    /// Load `~/.kvendra/config.toml` or return defaults when absent.
    pub fn load(home: &Path) -> KvendraResult<Self> {
        let path = home.join("config.toml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path)?;
        let cfg: Config = toml::from_str(&raw).map_err(|e| KvendraError::Config(e.to_string()))?;
        Ok(cfg)
    }

    /// Persist to `~/.kvendra/config.toml`.
    pub fn save(&self, home: &Path) -> KvendraResult<()> {
        let path = home.join("config.toml");
        let raw = toml::to_string_pretty(self).map_err(|e| KvendraError::Config(e.to_string()))?;
        std::fs::write(&path, raw)?;
        set_file_mode_secure(&path)?;
        Ok(())
    }
}

/// Compute the kvendra home directory.
///
/// Honours `$KVENDRA_HOME` for testing/sandboxing, falling back to
/// `~/.kvendra/` (`$HOME/.kvendra/`).
pub fn kvendra_home() -> KvendraResult<PathBuf> {
    if let Some(p) = std::env::var_os("KVENDRA_HOME")
        && !p.is_empty()
    {
        return Ok(PathBuf::from(p));
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| KvendraError::Config("HOME env var not set".into()))?;
    Ok(home.join(".kvendra"))
}

/// Ensure the `~/.kvendra/` layout exists.
pub fn ensure_layout(home: &Path) -> KvendraResult<()> {
    create_dir_secure(home)?;
    create_dir_secure(&home.join("secrets"))?;
    create_dir_secure(&home.join("allowlists"))?;
    create_dir_secure(&home.join("profiles"))?;
    Ok(())
}

/// Create a directory (idempotent) and tighten Unix perms to 0700.
///
/// Convention used by `~/.ssh`, `~/.gnupg`, `~/.password-store`. Other local
/// users cannot enumerate or enter the directory (defence-in-depth on top of
/// the per-file 0600 perms — see THREAT-MODEL V2).
pub fn create_dir_secure(path: &Path) -> KvendraResult<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

/// Set Unix perms of an existing file to 0600 (no-op on non-Unix).
///
/// Apply right after writing any sensitive vault file (sentinel, config,
/// recovery hashes, audit DB, profile blobs / metadata). Defence-in-depth.
pub fn set_file_mode_secure(path: &Path) -> KvendraResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
