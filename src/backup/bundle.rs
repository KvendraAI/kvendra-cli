//! Bundle build / extract — tar a directorio del vault.
//!
//! Inclusion list (per AC-BACKUP-1):
//!   - `secrets/*.blob`
//!   - `allowlists/*.yaml*`
//!   - `config.toml` (+ `.hmac` sidecar si existe)
//!   - `audit.db` (best-effort — bloqueado por WAL si MCP serve está corriendo)
//!   - `sentinel.blob`
//!   - `recovery_codes.json`
//!
//! Excluidos: `cache/`, `sessions/<workspace>.token`, archivos temporales.

use crate::error::{KvendraError, KvendraResult};
use std::io::{Read, Write};
use std::path::Path;
use tar::{Builder, Header};

const INCLUDE_TOP_LEVEL: &[&str] = &[
    "config.toml",
    "config.toml.hmac",
    "audit.db",
    "sentinel.blob",
    "recovery_codes.json",
];

const INCLUDE_DIRS: &[&str] = &["secrets", "allowlists"];

/// Build a tarball of the vault home directory. Returns bytes in memory.
pub fn build_bundle(home: &Path) -> KvendraResult<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut builder = Builder::new(&mut buf);
        builder.mode(tar::HeaderMode::Deterministic);

        for name in INCLUDE_TOP_LEVEL {
            let p = home.join(name);
            if p.is_file() {
                append_file(&mut builder, &p, name)?;
            }
        }
        for dir in INCLUDE_DIRS {
            let dp = home.join(dir);
            if !dp.is_dir() {
                continue;
            }
            let entries = std::fs::read_dir(&dp)?;
            for ent in entries {
                let ent = ent?;
                let path = ent.path();
                if !path.is_file() {
                    continue;
                }
                let rel = format!(
                    "{}/{}",
                    dir,
                    ent.file_name().to_string_lossy()
                );
                append_file(&mut builder, &path, &rel)?;
            }
        }
        builder
            .finish()
            .map_err(|e| KvendraError::Vault(format!("tar finish: {e}")))?;
    }
    Ok(buf)
}

fn append_file<W: Write>(
    builder: &mut Builder<W>,
    path: &Path,
    name: &str,
) -> KvendraResult<()> {
    let bytes = std::fs::read(path)?;
    let mut header = Header::new_gnu();
    header
        .set_path(name)
        .map_err(|e| KvendraError::Vault(format!("tar set_path: {e}")))?;
    header.set_size(bytes.len() as u64);
    header.set_mode(0o600);
    header.set_cksum();
    builder
        .append(&header, bytes.as_slice())
        .map_err(|e| KvendraError::Vault(format!("tar append: {e}")))?;
    Ok(())
}

/// Extract a previously built tarball to `target_dir`. Caller is responsible
/// for backing up any existing files in `target_dir` first (per AC-BACKUP-2:
/// confirm-before-overwrite is handled at CLI layer).
pub fn extract_bundle(bytes: &[u8], target_dir: &Path) -> KvendraResult<usize> {
    std::fs::create_dir_all(target_dir)?;
    let mut archive = tar::Archive::new(bytes);
    let mut count = 0usize;
    for entry in archive
        .entries()
        .map_err(|e| KvendraError::Vault(format!("tar entries: {e}")))?
    {
        let mut entry = entry.map_err(|e| KvendraError::Vault(format!("tar entry: {e}")))?;
        let rel_path = entry
            .path()
            .map_err(|e| KvendraError::Vault(format!("tar path: {e}")))?
            .into_owned();
        let dest = target_dir.join(&rel_path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut bytes: Vec<u8> = Vec::new();
        entry.read_to_end(&mut bytes)?;
        std::fs::write(&dest, bytes)?;
        // Restore 0600 permissions on UNIX.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perm = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&dest, perm)?;
        }
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_fake_vault(dir: &Path) {
        std::fs::write(dir.join("config.toml"), b"[vault]\n").unwrap();
        std::fs::write(dir.join("sentinel.blob"), b"sentinel-bytes").unwrap();
        let secrets = dir.join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        std::fs::write(secrets.join("profile-alpha.blob"), b"opaque").unwrap();
        std::fs::write(secrets.join("profile-beta.blob"), b"opaque2").unwrap();
        let aw = dir.join("allowlists");
        std::fs::create_dir_all(&aw).unwrap();
        std::fs::write(aw.join("profile-alpha.yaml"), b"---\n").unwrap();
    }

    #[test]
    fn build_and_extract_roundtrip() {
        let src = TempDir::new().unwrap();
        make_fake_vault(src.path());
        let bytes = build_bundle(src.path()).expect("build");
        assert!(!bytes.is_empty());

        let dst = TempDir::new().unwrap();
        let n = extract_bundle(&bytes, dst.path()).expect("extract");
        assert!(n >= 4, "expected ≥4 entries, got {n}");

        let cfg = std::fs::read(dst.path().join("config.toml")).unwrap();
        assert_eq!(cfg, b"[vault]\n");
        let alpha = std::fs::read(dst.path().join("secrets/profile-alpha.blob")).unwrap();
        assert_eq!(alpha, b"opaque");
        let allow = std::fs::read(dst.path().join("allowlists/profile-alpha.yaml")).unwrap();
        assert_eq!(allow, b"---\n");
    }

    #[test]
    fn empty_vault_yields_minimal_tar() {
        let src = TempDir::new().unwrap();
        let bytes = build_bundle(src.path()).expect("build");
        // Header + empty trailer = ~1024 bytes minimum.
        assert!(bytes.len() >= 512, "tar too short: {}", bytes.len());
    }
}
