//! Durable file writes for the vault commit paths (init / recover / passwd).

use crate::error::KvendraResult;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Create `path` exclusively (fails if it exists), mode 0600 from the
/// start on unix, write `bytes` and fsync it.
pub fn write_new_synced(path: &Path, bytes: &[u8]) -> KvendraResult<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    #[cfg(not(unix))]
    crate::config::set_file_mode_secure(path)?;
    Ok(())
}

/// fsync a directory so a rename inside it is durable (no-op off unix).
pub fn fsync_dir(dir: &Path) -> KvendraResult<()> {
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// `path` + `.<suffix>` in the same directory.
pub fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".");
    s.push(suffix);
    PathBuf::from(s)
}

/// Atomic replace: write a fresh sibling tmp (0600, fsync), rename it over
/// `path`, fsync the directory. `path` is either the old or the new content
/// at any instant.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> KvendraResult<()> {
    let tmp = sibling(path, &format!("tmp-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    if let Err(e) = write_new_synced(&tmp, bytes) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    if let Some(parent) = path.parent() {
        fsync_dir(parent)?;
    }
    Ok(())
}
