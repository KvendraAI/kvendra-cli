//! Durable file writes for the vault commit paths (init / recover / passwd).

use crate::error::KvendraResult;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Open `path` for a NEW file: exclusive create (fails if anything exists
/// there, including a dangling symlink), `O_NOFOLLOW`, mode 0600 from the
/// creation on unix (no umask window).
pub fn create_new_secure(path: &Path) -> KvendraResult<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    Ok(opts.open(path)?)
}

/// Create `path` exclusively (fails if it exists), mode 0600 from the
/// start on unix, write `bytes` and fsync it.
pub fn write_new_synced(path: &Path, bytes: &[u8]) -> KvendraResult<()> {
    let mut file = create_new_secure(path)?;
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

/// Exclusive advisory lock on `path` (created 0600 if missing); released on
/// drop. `Ok(None)` when another process holds it.
pub struct FileLock {
    file: std::fs::File,
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

pub fn try_lock_exclusive(path: &Path) -> KvendraResult<Option<FileLock>> {
    use fs2::FileExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts.open(path)?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(Some(FileLock { file })),
        Err(e)
            if e.kind() == fs2::lock_contended_error().kind()
                || e.kind() == std::io::ErrorKind::WouldBlock =>
        {
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}

/// Publish `tmp` at `dst` WITHOUT overwriting: hard link + unlink of the
/// tmp (`dst` existing → `AlreadyExists`). Where hard links are not
/// supported, falls back to "check then rename", which the caller must
/// serialize with a lock.
pub fn publish_no_overwrite(tmp: &Path, dst: &Path) -> std::io::Result<()> {
    match std::fs::hard_link(tmp, dst) {
        Ok(()) => {
            let _ = std::fs::remove_file(tmp);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(e),
        Err(_) => {
            if dst.exists() {
                return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists));
            }
            std::fs::rename(tmp, dst)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M1 — the file is 0600 at creation (checked on the open handle before
    /// any chmod) and a symlink or existing file is refused untouched.
    #[cfg(unix)]
    #[test]
    fn create_new_secure_is_0600_at_creation_and_refuses_symlinks() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("new");
        let f = create_new_secure(&p).unwrap();
        assert_eq!(f.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        drop(f);
        assert!(
            create_new_secure(&p).is_err(),
            "existing file must be refused"
        );
        let target = dir.path().join("target");
        std::fs::write(&target, b"keep").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(create_new_secure(&link).is_err(), "symlink must be refused");
        let dangling = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &dangling).unwrap();
        assert!(
            create_new_secure(&dangling).is_err(),
            "dangling symlink must be refused"
        );
        assert!(!dir.path().join("nowhere").exists());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    }

    #[test]
    fn publish_no_overwrite_refuses_existing_destination() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path().join("tmp");
        let dst = dir.path().join("dst");
        std::fs::write(&dst, b"first").unwrap();
        std::fs::write(&tmp, b"second").unwrap();
        let e = publish_no_overwrite(&tmp, &dst).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&dst).unwrap(), b"first");
        std::fs::remove_file(&dst).unwrap();
        publish_no_overwrite(&tmp, &dst).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"second");
        assert!(!tmp.exists());
    }
}
