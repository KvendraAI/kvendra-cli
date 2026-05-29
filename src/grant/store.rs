//! On-disk store for the ephemeral bypass grant
//! (ISSUE-KVD-CLI-20E747, AC-CLI-4).
//!
//! One grant per workspace, at
//! `~/.kvendra/sessions/<workspace_id_safe>.bypass`, mode 0600, written
//! atomically (tmp + rename) under an advisory exclusive flock. This is the
//! exact pattern of `session/store.rs` (the workspace JWT token store) — the
//! grant is a sibling artifact in the same directory with a `.bypass`
//! extension instead of `.token`.

use crate::config::set_file_mode_secure;
use crate::error::{KvendraError, KvendraResult};
use crate::grant::{SCHEMA_VERSION, SignedGrant};
use fs2::FileExt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Path of a workspace's grant file.
pub fn grant_path(home: &Path, workspace_id_safe: &str) -> PathBuf {
    home.join("sessions")
        .join(format!("{workspace_id_safe}.bypass"))
}

/// Path of a workspace's grant lock sidecar.
pub fn lock_path(home: &Path, workspace_id_safe: &str) -> PathBuf {
    home.join("sessions")
        .join(format!("{workspace_id_safe}.bypass.lock"))
}

/// RAII flock guard (releases on drop).
pub struct GrantLockGuard {
    file: File,
}

impl Drop for GrantLockGuard {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

fn acquire_lock(home: &Path, workspace_id_safe: &str) -> KvendraResult<GrantLockGuard> {
    let dir = home.join("sessions");
    std::fs::create_dir_all(&dir)
        .map_err(|e| KvendraError::SessionStore(format!("mkdir sessions: {e}")))?;
    let path = lock_path(home, workspace_id_safe);
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| KvendraError::SessionStore(format!("open grant lock: {e}")))?;
    FileExt::lock_exclusive(&file)
        .map_err(|e| KvendraError::SessionStore(format!("flock grant: {e}")))?;
    Ok(GrantLockGuard { file })
}

/// Persist a signed grant atomically (tmp + rename), mode 0600, under an
/// exclusive flock for the whole operation.
pub fn persist_atomic(grant: &SignedGrant, home: &Path) -> KvendraResult<()> {
    let ws = &grant.payload.workspace_id;
    let _guard = acquire_lock(home, ws)?;
    let final_path = grant_path(home, ws);
    let tmp_path = final_path.with_extension(format!("tmp.{}", std::process::id()));

    let raw = serde_json::to_vec_pretty(grant)
        .map_err(|e| KvendraError::SessionStore(format!("encode grant: {e}")))?;
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| KvendraError::SessionStore(format!("open tmp grant: {e}")))?;
        f.write_all(&raw)
            .map_err(|e| KvendraError::SessionStore(format!("write tmp grant: {e}")))?;
        f.sync_all().ok();
    }
    std::fs::rename(&tmp_path, &final_path)
        .map_err(|e| KvendraError::SessionStore(format!("rename grant: {e}")))?;
    set_file_mode_secure(&final_path)?;
    Ok(())
}

/// Load a workspace's grant. `Ok(None)` when no grant file exists. A present
/// but unparseable or wrong-schema file is an `Err` (the caller / verifier
/// treats it as fail-closed `Malformed`).
pub fn load(home: &Path, workspace_id_safe: &str) -> KvendraResult<Option<SignedGrant>> {
    let path = grant_path(home, workspace_id_safe);
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| KvendraError::SessionStore(format!("read grant: {e}")))?;
    let grant: SignedGrant = serde_json::from_str(&raw).map_err(|e| {
        KvendraError::SessionStore(format!("decode grant at {}: {e}", path.display()))
    })?;
    if grant.payload.schema_version != SCHEMA_VERSION {
        return Err(KvendraError::SessionStore(format!(
            "grant schema v{} unsupported by this binary",
            grant.payload.schema_version
        )));
    }
    Ok(Some(grant))
}

/// Remove a single workspace's grant + lock sidecar. Idempotent — returns
/// `true` if a grant file existed. This is the `kvendra protect` / TTL /
/// lock auto-revoke primitive.
pub fn revoke(home: &Path, workspace_id_safe: &str) -> KvendraResult<bool> {
    let _guard = acquire_lock(home, workspace_id_safe)?;
    let path = grant_path(home, workspace_id_safe);
    let existed = path.exists();
    if existed {
        std::fs::remove_file(&path)
            .map_err(|e| KvendraError::SessionStore(format!("rm grant: {e}")))?;
    }
    let lock = lock_path(home, workspace_id_safe);
    if lock.exists() {
        let _ = std::fs::remove_file(&lock);
    }
    Ok(existed)
}

/// Remove EVERY `*.bypass` grant under `~/.kvendra/sessions/`. Called by
/// `kvendra lock` (AC-CLI-3 auto-revoke at vault lock). Idempotent; returns
/// the number of grant files removed.
pub fn revoke_all(home: &Path) -> KvendraResult<usize> {
    let dir = home.join("sessions");
    if !dir.exists() {
        return Ok(0);
    }
    let mut removed = 0usize;
    for entry in
        std::fs::read_dir(&dir).map_err(|e| KvendraError::SessionStore(format!("readdir: {e}")))?
    {
        let entry = entry.map_err(|e| KvendraError::SessionStore(format!("entry: {e}")))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(stem) = name.strip_suffix(".bypass") {
            // Skip a half-written `.tmp.<pid>` file (it ends with the pid,
            // not `.bypass`, so it won't match — but guard anyway).
            if stem.contains(".tmp.") {
                continue;
            }
            if revoke(home, stem)? {
                removed += 1;
            }
        }
    }
    Ok(removed)
}

/// Enumerate the workspace ids (slugs) that currently hold a grant.
pub fn list_grants(home: &Path) -> KvendraResult<Vec<String>> {
    let dir = home.join("sessions");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in
        std::fs::read_dir(&dir).map_err(|e| KvendraError::SessionStore(format!("readdir: {e}")))?
    {
        let entry = entry.map_err(|e| KvendraError::SessionStore(format!("entry: {e}")))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(stem) = name.strip_suffix(".bypass") {
            if stem.contains(".tmp.") {
                continue;
            }
            out.push(stem.to_string());
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::{GrantPayload, sign::sign_grant};
    use chrono::{Duration as ChronoDuration, Utc};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use tempfile::tempdir;

    fn signed(home_ws_root: &str) -> SignedGrant {
        let key = SigningKey::generate(&mut OsRng);
        let now = Utc::now();
        let payload = GrantPayload {
            schema_version: SCHEMA_VERSION,
            workspace_root: home_ws_root.into(),
            workspace_id: crate::grant::workspace_id_from_root(home_ws_root),
            ops: vec!["kvendra.git.push".into()],
            issued_at: now,
            expires_at: now + ChronoDuration::hours(1),
            key_id: crate::grant::key_id_for_pubkey(key.verifying_key().to_bytes().as_slice()),
            nonce: "Tm9uY2U=".into(),
        };
        sign_grant(payload, &key).unwrap()
    }

    #[test]
    fn persist_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let g = signed("/Users/dev/Kvendra");
        persist_atomic(&g, dir.path()).unwrap();
        let loaded = load(dir.path(), "Kvendra").unwrap().unwrap();
        assert_eq!(loaded.payload.workspace_root, g.payload.workspace_root);
        assert_eq!(loaded.sig_ed25519, g.sig_ed25519);
    }

    #[test]
    fn load_returns_none_when_missing() {
        let dir = tempdir().unwrap();
        assert!(load(dir.path(), "nope").unwrap().is_none());
    }

    #[test]
    fn revoke_is_idempotent() {
        let dir = tempdir().unwrap();
        let g = signed("/Users/dev/Kvendra");
        persist_atomic(&g, dir.path()).unwrap();
        assert!(revoke(dir.path(), "Kvendra").unwrap());
        assert!(!revoke(dir.path(), "Kvendra").unwrap());
        assert!(load(dir.path(), "Kvendra").unwrap().is_none());
    }

    #[test]
    fn revoke_all_clears_every_grant() {
        let dir = tempdir().unwrap();
        persist_atomic(&signed("/Users/dev/A"), dir.path()).unwrap();
        persist_atomic(&signed("/Users/dev/B"), dir.path()).unwrap();
        let n = revoke_all(dir.path()).unwrap();
        assert_eq!(n, 2);
        assert_eq!(revoke_all(dir.path()).unwrap(), 0);
        assert!(list_grants(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn hand_edit_breaks_signature() {
        // Storage-level twin of the verify-layer test: editing the on-disk
        // JSON payload must invalidate the signature (AC-CLI-4 / AC-SEC-1).
        use crate::grant::verify::verify_signature;
        let dir = tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let now = Utc::now();
        let payload = GrantPayload {
            schema_version: SCHEMA_VERSION,
            workspace_root: "/Users/dev/Kvendra".into(),
            workspace_id: "Kvendra".into(),
            ops: vec!["kvendra.git.push".into()],
            issued_at: now,
            expires_at: now + ChronoDuration::hours(1),
            key_id: crate::grant::key_id_for_pubkey(key.verifying_key().to_bytes().as_slice()),
            nonce: "Tm9uY2U=".into(),
        };
        let g = sign_grant(payload, &key).unwrap();
        persist_atomic(&g, dir.path()).unwrap();

        // Hand-edit: widen the scope on disk.
        let path = grant_path(dir.path(), "Kvendra");
        let raw = std::fs::read_to_string(&path).unwrap();
        let tampered = raw.replace(
            "\"kvendra.git.push\"",
            "\"kvendra.git.push\",\n    \"kvendra.shell.exec\"",
        );
        assert_ne!(raw, tampered, "tamper must change the bytes");
        std::fs::write(&path, tampered).unwrap();

        let loaded = load(dir.path(), "Kvendra").unwrap().unwrap();
        assert!(
            verify_signature(&loaded, &key.verifying_key()).is_err(),
            "hand-edited grant must fail signature verification"
        );
    }
}
