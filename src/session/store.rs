//! Atomic JSON store for cached workspace session tokens.

use crate::auth::oidc::TokenSet;
use crate::config::set_file_mode_secure;
use crate::error::{KvendraError, KvendraResult};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Current on-disk JSON schema version. Bump if the shape changes
/// incompatibly so older binaries can refuse to load newer files.
pub const SCHEMA_VERSION: u32 = 1;

/// In-memory view of the persisted JSON.
///
/// `workspace_id` is the canonical `<tenant>/<workspace>` identifier (per
/// GLO-013). `member_id` and `member_email` derive from the IdP claims and
/// are cached for fast `session info` reads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub workspace_id: String,
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub member_id: String,
    pub member_email: String,
    pub jwt: String,
    pub jwt_expires_at: DateTime<Utc>,
    pub refresh_token: String,
    #[serde(default)]
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub issuer: String,
    pub audience: String,
    pub last_refresh_at: DateTime<Utc>,
    pub obtained_at: DateTime<Utc>,
    /// Last successful allowlist sync timestamp (RFC3339). Populated by
    /// `workspace::allowlist_sync`. `None` if no sync has run yet.
    #[serde(default)]
    pub last_allowlist_sync_at: Option<DateTime<Utc>>,
}

fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}

impl SessionState {
    /// Construct a [`SessionState`] from a freshly obtained [`TokenSet`].
    pub fn from_token_set(
        workspace_id: &str,
        tenant_id: &str,
        member_id: &str,
        member_email: &str,
        issuer: &str,
        audience: &str,
        token_set: &TokenSet,
        previous_refresh: Option<&str>,
        now: DateTime<Utc>,
    ) -> Self {
        let refresh_token = if token_set.refresh_token.is_empty() {
            previous_refresh.unwrap_or("").to_string()
        } else {
            token_set.refresh_token.clone()
        };
        let jwt_expires_at =
            now + ChronoDuration::seconds(token_set.expires_in.try_into().unwrap_or(900));
        Self {
            schema_version: SCHEMA_VERSION,
            workspace_id: workspace_id.into(),
            tenant_id: tenant_id.into(),
            member_id: member_id.into(),
            member_email: member_email.into(),
            jwt: token_set.access_token.clone(),
            jwt_expires_at,
            refresh_token,
            // Cognito does not expose a refresh expiry claim by default; the
            // pool-level TTL stays in the IdP. Leave None and let
            // `session info` show "unknown" gracefully.
            refresh_token_expires_at: None,
            issuer: issuer.into(),
            audience: audience.into(),
            last_refresh_at: now,
            obtained_at: now,
            last_allowlist_sync_at: None,
        }
    }

    /// Translate a `workspace_id` like `acme-corp/frontend` to a filesystem
    /// slug `acme-corp__frontend` so it can be used as a filename.
    pub fn workspace_id_safe(workspace_id: &str) -> String {
        workspace_id.replace('/', "__")
    }

    /// Convert a slug back to its canonical workspace id. Inverse of
    /// [`workspace_id_safe`].
    pub fn workspace_id_from_safe(slug: &str) -> String {
        slug.replace("__", "/")
    }

    pub fn token_path(home: &Path, workspace_id: &str) -> PathBuf {
        home.join("sessions")
            .join(format!("{}.token", Self::workspace_id_safe(workspace_id)))
    }

    pub fn lock_path(home: &Path, workspace_id: &str) -> PathBuf {
        home.join("sessions").join(format!(
            "{}.token.lock",
            Self::workspace_id_safe(workspace_id)
        ))
    }

    /// Load a session from disk. Returns `Ok(None)` when the file does not
    /// exist (no active session for that workspace).
    pub fn load(home: &Path, workspace_id: &str) -> KvendraResult<Option<Self>> {
        let path = Self::token_path(home, workspace_id);
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| KvendraError::SessionStore(format!("read: {e}")))?;
        let parsed: Self = serde_json::from_str(&raw)
            .map_err(|e| KvendraError::SessionStore(format!("decode: {e}")))?;
        Ok(Some(parsed))
    }

    /// Persist the session JSON atomically (tmp + rename), set file mode 0600.
    pub fn persist_atomic(&self, home: &Path) -> KvendraResult<()> {
        let dir = home.join("sessions");
        std::fs::create_dir_all(&dir)
            .map_err(|e| KvendraError::SessionStore(format!("mkdir: {e}")))?;
        let final_path = Self::token_path(home, &self.workspace_id);
        let tmp_path = final_path.with_extension(format!("tmp.{}", std::process::id()));

        let raw = serde_json::to_vec_pretty(self)
            .map_err(|e| KvendraError::SessionStore(format!("encode: {e}")))?;

        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(|e| KvendraError::SessionStore(format!("tmp open: {e}")))?;
            f.write_all(&raw)
                .map_err(|e| KvendraError::SessionStore(format!("write: {e}")))?;
            f.sync_all().ok();
        }
        // POSIX atomic rename guarantees observers either see the old file
        // or the new file, never a torn write.
        std::fs::rename(&tmp_path, &final_path)
            .map_err(|e| KvendraError::SessionStore(format!("rename: {e}")))?;
        set_file_mode_secure(&final_path)?;
        Ok(())
    }

    /// Remove the persisted token file (logout). Idempotent.
    pub fn delete(home: &Path, workspace_id: &str) -> KvendraResult<()> {
        let path = Self::token_path(home, workspace_id);
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| KvendraError::SessionStore(format!("rm: {e}")))?;
        }
        let lock = Self::lock_path(home, workspace_id);
        if lock.exists() {
            let _ = std::fs::remove_file(&lock);
        }
        Ok(())
    }

    /// Acquire an advisory exclusive flock on the sidecar lock path. The
    /// returned guard releases the lock on drop.
    pub fn acquire_lock(home: &Path, workspace_id: &str) -> KvendraResult<SessionLockGuard> {
        let dir = home.join("sessions");
        std::fs::create_dir_all(&dir)
            .map_err(|e| KvendraError::SessionStore(format!("mkdir lock: {e}")))?;
        let lock_path = Self::lock_path(home, workspace_id);
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| KvendraError::SessionStore(format!("open lock: {e}")))?;
        FileExt::lock_exclusive(&file)
            .map_err(|e| KvendraError::SessionStore(format!("flock: {e}")))?;
        Ok(SessionLockGuard { file })
    }
}

/// RAII guard around an `fs2` exclusive flock. Releases on drop.
pub struct SessionLockGuard {
    file: File,
}

impl Drop for SessionLockGuard {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

/// Enumerate every `*.token` file under `~/.kvendra/sessions/`. Returns the
/// canonical `workspace_id` (un-slugged) for each valid file.
pub fn list_active_sessions(home: &Path) -> KvendraResult<Vec<String>> {
    let dir = home.join("sessions");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .map_err(|e| KvendraError::SessionStore(format!("readdir: {e}")))?
    {
        let entry = entry.map_err(|e| KvendraError::SessionStore(format!("entry: {e}")))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(stripped) = name.strip_suffix(".token") {
            // Skip the .tmp.<pid> half-written file.
            if stripped.contains(".tmp.") {
                continue;
            }
            out.push(SessionState::workspace_id_from_safe(stripped));
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fixture_state() -> SessionState {
        let now = Utc::now();
        SessionState {
            schema_version: SCHEMA_VERSION,
            workspace_id: "acme-corp/frontend".into(),
            tenant_id: "acme-corp".into(),
            member_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            member_email: "bob@acme.com".into(),
            jwt: "abc.def.ghi".into(),
            jwt_expires_at: now + ChronoDuration::minutes(30),
            refresh_token: "rt-opaque".into(),
            refresh_token_expires_at: Some(now + ChronoDuration::days(30)),
            issuer: "https://auth.kvendra.cloud".into(),
            audience: "audience-id".into(),
            last_refresh_at: now,
            obtained_at: now,
            last_allowlist_sync_at: None,
        }
    }

    #[test]
    fn safe_slug_roundtrip() {
        let raw = "acme-corp/frontend";
        let slug = SessionState::workspace_id_safe(raw);
        assert_eq!(slug, "acme-corp__frontend");
        assert_eq!(SessionState::workspace_id_from_safe(&slug), raw);
    }

    #[test]
    fn persist_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let s = fixture_state();
        s.persist_atomic(dir.path()).unwrap();
        let loaded = SessionState::load(dir.path(), &s.workspace_id).unwrap().unwrap();
        assert_eq!(loaded.workspace_id, s.workspace_id);
        assert_eq!(loaded.jwt, s.jwt);
    }

    #[test]
    fn load_returns_none_when_missing() {
        let dir = tempdir().unwrap();
        let r = SessionState::load(dir.path(), "no/such").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn delete_is_idempotent() {
        let dir = tempdir().unwrap();
        let s = fixture_state();
        s.persist_atomic(dir.path()).unwrap();
        SessionState::delete(dir.path(), &s.workspace_id).unwrap();
        SessionState::delete(dir.path(), &s.workspace_id).unwrap(); // again, no-op
    }

    #[test]
    fn list_active_sessions_finds_workspace() {
        let dir = tempdir().unwrap();
        let s = fixture_state();
        s.persist_atomic(dir.path()).unwrap();
        let active = list_active_sessions(dir.path()).unwrap();
        assert_eq!(active, vec![s.workspace_id.clone()]);
    }
}
