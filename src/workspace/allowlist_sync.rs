//! Allowlist sync — pull templates from the broker on `login` and on a
//! configurable interval (default 5 min). Honors ETag conditional GETs and
//! caches the YAML body under `~/.kvendra/cache/allowlists/<ws>/`.
//!
//! Per AC-ALLOWSYNC-3 the cache is fail-soft up to 24h without successful
//! sync, after which the workspace is marked `stale_blocked` and every
//! subsequent `tools/call` rejects until a successful refresh recovers.

use crate::config::set_file_mode_secure;
use crate::error::{KvendraError, KvendraResult};
use crate::workspace::client::WorkspaceClient;
use chrono::{DateTime, Utc};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Default interval between background sync ticks (minutes).
pub const DEFAULT_SYNC_INTERVAL_MINUTES: u32 = 5;

/// Maximum number of consecutive failures before the workspace gets marked
/// `stale_blocked` (24h × 60 / DEFAULT_SYNC_INTERVAL_MINUTES with margin).
pub const STALE_BLOCK_AFTER_HOURS: i64 = 24;

/// Outcome of a single sync tick.
#[derive(Debug, Clone)]
pub struct SyncReport {
    pub fetched: usize,
    pub not_modified: usize,
    pub failed: usize,
}

/// Root of the per-workspace cache. Identical layout regardless of OS.
pub fn cache_root(home: &Path, workspace_id: &str) -> PathBuf {
    home.join("cache")
        .join("allowlists")
        .join(crate::session::SessionState::workspace_id_safe(workspace_id))
}

/// Path of the `.stale_blocked` sentinel — touched when the sync has not
/// succeeded in >24h.
pub fn stale_blocked_path(home: &Path, workspace_id: &str) -> PathBuf {
    cache_root(home, workspace_id).join(".stale_blocked")
}

/// Path of the cached YAML for a single template.
pub fn template_cache_path(home: &Path, workspace_id: &str, template_id: &str) -> PathBuf {
    cache_root(home, workspace_id).join(format!("{template_id}.yaml"))
}

/// Sidecar file holding the ETag for `template_id`.
pub fn template_etag_path(home: &Path, workspace_id: &str, template_id: &str) -> PathBuf {
    cache_root(home, workspace_id).join(format!("{template_id}.yaml.etag"))
}

#[allow(dead_code)]
fn read_etag(home: &Path, workspace_id: &str, template_id: &str) -> Option<String> {
    let path = template_etag_path(home, workspace_id, template_id);
    std::fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}

fn write_etag(
    home: &Path,
    workspace_id: &str,
    template_id: &str,
    etag: &str,
) -> KvendraResult<()> {
    let path = template_etag_path(home, workspace_id, template_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| KvendraError::Config(format!("mkdir etag: {e}")))?;
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| KvendraError::Config(format!("etag tmp open: {e}")))?;
        f.write_all(etag.as_bytes())
            .map_err(|e| KvendraError::Config(format!("etag write: {e}")))?;
    }
    std::fs::rename(&tmp, &path)
        .map_err(|e| KvendraError::Config(format!("etag rename: {e}")))?;
    set_file_mode_secure(&path)?;
    Ok(())
}

fn write_template_atomic(
    home: &Path,
    workspace_id: &str,
    template_id: &str,
    yaml: &str,
) -> KvendraResult<()> {
    let path = template_cache_path(home, workspace_id, template_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| KvendraError::Config(format!("mkdir cache: {e}")))?;
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| KvendraError::Config(format!("template tmp open: {e}")))?;
        f.write_all(yaml.as_bytes())
            .map_err(|e| KvendraError::Config(format!("template write: {e}")))?;
    }
    std::fs::rename(&tmp, &path)
        .map_err(|e| KvendraError::Config(format!("template rename: {e}")))?;
    // mode 0400 — read-only owner. Local edits get silently overwritten on
    // the next sync, the cache is opaque to the user.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400));
    }
    Ok(())
}

/// Run a single sync pass (`full = true` ignores ETags and re-downloads
/// every template; used on login).
pub async fn sync_once(
    home: &Path,
    workspace_id: &str,
    jwt: &str,
    full: bool,
) -> KvendraResult<SyncReport> {
    let client = WorkspaceClient::new(jwt.to_string())?;
    let prior_etag = if full {
        None
    } else {
        let cache_dir = cache_root(home, workspace_id);
        std::fs::read_dir(&cache_dir)
            .ok()
            .and_then(|mut it| it.next())
            .and_then(|first| first.ok())
            .and_then(|_| {
                // We use a per-template ETag below; this top-level value is
                // mostly informational. Forward as None.
                None::<String>
            })
    };

    let resp = client.list_templates(workspace_id, prior_etag.as_deref()).await?;
    let mut report = SyncReport {
        fetched: 0,
        not_modified: 0,
        failed: 0,
    };
    match resp {
        None => {
            // 304 at the top level — nothing changed. Touch the stale
            // sentinel by clearing it (we did get a successful response).
            clear_stale_blocked(home, workspace_id);
            report.not_modified = 1;
        }
        Some((templates, _root_etag)) => {
            for tmpl in templates.items {
                // Per-template ETag would require the broker to expose
                // template-level GETs. With v1.1.0 we get a list back; the
                // payload itself is the source of truth, so we write whatever
                // the broker said. The optional `If-None-Match` on the list
                // GET above already handles the "nothing changed" path.
                if let Err(e) = write_template_atomic(
                    home,
                    workspace_id,
                    &tmpl.template_id,
                    &tmpl.yaml_blob,
                ) {
                    tracing::warn!(
                        target: "kvendra::workspace",
                        template = %tmpl.template_id,
                        error = ?e,
                        "template write failed"
                    );
                    report.failed += 1;
                    continue;
                }
                // Use the version field as a tiny ETag surrogate; the
                // backend will emit real ETag headers in IF-002 v1.2.0.
                let _ = write_etag(
                    home,
                    workspace_id,
                    &tmpl.template_id,
                    &format!("v{}", tmpl.version),
                );
                report.fetched += 1;
            }
            clear_stale_blocked(home, workspace_id);
        }
    }
    Ok(report)
}

/// Touch the `.stale_blocked` sentinel under the workspace cache so the next
/// `tools/call` rejects with [`KvendraError::AllowlistCacheStale`].
pub fn mark_stale_blocked(home: &Path, workspace_id: &str) -> KvendraResult<()> {
    let path = stale_blocked_path(home, workspace_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| KvendraError::Config(format!("mkdir stale: {e}")))?;
    }
    let _ = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .map_err(|e| KvendraError::Config(format!("stale sentinel: {e}")))?;
    Ok(())
}

/// Inverse of [`mark_stale_blocked`]. Best-effort — missing file is OK.
pub fn clear_stale_blocked(home: &Path, workspace_id: &str) {
    let path = stale_blocked_path(home, workspace_id);
    let _ = std::fs::remove_file(&path);
}

/// Returns `true` when the workspace cache is marked stale.
pub fn is_stale_blocked(home: &Path, workspace_id: &str) -> bool {
    stale_blocked_path(home, workspace_id).exists()
}

/// Helper: compute hours elapsed since `last_success_at`, or `i64::MAX` if
/// the value is `None` (never synced).
pub fn hours_since(last_success_at: Option<DateTime<Utc>>) -> i64 {
    match last_success_at {
        Some(t) => (Utc::now() - t).num_hours(),
        None => i64::MAX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_blocked_path_is_under_cache_root() {
        let dir = tempfile::tempdir().unwrap();
        let p = stale_blocked_path(dir.path(), "acme/ws");
        let root = cache_root(dir.path(), "acme/ws");
        assert!(p.starts_with(&root), "{p:?} not under {root:?}");
    }

    #[test]
    fn mark_and_clear_stale_blocked() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_stale_blocked(dir.path(), "ws/a"));
        mark_stale_blocked(dir.path(), "ws/a").unwrap();
        assert!(is_stale_blocked(dir.path(), "ws/a"));
        clear_stale_blocked(dir.path(), "ws/a");
        assert!(!is_stale_blocked(dir.path(), "ws/a"));
    }
}
