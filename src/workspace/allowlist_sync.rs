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
        .join(crate::session::SessionState::workspace_id_safe(
            workspace_id,
        ))
}

/// Path of the `.stale_blocked` sentinel — touched when the sync has not
/// succeeded in >24h.
pub fn stale_blocked_path(home: &Path, workspace_id: &str) -> PathBuf {
    cache_root(home, workspace_id).join(".stale_blocked")
}

/// Build `<cache_root>/<template_id>.<suffix>`, refusing anything that is not
/// exactly one safe component directly under the root.
///
/// ISSUE-KVD-CLI-3319F0: `template_id` is chosen by the BROKER
/// ([`crate::protocol::v1::Template`] decodes it as a free `String`), and
/// `Path::join` discards the base on an absolute operand while a `..` segment
/// survives the join, so the previous lexical join let a hostile broker pick
/// any path the user can write — including the vault's own signed
/// `allowlists/*.yaml`.
///
/// Two independent gates, both required:
/// 1. the shared charset/length rule
///    ([`crate::path_id::is_safe_path_component`]) on the template id AND on
///    the workspace slug that forms the parent directory — the slug is
///    `workspace_id_safe`, which only maps `/` to `__` and is broker-supplied
///    the moment `/v1/me` is wired in;
/// 2. containment by PARENT EQUALITY. `Path::starts_with` is not containment:
///    `<root>/../../x` still starts with `<root>`.
fn cache_child(
    home: &Path,
    workspace_id: &str,
    template_id: &str,
    suffix: &str,
) -> KvendraResult<PathBuf> {
    if !crate::path_id::is_safe_path_component(template_id) {
        return Err(KvendraError::Config(format!(
            "broker returned an unusable template id: {template_id:?}"
        )));
    }
    let slug = crate::session::SessionState::workspace_id_safe(workspace_id);
    if !crate::path_id::is_safe_path_component(&slug) {
        return Err(KvendraError::Config(format!(
            "broker returned an unusable workspace id: {workspace_id:?}"
        )));
    }
    let root = cache_root(home, workspace_id);
    let path = root.join(format!("{template_id}.{suffix}"));
    if path.parent() != Some(root.as_path()) {
        return Err(KvendraError::Config(
            "template path escaped the sync cache root".to_string(),
        ));
    }
    Ok(path)
}

/// Path of the cached YAML for a single template.
///
/// Fallible since ISSUE-KVD-CLI-3319F0 — see [`cache_child`].
pub fn template_cache_path(
    home: &Path,
    workspace_id: &str,
    template_id: &str,
) -> KvendraResult<PathBuf> {
    cache_child(home, workspace_id, template_id, "yaml")
}

/// Sidecar file holding the ETag for `template_id`.
///
/// Fallible since ISSUE-KVD-CLI-3319F0 — see [`cache_child`].
pub fn template_etag_path(
    home: &Path,
    workspace_id: &str,
    template_id: &str,
) -> KvendraResult<PathBuf> {
    cache_child(home, workspace_id, template_id, "yaml.etag")
}

#[allow(dead_code)]
fn read_etag(home: &Path, workspace_id: &str, template_id: &str) -> Option<String> {
    let path = template_etag_path(home, workspace_id, template_id).ok()?;
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn write_etag(home: &Path, workspace_id: &str, template_id: &str, etag: &str) -> KvendraResult<()> {
    let path = template_etag_path(home, workspace_id, template_id)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| KvendraError::Config(format!("mkdir etag: {e}")))?;
    }
    // `with_file_name` (not `with_extension`): the stem is attacker-chosen, and
    // `with_extension` on an id like `.` resolves to the PARENT directory.
    let tmp = path.with_file_name(format!(
        "{template_id}.yaml.etag.tmp.{}",
        std::process::id()
    ));
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
    std::fs::rename(&tmp, &path).map_err(|e| KvendraError::Config(format!("etag rename: {e}")))?;
    set_file_mode_secure(&path)?;
    Ok(())
}

fn write_template_atomic(
    home: &Path,
    workspace_id: &str,
    template_id: &str,
    yaml: &str,
) -> KvendraResult<()> {
    let path = template_cache_path(home, workspace_id, template_id)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| KvendraError::Config(format!("mkdir cache: {e}")))?;
    }
    // `with_file_name` (not `with_extension`): the stem is attacker-chosen, and
    // `with_extension` on an id like `.` resolves to the PARENT directory.
    let tmp = path.with_file_name(format!("{template_id}.yaml.tmp.{}", std::process::id()));
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
    // Top-level ETag is informational — per-template ETags are written
    // below as sidecars. `prior_etag` stays None for now; IF-002 v1.2.0
    // will populate it via the list endpoint's `ETag` header.
    let prior_etag: Option<String> = None;
    let _ = full; // keep the signature stable until IF-002 v1.2.0

    let resp = client
        .list_templates(workspace_id, prior_etag.as_deref())
        .await?;
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
                // ISSUE-KVD-CLI-3319F0: an id that is not a safe path
                // component is refused by the builder BEFORE any mkdir/open,
                // so a hostile template is skipped and counted — never fatal
                // for the templates that are well-formed.
                if !crate::path_id::is_safe_path_component(&tmpl.template_id) {
                    tracing::warn!(
                        target: "kvendra::workspace",
                        flag = "workspace_template_id_rejected",
                        template = ?log_safe_template_id(&tmpl.template_id),
                        workspace = %workspace_id,
                        "broker returned a template id that is not a safe path component — template skipped, nothing written"
                    );
                    report.failed += 1;
                    continue;
                }
                if let Err(e) =
                    write_template_atomic(home, workspace_id, &tmpl.template_id, &tmpl.yaml_blob)
                {
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
            // AC-ALLOWSYNC-3 + ISSUE-KVD-CLI-3319F0: the sentinel means "the
            // cache is fresh". Clearing it after a pass in which templates
            // were REJECTED or failed to write would declare a cache fresh
            // that the broker never managed to refresh — a hostile broker
            // could hold the workspace open indefinitely by returning ids the
            // CLI must refuse. Only a fully successful pass recovers.
            if report.failed == 0 {
                clear_stale_blocked(home, workspace_id);
            }
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

/// Char cap for a hostile template id echoed into logs.
const LOG_TEMPLATE_ID_MAX_CHARS: usize = 64;

/// Length-capped form of a REJECTED (broker-supplied, untrusted) template id
/// for logging. It is emitted with tracing's `?` (Debug), which escapes
/// control characters, so a hostile id cannot inject ANSI sequences or fake
/// log lines; the cap bounds log amplification.
fn log_safe_template_id(id: &str) -> String {
    if id.chars().count() <= LOG_TEMPLATE_ID_MAX_CHARS {
        return id.to_string();
    }
    let mut out: String = id.chars().take(LOG_TEMPLATE_ID_MAX_CHARS).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Log injection: a rejected hostile template id is length-capped and,
    /// logged via Debug, carries no raw control characters.
    #[test]
    fn rejected_template_id_is_capped_and_escaped_for_logs() {
        let hostile = format!("\x1b[31mFAKE\nINFO ok{}", "A".repeat(200));
        let safe = log_safe_template_id(&hostile);
        assert_eq!(safe.chars().count(), LOG_TEMPLATE_ID_MAX_CHARS + 1);
        assert!(safe.ends_with('…'));
        let logged = format!("{safe:?}");
        assert!(
            !logged.chars().any(|c| c.is_control()),
            "Debug form must escape control chars: {logged}"
        );
        assert!(
            logged.contains("\\u{1b}") && logged.contains("\\n"),
            "{logged}"
        );
        assert_eq!(log_safe_template_id("short-id"), "short-id");
    }

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

    // ───────────────────────────────────────────────────────────────────
    // SA5 — ISSUE-KVD-CLI-3319F0 (RUN-KVD-CLI-190069).
    //
    // The BROKER chooses `template_id` (`protocol::v1::Template`, a free
    // `String` with no bound and no charset) and `template_cache_path` /
    // `template_etag_path` join it LEXICALLY onto the per-workspace cache
    // root. `Path::join` discards the base on an absolute operand and a `..`
    // segment survives the join, so a hostile (or compromised) broker picks
    // ANY path the user can write — including the vault's own signed
    // allowlists at `~/.kvendra/allowlists/*.yaml`.
    //
    // These tests are the WRITE boundary (the path-building half is pinned in
    // tests/security_audit_run1.rs). They live in-crate because
    // `write_template_atomic` / `write_etag` are private. RED at e41b652: the
    // writes return Ok and the bytes land outside the cache root.
    // ───────────────────────────────────────────────────────────────────

    const WS: &str = "ws-test";

    /// Hostile ids that must never reach the filesystem. Each one is the exact
    /// shape a broker could return today.
    fn hostile_relative_ids() -> Vec<&'static str> {
        vec![
            // Escapes the cache root and lands on a REAL vault allowlist.
            "../../../allowlists/profile-alpha",
            // Materialises a whole directory chain outside the cache root.
            "../../../deep/a/b/c/d/mark",
        ]
    }

    /// Create the 0400 victim a hostile template id can overwrite:
    /// `<home>/allowlists/profile-alpha.yaml`, i.e. exactly where the vault
    /// keeps the signed per-profile allowlists.
    fn plant_victim(home: &Path) -> PathBuf {
        let victim_dir = home.join("allowlists");
        std::fs::create_dir_all(&victim_dir).unwrap();
        let victim = victim_dir.join("profile-alpha.yaml");
        std::fs::write(
            &victim,
            "profile_id: profile-alpha\n# SIGNED — do not touch\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        victim
    }

    #[test]
    fn sa5_traversal_template_id_must_not_overwrite_a_vault_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let victim = plant_victim(home);
        let before = std::fs::read(&victim).unwrap();
        #[cfg(unix)]
        let ino_before = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(&victim).unwrap().ino()
        };

        let r = write_template_atomic(
            home,
            WS,
            "../../../allowlists/profile-alpha",
            "profile_id: pwned\nallowlist:\n  primitives: []\n",
        );

        assert_eq!(
            std::fs::read(&victim).unwrap(),
            before,
            "the 0400 vault allowlist at {} was OVERWRITTEN through the \
             template cache path",
            victim.display()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                std::fs::metadata(&victim).unwrap().ino(),
                ino_before,
                "the victim file was REPLACED (rename onto the target changes \
                 the inode even when the old file was mode 0400)"
            );
        }
        assert!(
            r.is_err(),
            "a template id containing `..` must be REFUSED before any write; \
             write_template_atomic returned {r:?}"
        );
    }

    #[test]
    fn sa5_traversal_template_id_must_not_materialise_directories_outside_the_cache_root() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();

        let r = write_template_atomic(home, WS, "../../../deep/a/b/c/d/mark", "x: 1\n");

        assert!(
            !home.join("deep").exists(),
            "`create_dir_all` MATERIALISED a directory chain outside the cache \
             root at {}",
            home.join("deep").display()
        );
        assert!(
            r.is_err(),
            "a deep `..` chain must be REFUSED; write_template_atomic returned {r:?}"
        );
    }

    #[test]
    fn sa5_absolute_template_id_must_not_create_a_file_outside_the_cache_root() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        // A second tempdir keeps the escape bounded: an absolute operand makes
        // `Path::join` DISCARD the cache root entirely.
        let elsewhere = tempfile::tempdir().unwrap();
        let stem = elsewhere.path().join("escapee");
        let escapee = elsewhere.path().join("escapee.yaml");

        let r = write_template_atomic(home, WS, &stem.to_string_lossy(), "x: 1\n");

        assert!(
            !escapee.exists(),
            "an absolute template id WROTE {} — entirely outside {}",
            escapee.display(),
            cache_root(home, WS).display()
        );
        assert!(
            r.is_err(),
            "an ABSOLUTE template id must be REFUSED; write_template_atomic \
             returned {r:?}"
        );
    }

    #[test]
    fn sa5_hostile_template_ids_must_be_refused_by_the_etag_writer_too() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let elsewhere = tempfile::tempdir().unwrap();
        let abs_stem = elsewhere.path().join("escapee");

        let mut ids: Vec<String> = hostile_relative_ids()
            .into_iter()
            .map(str::to_string)
            .collect();
        ids.push(abs_stem.to_string_lossy().into_owned());

        for id in &ids {
            let r = write_etag(home, WS, id, "\"etag-value\"");
            assert!(
                r.is_err(),
                "write_etag accepted the hostile template id {id:?} (the ETag \
                 sidecar shares the builder, so it shares the hole); returned {r:?}"
            );
        }
        assert!(
            !home.join("deep").exists(),
            "the etag writer materialised directories outside the cache root"
        );
        assert!(
            !elsewhere.path().join("escapee.yaml.etag").exists(),
            "the etag writer wrote outside the cache root"
        );
    }

    /// GUARD (green before AND after) — a legitimate broker id must still
    /// round-trip to exactly one file directly under the cache root, mode 0400.
    #[test]
    fn sa5_guard_legit_template_id_still_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let path = template_cache_path(home, WS, "github-deploy-tmpl-v1").unwrap();
        write_template_atomic(home, WS, "github-deploy-tmpl-v1", "x: 1\n").unwrap();
        assert!(path.exists(), "the legit template must be cached");
        assert_eq!(
            path.parent(),
            Some(cache_root(home, WS).as_path()),
            "the cached template must sit DIRECTLY under the cache root"
        );
    }
}
