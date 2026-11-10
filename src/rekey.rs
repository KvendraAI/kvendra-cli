//! Password re-wrap commit shared by `kvendra recover` and `kvendra passwd`
//! (REQ-KVD-CLI-CFB449 F3/F5, ADR-KVD-CLI-4810AF).
//!
//! With the envelope, changing the password only replaces `sentinel.blob`:
//! MK does not change, so secrets, local vars, signed allowlists/config,
//! grants, backups and the audit chain stay valid. The commit:
//!
//! 1. invalidates every cache that holds MK or the OLD password (session
//!    blob, keychain entries, legacy wrapper) — before the commit, abort on
//!    failure (nothing else changed yet; caches regenerate on next unlock);
//! 2. copies `sentinel.blob` → `sentinel.blob.pre-recover` (0600, fsync);
//! 3. writes `sentinel.blob.recover-tmp` (0600, create_new, fsync);
//! 4. renames it over `sentinel.blob` (THE publication point) + dir fsync;
//! 5. verifies the new password yields the same MK;
//! 6. appends the HMAC audit row (`recover` / `passwd`) and imports pending
//!    pre-auth rejections;
//! 7. deletes `sentinel.blob.pre-recover`.
//!
//! A failure in 2–6 restores the previous sentinel (so an error always means
//! "old password still in force"). Both sentinels wrap the same MK, so even
//! a crash at any point leaves a vault that opens with the old password OR
//! the new one, never neither. Leftovers are cleaned by
//! [`cleanup_before_auth`] / [`finish_after_auth`].

use crate::audit::preauth::{Reason, record_rejection};
use crate::audit::{
    AuditEvent, AuditWriter, FLAG_PASSWD_OK, FLAG_RECOVER_CLEANUP, FLAG_RECOVER_OK,
    PRIMITIVE_SYSTEM, Severity, Status, reader::args_hash_hex,
};
use crate::error::{KvendraError, KvendraResult};
use crate::fault::maybe_fail;
use crate::vault::Vault;
use crate::vault::envelope::{MasterKey, SentinelV2, parse_phrase};
use crate::vault::fsutil;
use crate::vault::session::{HKDF_INFO_AUDIT_HMAC, hkdf_expand};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Keychain service + labels holding vault-derived material.
pub const KEYCHAIN_SERVICE: &str = "kvendra";
pub const KEYCHAIN_DERIVED_KEY_LABEL: &str = "kvendra/derived-key/v1";
pub const KEYCHAIN_MCP_PASSWORD_LABEL: &str = "kvendra/mcp-password/v1";
/// Legacy MCP wrapper script (may embed the password).
pub const LEGACY_WRAPPER_NAME: &str = "kvendra-mcp-serve";

/// Suffix of the companion entry that records which vault wrote a keychain
/// entry. The keychain is global to the OS user while vaults are per
/// `KVENDRA_HOME`, so `recover` / `passwd` only remove an entry whose owner
/// tag is THIS vault's `vault_id` (public, non-secret) — never another
/// vault's credential (REQ-KVD-CLI-CFB449, validation finding M3).
pub const KEYCHAIN_OWNER_SUFFIX: &str = "#owner";

pub fn owner_label(label: &str) -> String {
    format!("{label}{KEYCHAIN_OWNER_SUFFIX}")
}

/// OS credential caches that a password change must invalidate. Abstracted
/// so tests never read or delete the machine's real keychain entries.
pub trait CredentialCaches: Send + Sync {
    /// `vault_id` (hex) recorded for `label`; `Ok(None)` = no owner tag.
    /// A backend error is an `Err` (fail-closed for mcp-password, B4).
    fn owner(&self, label: &str) -> KvendraResult<Option<String>>;
    /// Whether the entry itself exists. Never returns the secret, but how it
    /// checks depends on the backend: macOS presence-gated items use an
    /// attributes-only query (the ACL'd value is not read); plain `keyring`
    /// entries (derived-key/v1 everywhere, legacy mcp-password/v1 off macOS)
    /// have no such query, so the value is read and dropped at once.
    fn exists(&self, label: &str) -> KvendraResult<bool>;
    /// Record `vault_id_hex` as the owner of `label`.
    fn set_owner(&self, label: &str, vault_id_hex: &str) -> KvendraResult<()>;
    /// Remove the entry: `Ok(true)` removed, `Ok(false)` it did not exist.
    fn delete_entry(&self, label: &str) -> KvendraResult<bool>;
    /// Remove the owner tag. Absent = success.
    fn delete_owner(&self, label: &str) -> KvendraResult<()>;
}

/// Real OS keychain.
pub struct OsCredentialCaches;

fn keyring_entry(label: &str) -> KvendraResult<keyring::Entry> {
    keyring::Entry::new(KEYCHAIN_SERVICE, label).map_err(|e| KvendraError::Keychain(e.to_string()))
}

impl CredentialCaches for OsCredentialCaches {
    fn owner(&self, label: &str) -> KvendraResult<Option<String>> {
        match keyring_entry(&owner_label(label))?.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(KvendraError::Keychain(format!(
                "could not read the owner of {label}: {e}"
            ))),
        }
    }

    fn exists(&self, label: &str) -> KvendraResult<bool> {
        if label == KEYCHAIN_MCP_PASSWORD_LABEL {
            // Attributes-only query: does not trigger the presence prompt.
            return crate::keychain_acl::exists(label)
                .map_err(|e| KvendraError::Keychain(format!("{label}: {e}")));
        }
        match keyring_entry(label)?.get_password() {
            Ok(_) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(KvendraError::Keychain(format!("{label}: {e}"))),
        }
    }

    fn set_owner(&self, label: &str, vault_id_hex: &str) -> KvendraResult<()> {
        keyring_entry(&owner_label(label))?
            .set_password(vault_id_hex)
            .map_err(|e| KvendraError::Keychain(e.to_string()))
    }

    fn delete_entry(&self, label: &str) -> KvendraResult<bool> {
        if label == KEYCHAIN_MCP_PASSWORD_LABEL {
            use crate::keychain_acl::{self, BiometricError};
            return match keychain_acl::delete(label) {
                Ok(()) => Ok(true),
                Err(BiometricError::NotFound(_)) | Err(BiometricError::Unavailable(_)) => Ok(false),
                Err(e) => Err(KvendraError::Keychain(format!(
                    "could not remove {label}: {e:?}"
                ))),
            };
        }
        match keyring_entry(label)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(KvendraError::Keychain(e.to_string())),
        }
    }

    fn delete_owner(&self, label: &str) -> KvendraResult<()> {
        match keyring_entry(&owner_label(label))?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(KvendraError::Keychain(e.to_string())),
        }
    }
}

/// File-backed fake keychain (tests). Each entry is a file in `dir`.
/// `KVENDRA_TEST_KEYCHAIN_FAIL=<label>` makes every operation on that label
/// (or on `<label>#owner`) fail like a broken backend.
pub struct FileCredentialCaches {
    pub dir: PathBuf,
}

impl FileCredentialCaches {
    pub fn entry_path(&self, label: &str) -> PathBuf {
        self.dir.join(label.replace('/', "_"))
    }

    fn check(&self, label: &str) -> KvendraResult<()> {
        if std::env::var("KVENDRA_TEST_KEYCHAIN_FAIL").is_ok_and(|l| l == label) {
            return Err(KvendraError::Keychain(format!(
                "fake keychain backend failure on {label}"
            )));
        }
        Ok(())
    }

    fn remove(&self, label: &str) -> KvendraResult<bool> {
        self.check(label)?;
        match std::fs::remove_file(self.entry_path(label)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

impl CredentialCaches for FileCredentialCaches {
    fn owner(&self, label: &str) -> KvendraResult<Option<String>> {
        self.check(&owner_label(label))?;
        match std::fs::read_to_string(self.entry_path(&owner_label(label))) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn exists(&self, label: &str) -> KvendraResult<bool> {
        self.check(label)?;
        Ok(self.entry_path(label).exists())
    }

    fn set_owner(&self, label: &str, vault_id_hex: &str) -> KvendraResult<()> {
        std::fs::create_dir_all(&self.dir)?;
        std::fs::write(self.entry_path(&owner_label(label)), vault_id_hex)?;
        Ok(())
    }

    fn delete_entry(&self, label: &str) -> KvendraResult<bool> {
        self.remove(label)
    }

    fn delete_owner(&self, label: &str) -> KvendraResult<()> {
        self.remove(&owner_label(label)).map(|_| ())
    }
}

/// The caches the CLI uses. In unit tests and in `test-hooks` builds the
/// real keychain is NEVER used: `KVENDRA_TEST_KEYCHAIN_DIR` must point at a
/// fake one, otherwise the command refuses.
pub fn caches_for_process() -> KvendraResult<Box<dyn CredentialCaches>> {
    #[cfg(any(test, feature = "test-hooks"))]
    {
        match std::env::var_os("KVENDRA_TEST_KEYCHAIN_DIR") {
            Some(dir) => Ok(Box::new(FileCredentialCaches { dir: dir.into() })),
            None => Err(KvendraError::Keychain(
                "test build: set KVENDRA_TEST_KEYCHAIN_DIR (the real keychain is never used)"
                    .into(),
            )),
        }
    }
    #[cfg(not(any(test, feature = "test-hooks")))]
    {
        Ok(Box::new(OsCredentialCaches))
    }
}

/// Which command is committing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyAction {
    Recover,
    Passwd,
}

impl RekeyAction {
    fn action(self) -> &'static str {
        match self {
            RekeyAction::Recover => "recover",
            RekeyAction::Passwd => "passwd",
        }
    }

    fn flag(self) -> &'static str {
        match self {
            RekeyAction::Recover => FLAG_RECOVER_OK,
            RekeyAction::Passwd => FLAG_PASSWD_OK,
        }
    }
}

pub fn pre_recover_path(vault: &Vault) -> PathBuf {
    fsutil::sibling(&vault.sentinel_path(), "pre-recover")
}

pub fn recover_tmp_path(vault: &Vault) -> PathBuf {
    fsutil::sibling(&vault.sentinel_path(), "recover-tmp")
}

/// Exclusive per-vault lock held by `recover` / `passwd` for the whole
/// commit, and taken (non-blocking) by the leftover cleanup, so one command
/// never deletes the other's `.pre-recover` / `.recover-tmp` mid-commit.
pub type RekeyLock = fsutil::FileLock;

pub const REKEY_LOCK_NAME: &str = ".rekey.lock";

/// `Ok(None)` when another process holds the lock.
pub fn try_lock_rekey(home: &Path) -> KvendraResult<Option<RekeyLock>> {
    fsutil::try_lock_exclusive(&home.join(REKEY_LOCK_NAME))
}

/// Before any authentication: drop an unpublished tmp sentinel and, if the
/// sentinel itself is missing but a pre-recover copy exists, put the copy
/// back. Never deletes the pre-recover copy (that needs proof the current
/// sentinel opens: [`finish_after_auth`]).
pub fn cleanup_before_auth(vault: &Vault) -> KvendraResult<()> {
    cleanup_init_tmp(vault.home())?;
    if !recover_tmp_path(vault).exists() && !pre_recover_path(vault).exists() {
        return Ok(());
    }
    // A recover/passwd in progress owns these files: leave them alone.
    let Some(_lock) = try_lock_rekey(vault.home())? else {
        return Ok(());
    };
    let tmp = recover_tmp_path(vault);
    if tmp.exists() {
        std::fs::remove_file(&tmp)?;
    }
    let pre = pre_recover_path(vault);
    if !vault.sentinel_path().exists() && pre.exists() {
        std::fs::rename(&pre, vault.sentinel_path())?;
        fsutil::fsync_dir(vault.home())?;
    }
    Ok(())
}

/// Leftover of an init that crashed between publishing `sentinel.blob`
/// (hard link) and removing its tmp (B5).
pub const INIT_TMP_NAME: &str = "sentinel.blob.init-tmp";

/// With `sentinel.blob` present: a byte-identical `sentinel.blob.init-tmp`
/// is removed; a different one is moved (never deleted) to
/// `.init-orphans-<ts>/`. Skipped while an init holds `.init.lock`.
/// Returns the quarantine directory when something was moved.
pub fn cleanup_init_tmp(home: &Path) -> KvendraResult<Option<PathBuf>> {
    if !home.join(INIT_TMP_NAME).exists() || !home.join("sentinel.blob").exists() {
        return Ok(None);
    }
    let Some(_lock) = fsutil::try_lock_exclusive(&home.join(crate::cli::init::INIT_LOCK_NAME))?
    else {
        return Ok(None);
    };
    cleanup_init_tmp_locked(home)
}

/// [`cleanup_init_tmp`] for a caller that already holds `.init.lock`.
pub(crate) fn cleanup_init_tmp_locked(home: &Path) -> KvendraResult<Option<PathBuf>> {
    let tmp = home.join(INIT_TMP_NAME);
    let sentinel = home.join("sentinel.blob");
    if !tmp.exists() || !sentinel.exists() {
        return Ok(None);
    }
    if std::fs::read(&tmp)? == std::fs::read(&sentinel)? {
        std::fs::remove_file(&tmp)?;
        fsutil::fsync_dir(home)?;
        return Ok(None);
    }
    let dir = crate::cli::init::new_orphans_dir(home)?;
    std::fs::rename(&tmp, dir.join(INIT_TMP_NAME))?;
    fsutil::fsync_dir(home)?;
    eprintln!(
        "warning: {INIT_TMP_NAME} did not match sentinel.blob; it was moved, not deleted, to {}",
        dir.display()
    );
    Ok(Some(dir))
}

/// After a successful authentication with the CURRENT sentinel (unlock,
/// mcp serve, recover/passwd): remove a leftover pre-recover copy (audited
/// as `recover_cleanup`) and import pending pre-auth rejections.
pub async fn finish_after_auth(home: &Path, audit_hmac_key: Vec<u8>) -> KvendraResult<()> {
    let vault = Vault::new(home.to_path_buf());
    let pre = pre_recover_path(&vault);
    let lock = if pre.exists() {
        try_lock_rekey(home)?
    } else {
        None
    };
    if let Some(_lock) = lock
        && pre.exists()
    {
        std::fs::remove_file(&pre)?;
        fsutil::fsync_dir(home)?;
        record_system_row(
            home,
            audit_hmac_key.clone(),
            "recover_cleanup",
            FLAG_RECOVER_CLEANUP,
        )
        .await?;
    }
    crate::audit::preauth::flush_into_chain(home, audit_hmac_key).await?;
    Ok(())
}

async fn record_system_row(
    home: &Path,
    hmac_key: Vec<u8>,
    action: &str,
    flag: &str,
) -> KvendraResult<()> {
    let writer = AuditWriter::spawn(home.join("audit.db"), hmac_key)?;
    let event = AuditEvent {
        ts_unix_ms: time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64 / 1_000_000,
        profile_id: PRIMITIVE_SYSTEM.into(),
        primitive: PRIMITIVE_SYSTEM.into(),
        action: action.into(),
        args_hash_hex: args_hash_hex(&serde_json::json!({})),
        status: Status::Ok,
        severity: Severity::Info,
        flags: flag.into(),
        remote_audit_id: None,
        error_code: None,
        error_message: None,
    };
    let r = writer.record(event).await;
    writer.shutdown().await;
    r.map(|_| ())
}

/// Record the current vault (`home`, sentinel v2) as the owner of the
/// keychain `label` it just wrote. Best effort: a v1 vault or an unavailable
/// backend just leaves the entry untagged (never removed by recover/passwd).
pub fn bind_keychain_owner(home: &Path, label: &str) {
    let vault = Vault::new(home.to_path_buf());
    let Ok(crate::vault::envelope::Sentinel::V2(s)) = vault.read_sentinel() else {
        return;
    };
    let Ok(id) = s.vault_id() else { return };
    match caches_for_process() {
        Ok(c) => {
            if let Err(e) = c.set_owner(label, &id.to_hex()) {
                tracing::warn!(target: "kvendra::rekey", "keychain owner tag not written: {e}");
            }
        }
        Err(e) => tracing::warn!(target: "kvendra::rekey", "keychain owner tag not written: {e}"),
    }
}

/// Remove the owner tag of `label` (used by the `disable` commands).
pub fn unbind_keychain_owner(label: &str) {
    if let Ok(c) = caches_for_process() {
        let _ = c.delete_owner(label);
    }
}

/// Why a keychain entry was left in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeptReason {
    /// Owner tag names another vault.
    OtherVault,
    /// Entry exists without an owner tag (written before 0.9).
    NoOwner,
    /// derived-key/v1 only: the backend failed (best effort, B4).
    BackendError(String),
}

/// What happened to one keychain entry during the commit (M1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheOutcome {
    Removed,
    /// Did not exist: nothing to report.
    Absent,
    Kept(KeptReason),
}

/// Exactly what the cache invalidation did (feeds the final message).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RekeyReport {
    pub session_removed: bool,
    pub wrapper_removed: bool,
    pub keychain: Vec<(&'static str, CacheOutcome)>,
}

fn disable_command(label: &str) -> &'static str {
    if label == KEYCHAIN_MCP_PASSWORD_LABEL {
        "kvendra config mcp-password disable"
    } else {
        "kvendra config keychain disable"
    }
}

/// Notice for an entry that was left in place.
pub fn kept_notice(label: &str, reason: &KeptReason) -> String {
    let fix = disable_command(label);
    match reason {
        KeptReason::OtherVault => format!(
            "Keychain entry {label} was left untouched: it belongs to another vault. It cannot \
             open this vault with the new password."
        ),
        KeptReason::NoOwner => format!(
            "Keychain entry {label} was left untouched: it is not bound to any vault (written \
             before 0.9). It cannot open this vault with the new password; if it holds this \
             vault's old password, remove it with `{fix}`."
        ),
        KeptReason::BackendError(e) => format!(
            "Keychain entry {label} could not be checked or removed ({e}); it only ever holds a \
             presence flag, never key material. Remove it with `{fix}` if it is still there."
        ),
    }
}

/// The final message of `recover` / `passwd`, built from what actually
/// happened (no fixed claim about caches — M1).
pub fn success_message(action: RekeyAction, report: &RekeyReport) -> String {
    let mut out = String::new();
    out.push_str(match action {
        RekeyAction::Recover => "Master password reset.",
        RekeyAction::Passwd => "Master password changed.",
    });
    out.push_str(" Your secrets, local variables, allowlists, grants and backups keep working.\n");
    out.push_str(if report.session_removed {
        "The local session (sessions/active.blob) was cleared.\n"
    } else {
        "There was no local session to clear.\n"
    });
    if report.wrapper_removed {
        out.push_str("The legacy MCP wrapper script was removed.\n");
    }
    let mut any_keychain = false;
    for (label, outcome) in &report.keychain {
        match outcome {
            CacheOutcome::Removed => {
                any_keychain = true;
                out.push_str(&format!("Keychain entry {label} was removed.\n"));
            }
            CacheOutcome::Absent => {}
            CacheOutcome::Kept(reason) => {
                any_keychain = true;
                out.push_str(&kept_notice(label, reason));
                out.push('\n');
            }
        }
    }
    if !any_keychain {
        out.push_str("No kvendra keychain entries were found.\n");
    }
    out.push_str(
        "Any running `kvendra mcp serve` keeps its in-memory session until it expires — \
         restart it.\n",
    );
    out.push_str(match action {
        RekeyAction::Recover => {
            "If you suspect the old password was stolen, recovery is not enough: create a new \
             vault."
        }
        RekeyAction::Passwd => {
            "Old copies of sentinel.blob (for example inside earlier backups) still open with the \
             OLD password: if you suspect it was stolen, create a new vault instead."
        }
    });
    out
}

/// What the commit will do with one keychain entry, decided BEFORE any
/// deletion (round 3 B2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CachePlan {
    /// Owner tag is this vault: remove it.
    Delete,
    /// Nothing there.
    Absent,
    /// Leave it (another vault, no owner, or derived-key backend error).
    Keep(KeptReason),
}

/// Read-only phase: owner tags and existence of every keychain entry. A
/// backend error on `mcp-password/v1` (which holds the OLD password) aborts
/// here, before anything has been deleted (B4 + round 3 B2); for
/// `derived-key/v1` it becomes `Keep(BackendError)`.
pub fn plan_cache_invalidation(
    vault_id_hex: &str,
    caches: &dyn CredentialCaches,
) -> KvendraResult<Vec<(&'static str, CachePlan)>> {
    let mut plan = Vec::new();
    for label in [KEYCHAIN_DERIVED_KEY_LABEL, KEYCHAIN_MCP_PASSWORD_LABEL] {
        let p = match plan_entry(label, vault_id_hex, caches) {
            Ok(p) => p,
            Err(e) if label == KEYCHAIN_MCP_PASSWORD_LABEL => return Err(e),
            Err(e) => {
                tracing::warn!(target: "kvendra::rekey", "{label}: {e}");
                CachePlan::Keep(KeptReason::BackendError(e.to_string()))
            }
        };
        plan.push((label, p));
    }
    Ok(plan)
}

fn plan_entry(
    label: &str,
    vault_id_hex: &str,
    caches: &dyn CredentialCaches,
) -> KvendraResult<CachePlan> {
    Ok(match caches.owner(label)? {
        Some(owner) if owner == vault_id_hex => CachePlan::Delete,
        Some(_) if caches.exists(label)? => CachePlan::Keep(KeptReason::OtherVault),
        None if caches.exists(label)? => CachePlan::Keep(KeptReason::NoOwner),
        _ => CachePlan::Absent,
    })
}

/// Invalidate every cache holding MK or the old password. Idempotent.
/// Keychain entries are removed only when their owner tag is `vault_id_hex`
/// (per-vault, M3); each entry ends Removed, Absent or Kept (M1). All owner
/// tags are read first ([`plan_cache_invalidation`]): a backend error there
/// aborts before anything is deleted. A failure to DELETE mcp-password/v1
/// still aborts, but the session blob (and derived-key/v1, if it was due)
/// may already be gone — both regenerate on the next unlock.
pub fn invalidate_caches(
    home: &Path,
    vault_id_hex: &str,
    caches: &dyn CredentialCaches,
) -> KvendraResult<RekeyReport> {
    let plan = plan_cache_invalidation(vault_id_hex, caches)?;
    apply_cache_invalidation(home, plan, caches)
}

/// Destructive phase: session blob, planned keychain deletions, wrapper.
pub fn apply_cache_invalidation(
    home: &Path,
    plan: Vec<(&'static str, CachePlan)>,
    caches: &dyn CredentialCaches,
) -> KvendraResult<RekeyReport> {
    let mut report = RekeyReport {
        session_removed: crate::session::local::delete(home)?,
        ..Default::default()
    };
    for (label, p) in plan {
        let outcome = match p {
            CachePlan::Absent => CacheOutcome::Absent,
            CachePlan::Keep(r) => CacheOutcome::Kept(r),
            CachePlan::Delete => match caches.delete_entry(label) {
                Ok(removed) => {
                    if let Err(e) = caches.delete_owner(label) {
                        tracing::warn!(target: "kvendra::rekey", "{label} owner tag not removed: {e}");
                    }
                    if removed {
                        CacheOutcome::Removed
                    } else {
                        CacheOutcome::Absent
                    }
                }
                // mcp-password/v1 holds the OLD password: abort.
                Err(e) if label == KEYCHAIN_MCP_PASSWORD_LABEL => return Err(e),
                Err(e) => {
                    tracing::warn!(target: "kvendra::rekey", "{label}: {e}");
                    CacheOutcome::Kept(KeptReason::BackendError(e.to_string()))
                }
            },
        };
        report.keychain.push((label, outcome));
    }
    let wrapper = home.join("wrappers").join(LEGACY_WRAPPER_NAME);
    match std::fs::remove_file(&wrapper) {
        Ok(()) => report.wrapper_removed = true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(report)
}

/// Publish `new_sentinel` (which must wrap `mk`) as the vault's sentinel.
/// See the module docs for the exact sequence and failure semantics.
pub async fn commit_new_password(
    vault: &Vault,
    mk: &MasterKey,
    new_sentinel: &SentinelV2,
    new_password: &[u8],
    caches: &dyn CredentialCaches,
    action: RekeyAction,
) -> KvendraResult<RekeyReport> {
    if !new_sentinel.verifies(mk) {
        return Err(KvendraError::Vault(
            "new sentinel does not wrap this vault's key".into(),
        ));
    }
    let home = vault.home().to_path_buf();
    let sentinel = vault.sentinel_path();
    let pre = pre_recover_path(vault);
    let tmp = recover_tmp_path(vault);

    let vault_id_hex = new_sentinel.vault_id()?.to_hex();
    let _lock = try_lock_rekey(&home)?.ok_or_else(|| {
        KvendraError::Vault(
            "another `kvendra recover` or `kvendra passwd` is in progress on this vault; \
             nothing was changed"
                .into(),
        )
    })?;
    // Under the lock: the CURRENT sentinel (maybe just re-wrapped by another
    // command) must still be this vault's.
    if !vault.read_sentinel()?.verifies_master_key(mk.as_bytes())? {
        return Err(KvendraError::Vault(
            "sentinel.blob changed and no longer matches this vault's key; nothing was changed"
                .into(),
        ));
    }
    // Read-only first (round 3 B2): every keychain owner tag is read before
    // anything is deleted, so an owner-read failure aborts with no change.
    let plan = plan_cache_invalidation(&vault_id_hex, caches)?;

    // A stale pre-recover copy from an earlier crash: the caller proved `mk`
    // against the CURRENT sentinel, so it can go — but that earlier password
    // change may have no audit row of its own (crash after the rename), so
    // its removal is audited as `recover_cleanup` exactly like in
    // `finish_after_auth` (B2).
    let hmac_key = hkdf_expand(mk.as_bytes(), HKDF_INFO_AUDIT_HMAC).to_vec();
    if pre.exists() {
        std::fs::remove_file(&pre)?;
        fsutil::fsync_dir(&home)?;
        record_system_row(
            &home,
            hmac_key.clone(),
            "recover_cleanup",
            FLAG_RECOVER_CLEANUP,
        )
        .await?;
    }
    let _ = std::fs::remove_file(&tmp);

    maybe_fail("rekey.before_invalidate")?;
    let report = apply_cache_invalidation(&home, plan, caches)?;
    maybe_fail("rekey.after_invalidate")?;

    let original = std::fs::read(&sentinel)?;
    let published = publish(vault, mk, new_sentinel, new_password, action, &original).await;
    if let Err(e) = published {
        restore_previous(&home, &sentinel, &pre, &tmp, &original);
        return Err(e);
    }

    // Past the audit row: the change is final. Cleanup failures are
    // warnings (handled again by `finish_after_auth` later).
    if let Err(e) = maybe_fail("rekey.before_cleanup").and_then(|_| {
        std::fs::remove_file(&pre)?;
        fsutil::fsync_dir(&home)
    }) {
        tracing::warn!(target: "kvendra::rekey", "pre-recover copy kept: {e}");
    }
    if let Err(e) = crate::audit::preauth::flush_into_chain(&home, hmac_key).await {
        tracing::warn!(target: "kvendra::rekey", "pre-auth rejections not imported yet: {e}");
    }
    Ok(report)
}

async fn publish(
    vault: &Vault,
    mk: &MasterKey,
    new_sentinel: &SentinelV2,
    new_password: &[u8],
    action: RekeyAction,
    original: &[u8],
) -> KvendraResult<()> {
    let home = vault.home();
    let sentinel = &vault.sentinel_path();
    let pre = &pre_recover_path(vault);
    let tmp = &recover_tmp_path(vault);
    fsutil::write_new_synced(pre, original)?;
    maybe_fail("rekey.after_pre_copy")?;

    fsutil::write_new_synced(tmp, new_sentinel.to_json()?.as_bytes())?;
    maybe_fail("rekey.after_tmp")?;

    std::fs::rename(tmp, sentinel)?;
    maybe_fail("rekey.after_rename")?;
    fsutil::fsync_dir(home)?;
    maybe_fail("rekey.after_dir_fsync")?;

    let check = vault.master_key_from_password(new_password)?;
    maybe_fail("rekey.after_verify")?;
    if !check.ct_eq(mk) {
        return Err(KvendraError::Vault(
            "new sentinel did not yield the vault key; previous sentinel restored".into(),
        ));
    }

    maybe_fail("rekey.before_audit")?;
    let hmac_key = hkdf_expand(mk.as_bytes(), HKDF_INFO_AUDIT_HMAC).to_vec();
    record_system_row(home, hmac_key, action.action(), action.flag()).await
}

/// Put the previous sentinel back after a failure in the publish sequence.
/// `original` (the sentinel bytes read before the commit) is the source of
/// truth: a partially written pre-recover copy is never renamed over a
/// good sentinel.
fn restore_previous(home: &Path, sentinel: &Path, pre: &Path, tmp: &Path, original: &[u8]) {
    let _ = std::fs::remove_file(tmp);
    let current = std::fs::read(sentinel).ok();
    if current.as_deref() != Some(original) {
        let restored = if std::fs::read(pre).ok().as_deref() == Some(original) {
            std::fs::rename(pre, sentinel).map_err(KvendraError::from)
        } else {
            fsutil::write_atomic(sentinel, original)
        };
        if let Err(e) = restored {
            tracing::error!(target: "kvendra::rekey", "could not restore previous sentinel: {e}");
            return;
        }
        let _ = fsutil::fsync_dir(home);
    }
    let _ = std::fs::remove_file(pre);
}

/// Map a rejection to its pre-auth reason (None = not a pre-auth rejection).
fn preauth_reason(e: &KvendraError) -> Option<Reason> {
    match e {
        KvendraError::RecoveryUnavailable | KvendraError::RecoveryBlobMissing => {
            Some(Reason::Unavailable)
        }
        KvendraError::RecoveryPhraseInvalid { .. } => Some(Reason::PhraseInvalid),
        KvendraError::RecoveryPhraseMismatch => Some(Reason::PhraseMismatch),
        KvendraError::RecoveryMaterialCorrupt(_) => Some(Reason::MaterialCorrupt),
        KvendraError::InvalidMasterPassword => Some(Reason::PasswordInvalid),
        _ => None,
    }
}

fn logged<T>(home: &Path, action: &'static str, r: KvendraResult<T>) -> KvendraResult<T> {
    if let Err(e) = &r
        && let Some(reason) = preauth_reason(e)
    {
        record_rejection(home, action, reason);
    }
    r
}

/// Minimum master-password length (same rule as `kvendra init`).
pub const MIN_PASSWORD_LEN: usize = 8;

/// `kvendra recover` (F3). Strict order, nothing written before the commit:
/// availability (before asking the phrase) → phrase (`read_phrase`) → BIP-39
/// validation (before asking a new password) → open `recovery.blob` →
/// `read_new_password` → re-wrap in memory → [`commit_new_password`].
/// Every rejection appends one line to `audit.preauth.jsonl`.
pub async fn recover_with_phrase(
    vault: &Vault,
    read_phrase: impl FnOnce() -> KvendraResult<Zeroizing<String>>,
    read_new_password: impl FnOnce() -> KvendraResult<Zeroizing<String>>,
    caches: &dyn CredentialCaches,
) -> KvendraResult<RekeyReport> {
    let home = vault.home().to_path_buf();
    if !vault.sentinel_path().exists() {
        return Err(KvendraError::Vault(
            "vault not initialized. Run `kvendra init` first.".into(),
        ));
    }
    cleanup_before_auth(vault)?;
    if matches!(
        vault.read_sentinel()?,
        crate::vault::envelope::Sentinel::V1(_)
    ) {
        return logged(&home, "recover", Err(KvendraError::RecoveryUnavailable));
    }
    // Missing (RecoveryBlobMissing) or corrupt / unknown-version material is
    // refused before the phrase.
    logged(&home, "recover", vault.read_recovery_blob())?;

    let phrase = read_phrase()?;
    let mnemonic = logged(&home, "recover", parse_phrase(&phrase))?;
    drop(phrase);
    let mk = logged(&home, "recover", vault.open_recovery(&mnemonic))?;
    drop(mnemonic);

    let new_password = read_new_password()?;
    if new_password.len() < MIN_PASSWORD_LEN {
        return Err(KvendraError::Vault(
            "master password must be ≥ 8 characters".into(),
        ));
    }
    let new_sentinel = vault.rewrap_password(&mk, new_password.as_bytes())?;
    commit_new_password(
        vault,
        &mk,
        &new_sentinel,
        new_password.as_bytes(),
        caches,
        RekeyAction::Recover,
    )
    .await
}

/// Refusal for `kvendra passwd` on a 0.8.0 (sentinel v1) vault.
pub const PASSWD_V1_UNSUPPORTED: &str = "This vault was created before Kvendra 0.9; changing its password is not \
     supported. Nothing was changed.";

/// Checks that need no secret: initialized, leftovers dropped, not v1.
pub fn passwd_preflight(vault: &Vault) -> KvendraResult<()> {
    if !vault.sentinel_path().exists() {
        return Err(KvendraError::Vault(
            "vault not initialized. Run `kvendra init` first.".into(),
        ));
    }
    cleanup_before_auth(vault)?;
    match vault.read_sentinel()? {
        crate::vault::envelope::Sentinel::V1(_) => {
            Err(KvendraError::Vault(PASSWD_V1_UNSUPPORTED.into()))
        }
        crate::vault::envelope::Sentinel::V2(_) => Ok(()),
    }
}

/// `kvendra passwd` (F5): current password → MK (wrong one: logged
/// pre-auth, nothing written) → new password (≥ 8, different) → re-wrap →
/// [`commit_new_password`].
pub async fn change_password(
    vault: &Vault,
    read_current: impl FnOnce() -> KvendraResult<Zeroizing<String>>,
    read_new: impl FnOnce() -> KvendraResult<Zeroizing<String>>,
    caches: &dyn CredentialCaches,
) -> KvendraResult<RekeyReport> {
    use subtle::ConstantTimeEq;
    let home = vault.home().to_path_buf();
    passwd_preflight(vault)?;
    let current = read_current()?;
    let mk = logged(
        &home,
        "passwd",
        vault.master_key_from_password(current.as_bytes()),
    )?;
    let new_password = read_new()?;
    if new_password.len() < MIN_PASSWORD_LEN {
        return Err(KvendraError::Vault(
            "master password must be ≥ 8 characters".into(),
        ));
    }
    if bool::from(current.as_bytes().ct_eq(new_password.as_bytes())) {
        return Err(KvendraError::Vault(
            "the new master password must differ from the current one — nothing was changed".into(),
        ));
    }
    drop(current);
    let new_sentinel = vault.rewrap_password(&mk, new_password.as_bytes())?;
    commit_new_password(
        vault,
        &mk,
        &new_sentinel,
        new_password.as_bytes(),
        caches,
        RekeyAction::Passwd,
    )
    .await
}
