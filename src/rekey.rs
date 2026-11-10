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
    /// `vault_id` (hex) recorded for `label`, if any. Backend errors read
    /// as "no owner" (the entry is then left untouched).
    fn owner(&self, label: &str) -> Option<String>;
    /// Record `vault_id_hex` as the owner of `label`.
    fn set_owner(&self, label: &str, vault_id_hex: &str) -> KvendraResult<()>;
    /// Remove the entry itself. Absent = success.
    fn delete_entry(&self, label: &str) -> KvendraResult<()>;
    /// Remove the owner tag. Absent = success.
    fn delete_owner(&self, label: &str) -> KvendraResult<()>;
}

/// Real OS keychain.
pub struct OsCredentialCaches;

impl CredentialCaches for OsCredentialCaches {
    fn owner(&self, label: &str) -> Option<String> {
        keyring::Entry::new(KEYCHAIN_SERVICE, &owner_label(label))
            .ok()?
            .get_password()
            .ok()
    }

    fn set_owner(&self, label: &str, vault_id_hex: &str) -> KvendraResult<()> {
        keyring::Entry::new(KEYCHAIN_SERVICE, &owner_label(label))
            .and_then(|e| e.set_password(vault_id_hex))
            .map_err(|e| KvendraError::Keychain(e.to_string()))
    }

    fn delete_entry(&self, label: &str) -> KvendraResult<()> {
        if label == KEYCHAIN_MCP_PASSWORD_LABEL {
            use crate::keychain_acl::{self, BiometricError};
            return match keychain_acl::delete(label) {
                Ok(()) | Err(BiometricError::NotFound(_)) | Err(BiometricError::Unavailable(_)) => {
                    Ok(())
                }
                Err(e) => Err(KvendraError::Keychain(format!(
                    "could not remove {label}: {e:?}"
                ))),
            };
        }
        match keyring::Entry::new(KEYCHAIN_SERVICE, label) {
            Ok(entry) => match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(KvendraError::Keychain(e.to_string())),
            },
            Err(e) => Err(KvendraError::Keychain(e.to_string())),
        }
    }

    fn delete_owner(&self, label: &str) -> KvendraResult<()> {
        match keyring::Entry::new(KEYCHAIN_SERVICE, &owner_label(label)) {
            Ok(entry) => match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(KvendraError::Keychain(e.to_string())),
            },
            Err(e) => Err(KvendraError::Keychain(e.to_string())),
        }
    }
}

/// File-backed fake keychain (tests). Each entry is a file in `dir`.
pub struct FileCredentialCaches {
    pub dir: PathBuf,
}

impl FileCredentialCaches {
    pub fn entry_path(&self, label: &str) -> PathBuf {
        self.dir.join(label.replace('/', "_"))
    }

    fn remove(&self, label: &str) -> KvendraResult<()> {
        if std::env::var("KVENDRA_TEST_KEYCHAIN_FAIL").is_ok_and(|l| l == label) {
            return Err(KvendraError::Keychain(format!(
                "fake keychain refused {label}"
            )));
        }
        match std::fs::remove_file(self.entry_path(label)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

impl CredentialCaches for FileCredentialCaches {
    fn owner(&self, label: &str) -> Option<String> {
        std::fs::read_to_string(self.entry_path(&owner_label(label))).ok()
    }

    fn set_owner(&self, label: &str, vault_id_hex: &str) -> KvendraResult<()> {
        std::fs::create_dir_all(&self.dir)?;
        std::fs::write(self.entry_path(&owner_label(label)), vault_id_hex)?;
        Ok(())
    }

    fn delete_entry(&self, label: &str) -> KvendraResult<()> {
        self.remove(label)
    }

    fn delete_owner(&self, label: &str) -> KvendraResult<()> {
        self.remove(&owner_label(label))
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

/// Keychain entries left untouched because they are not bound to this vault.
pub fn not_owned_notice(label: &str) -> String {
    let fix = if label == KEYCHAIN_MCP_PASSWORD_LABEL {
        "kvendra config mcp-password disable"
    } else {
        "kvendra config keychain disable"
    };
    format!(
        "note: keychain entry {label} was left untouched: it is not bound to this vault \
         (written by another vault or by a release before 0.9). It cannot open this vault \
         with the new password; if it holds this vault's old password, remove it with `{fix}`."
    )
}

/// Invalidate every cache holding MK or the old password. Idempotent.
/// Keychain entries are removed only when their owner tag is `vault_id_hex`
/// (M3); the labels skipped are returned so the caller can tell the user.
pub fn invalidate_caches(
    home: &Path,
    vault_id_hex: &str,
    caches: &dyn CredentialCaches,
) -> KvendraResult<Vec<&'static str>> {
    crate::session::local::delete(home)?;
    let mut skipped = Vec::new();
    for label in [KEYCHAIN_DERIVED_KEY_LABEL, KEYCHAIN_MCP_PASSWORD_LABEL] {
        if caches.owner(label).as_deref() != Some(vault_id_hex) {
            skipped.push(label);
            continue;
        }
        match caches.delete_entry(label) {
            Ok(()) => {}
            // The mcp-password entry holds the OLD password: abort.
            Err(e) if label == KEYCHAIN_MCP_PASSWORD_LABEL => return Err(e),
            // derived-key/v1 only ever holds a constant presence flag (never
            // key material): a backend failure must not block recovery.
            Err(e) => tracing::warn!(target: "kvendra::rekey", "{label} not removed: {e}"),
        }
        if let Err(e) = caches.delete_owner(label) {
            tracing::warn!(target: "kvendra::rekey", "{label} owner tag not removed: {e}");
        }
    }
    let wrapper = home.join("wrappers").join(LEGACY_WRAPPER_NAME);
    match std::fs::remove_file(&wrapper) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(skipped)
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
) -> KvendraResult<()> {
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
    maybe_fail("rekey.before_invalidate")?;
    let skipped = invalidate_caches(&home, &vault_id_hex, caches)?;
    maybe_fail("rekey.after_invalidate")?;

    // The caller proved `mk` against the CURRENT sentinel, so a stale
    // pre-recover copy from an earlier crash can go.
    if pre.exists() {
        std::fs::remove_file(&pre)?;
    }
    let _ = std::fs::remove_file(&tmp);

    let original = std::fs::read(&sentinel)?;
    let published = publish(vault, mk, new_sentinel, new_password, action, &original).await;
    if let Err(e) = published {
        restore_previous(&home, &sentinel, &pre, &tmp, &original);
        return Err(e);
    }

    // Past the audit row: the change is final. Cleanup failures are
    // warnings (handled again by `finish_after_auth` later).
    let hmac_key = hkdf_expand(mk.as_bytes(), HKDF_INFO_AUDIT_HMAC).to_vec();
    if let Err(e) = maybe_fail("rekey.before_cleanup").and_then(|_| {
        std::fs::remove_file(&pre)?;
        fsutil::fsync_dir(&home)
    }) {
        tracing::warn!(target: "kvendra::rekey", "pre-recover copy kept: {e}");
    }
    if let Err(e) = crate::audit::preauth::flush_into_chain(&home, hmac_key).await {
        tracing::warn!(target: "kvendra::rekey", "pre-auth rejections not imported yet: {e}");
    }
    for label in skipped {
        eprintln!("{}", not_owned_notice(label));
    }
    Ok(())
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
) -> KvendraResult<()> {
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
) -> KvendraResult<()> {
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
