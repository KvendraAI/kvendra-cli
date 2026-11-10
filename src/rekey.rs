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

/// OS credential caches that a password change must invalidate. Abstracted
/// so tests never read or delete the machine's real keychain entries.
pub trait CredentialCaches: Send + Sync {
    /// Remove `kvendra/derived-key/v1`. Absent = success.
    fn delete_derived_key(&self) -> KvendraResult<()>;
    /// Remove `kvendra/mcp-password/v1`. Absent = success.
    fn delete_mcp_password(&self) -> KvendraResult<()>;
}

/// Real OS keychain.
pub struct OsCredentialCaches;

impl CredentialCaches for OsCredentialCaches {
    fn delete_derived_key(&self) -> KvendraResult<()> {
        // Since 0.5 this entry only ever holds a constant presence flag
        // (`kvendra unlock` stores B64("kvendra-keychain-sentinel-v1")), never
        // key material, so it cannot open the vault with any password. A
        // backend that is not available (headless Linux, CI) therefore must
        // not block a recovery: warn and continue.
        match keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_DERIVED_KEY_LABEL) {
            Ok(entry) => match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => {
                    tracing::warn!(target: "kvendra::rekey", "derived-key/v1 not removed: {e}");
                    Ok(())
                }
            },
            Err(e) => {
                tracing::warn!(target: "kvendra::rekey", "keychain backend unavailable: {e}");
                Ok(())
            }
        }
    }

    fn delete_mcp_password(&self) -> KvendraResult<()> {
        use crate::keychain_acl::{self, BiometricError};
        // This entry holds the OLD master password: failing to remove it
        // aborts the commit.
        match keychain_acl::delete(KEYCHAIN_MCP_PASSWORD_LABEL) {
            Ok(()) | Err(BiometricError::NotFound(_)) | Err(BiometricError::Unavailable(_)) => {
                Ok(())
            }
            Err(e) => Err(KvendraError::Keychain(format!(
                "could not remove {KEYCHAIN_MCP_PASSWORD_LABEL}: {e:?}"
            ))),
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

    fn delete(&self, label: &str) -> KvendraResult<()> {
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
    fn delete_derived_key(&self) -> KvendraResult<()> {
        self.delete(KEYCHAIN_DERIVED_KEY_LABEL)
    }

    fn delete_mcp_password(&self) -> KvendraResult<()> {
        self.delete(KEYCHAIN_MCP_PASSWORD_LABEL)
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

/// Before any authentication: drop an unpublished tmp sentinel and, if the
/// sentinel itself is missing but a pre-recover copy exists, put the copy
/// back. Never deletes the pre-recover copy (that needs proof the current
/// sentinel opens: [`finish_after_auth`]).
pub fn cleanup_before_auth(vault: &Vault) -> KvendraResult<()> {
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
    if pre.exists() {
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

/// Invalidate every cache holding MK or the old password. Idempotent.
pub fn invalidate_caches(home: &Path, caches: &dyn CredentialCaches) -> KvendraResult<()> {
    crate::session::local::delete(home)?;
    caches.delete_derived_key()?;
    caches.delete_mcp_password()?;
    let wrapper = home.join("wrappers").join(LEGACY_WRAPPER_NAME);
    match std::fs::remove_file(&wrapper) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
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

    maybe_fail("rekey.before_invalidate")?;
    invalidate_caches(&home, caches)?;
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
        KvendraError::RecoveryUnavailable => Some(Reason::Unavailable),
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
    let available = logged(&home, "recover", vault.recovery_available())?;
    if !available {
        return logged(&home, "recover", Err(KvendraError::RecoveryUnavailable));
    }
    // Corrupt / unknown-version material is refused before the phrase.
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
