//! Restore of a decrypted backup bundle into a staging directory
//! (REQ-KVD-CLI-CFB449 F4, ISSUE-KVD-CLI-043B2B).
//!
//! The bundle was sealed under a key derived from the vault key (MK), so it
//! decrypts with the CURRENT password even if the bundle was made before a
//! `recover` / `passwd`. But it carries the sentinel of that time — whose
//! password may be the forgotten one. Moving such a staging into place would
//! silently bring the old password back. So, for a v2 bundle of THIS vault
//! (same vault_id, its `check` opens with the local MK), the staging
//! sentinel is replaced by a copy of the local one (current password); the
//! bundle's `recovery.blob` is kept (same MK). Anything else is refused
//! fail-closed and the staging is not left behind half-built.

use crate::backup::bundle;
use crate::error::{KvendraError, KvendraResult};
use crate::vault::Vault;
use crate::vault::envelope::{MasterKey, Sentinel};
use crate::vault::fsutil;
use std::path::Path;

/// Outcome of [`restore_into_staging`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreReport {
    /// Files extracted from the bundle.
    pub entries: usize,
    /// Local variables reset to `verified:false`.
    pub vars_reset: usize,
    /// Whether the staging sentinel was replaced by the local one.
    pub sentinel_replaced: bool,
}

/// Extract `tar_bytes` into `target`, reconcile its sentinel with the local
/// vault and re-seal its `vars.blob` unverified. Work happens in a fresh
/// sibling directory; `target` only receives a fully reconciled tree.
pub fn restore_into_staging(
    local: &Vault,
    mk: &MasterKey,
    tar_bytes: &[u8],
    target: &Path,
) -> KvendraResult<RestoreReport> {
    let partial = fsutil::sibling(target, &format!("partial-{}", std::process::id()));
    if partial.exists() {
        std::fs::remove_dir_all(&partial)?;
    }
    let result = (|| {
        let entries = bundle::extract_bundle(tar_bytes, &partial)?;
        let sentinel_replaced = reconcile_sentinel(local, mk, &partial)?;
        let vars_reset = crate::vars::mark_restored_unverified(&partial, mk)?;
        Ok(RestoreReport {
            entries,
            vars_reset,
            sentinel_replaced,
        })
    })();
    let report = match result {
        Ok(r) => r,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&partial);
            return Err(e);
        }
    };
    if target.exists() {
        // `--yes` over an existing directory: same merge-overwrite semantics
        // as before, but only with the reconciled files.
        if let Err(e) = copy_tree(&partial, target) {
            let _ = std::fs::remove_dir_all(&partial);
            return Err(e);
        }
        std::fs::remove_dir_all(&partial)?;
    } else {
        std::fs::rename(&partial, target)?;
    }
    Ok(report)
}

/// Returns whether the staging sentinel was replaced.
fn reconcile_sentinel(local: &Vault, mk: &MasterKey, staging_home: &Path) -> KvendraResult<bool> {
    let staging = Vault::new(staging_home.to_path_buf());
    if !staging.sentinel_path().exists() {
        return Ok(false);
    }
    match staging.read_sentinel()? {
        // 0.8.0 bundle: same behaviour as before (no envelope to reconcile).
        Sentinel::V1(_) => Ok(false),
        Sentinel::V2(restored) => {
            let Sentinel::V2(current) = local.read_sentinel()? else {
                return Err(KvendraError::RecoveryMaterialCorrupt(
                    "restored sentinel.blob is v2 but the local vault is not".into(),
                ));
            };
            if restored.vault_id != current.vault_id || !restored.verifies(mk) {
                return Err(KvendraError::RecoveryMaterialCorrupt(
                    "restored sentinel.blob does not belong to this vault".into(),
                ));
            }
            let bytes = std::fs::read(local.sentinel_path())?;
            fsutil::write_atomic(&staging.sentinel_path(), &bytes)?;
            Ok(true)
        }
    }
}

fn copy_tree(src: &Path, dst: &Path) -> KvendraResult<()> {
    std::fs::create_dir_all(dst)?;
    for e in std::fs::read_dir(src)? {
        let e = e?;
        let to = dst.join(e.file_name());
        if e.file_type()?.is_dir() {
            copy_tree(&e.path(), &to)?;
        } else {
            std::fs::copy(e.path(), &to)?;
            crate::config::set_file_mode_secure(&to)?;
        }
    }
    Ok(())
}
