//! Local variables `{{lvr:<key>}}` (REQ-KVD-11F906, SPEC DOC-KVD-E49C6E F1).
//!
//! The KB declares per-user, per-machine variables (CFG `kind:"local_var"`,
//! no value) and content references them as `{{lvr:key}}`. Each machine keeps
//! the value in `vars.blob`, written ONLY by a human on a real TTY with the
//! master password (S0 — `cli::vars`). The MCP broker substitutes a reference
//! INSIDE its primitives, only in positions bounded by the signed allowlist
//! ([`position`]), validates the value by type ([`validate`]) and masks every
//! local value out of its responses ([`filter`]).
//!
//! # On-disk format (D1)
//!
//! `vars.blob` reuses the [`Blob`] envelope (KDF params are a shell, like the
//! secret blobs). The payload `{v, vars:{key→{value,type,verified,updated_at,
//! verified_at,origin}}}` is sealed with AES-256-GCM under a dedicated HKDF
//! sub-key (`kvendra/local-vars-key/v1`) and a fixed AAD
//! `"kvendra/local-vars/v1" ‖ 0x01`. The secret blobs use the master key and
//! no AAD, so the two blob kinds are not interchangeable (AC-LVR-5).
//!
//! Every save rotates three local copies `vars.blob.1..3` (not part of the
//! backup bundle). Residual C3 (accepted): a process running as the same uid
//! can roll `vars.blob` back to one of those copies (or to any older blob it
//! kept) — the AEAD authenticates content, not freshness. The broker still
//! refuses unverified values and re-validates every value at use time.
//!
//! Writes go to a `vars.blob.tmp-<pid>` created with mode `0600` from the
//! start (unix `OpenOptions::mode`, no umask window) and renamed into place.

pub mod filter;
pub mod position;
pub mod rate;
pub mod refs;
pub mod resolve;
pub mod validate;

use crate::config::set_file_mode_secure;
use crate::error::{KvendraError, KvendraResult};
use crate::vault::Vault;
use crate::vault::blob::Blob;
use crate::vault::crypto::{NONCE_LEN, open_aad, random_nonce, seal_aad};
use crate::vault::kdf::KdfParams;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// File name of the local-vars blob under the vault home.
pub const VARS_BLOB_FILE: &str = "vars.blob";
/// AAD prefix of the local-vars blob (D1).
pub const VARS_AAD_PREFIX: &[u8] = b"kvendra/local-vars/v1";
/// Format version byte appended to the AAD and stored as `v` in the payload.
pub const VARS_FORMAT_VERSION: u8 = 1;
/// Number of rotated local copies (`vars.blob.1..N`).
pub const VARS_BACKUP_COPIES: usize = 3;

/// The fixed AAD: prefix ‖ version byte.
pub fn aad() -> Vec<u8> {
    let mut a = VARS_AAD_PREFIX.to_vec();
    a.push(VARS_FORMAT_VERSION);
    a
}

/// Declared type of a local variable. Drives value validation ([`validate`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VarType {
    Path,
    Host,
    Port,
    ProfileId,
    String,
}

impl VarType {
    pub const ALL: [VarType; 5] = [
        VarType::Path,
        VarType::Host,
        VarType::Port,
        VarType::ProfileId,
        VarType::String,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            VarType::Path => "path",
            VarType::Host => "host",
            VarType::Port => "port",
            VarType::ProfileId => "profile_id",
            VarType::String => "string",
        }
    }

    pub fn parse(s: &str) -> Option<VarType> {
        VarType::ALL.into_iter().find(|t| t.as_str() == s)
    }
}

/// Who wrote the value last: a human `set`, or a backup restore (which always
/// leaves the variable unverified — AC-LVR-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VarOrigin {
    Set,
    Restore,
}

/// One stored local variable. The value is zeroized on drop and never shown
/// by `Debug`.
#[derive(Clone, Serialize, Deserialize)]
pub struct LocalVar {
    #[serde(serialize_with = "ser_zstr", deserialize_with = "de_zstr")]
    pub value: Zeroizing<String>,
    #[serde(rename = "type")]
    pub var_type: VarType,
    pub verified: bool,
    pub updated_at: String,
    #[serde(default)]
    pub verified_at: Option<String>,
    pub origin: VarOrigin,
}

impl std::fmt::Debug for LocalVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalVar")
            .field("value", &"<redacted>")
            .field("type", &self.var_type)
            .field("verified", &self.verified)
            .field("origin", &self.origin)
            .finish()
    }
}

fn ser_zstr<S: serde::Serializer>(v: &Zeroizing<String>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(v.as_str())
}

fn de_zstr<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}

/// Decrypted payload of `vars.blob`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarsDoc {
    pub v: u8,
    pub vars: BTreeMap<String, LocalVar>,
}

impl Default for VarsDoc {
    fn default() -> Self {
        Self {
            v: VARS_FORMAT_VERSION,
            vars: BTreeMap::new(),
        }
    }
}

/// A local-variable refusal: closed `code`, the variable `key` (may be empty)
/// and a static hint. Never carries the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LvrError {
    pub code: &'static str,
    pub key: String,
}

impl LvrError {
    pub fn new(code: &'static str, key: impl Into<String>) -> Self {
        Self {
            code,
            key: key.into(),
        }
    }

    pub fn hint(&self) -> &'static str {
        hint_for(self.code)
    }
}

impl From<LvrError> for KvendraError {
    fn from(e: LvrError) -> Self {
        KvendraError::LocalVar {
            code: e.code,
            key: e.key,
        }
    }
}

/// Static, value-free hint for every `lvr_*` code (wire `data.hint`).
pub fn hint_for(code: &str) -> &'static str {
    match code {
        "lvr_vault_locked" => {
            "the vault is locked: run `kvendra unlock` in your own terminal; local variables are never resolved without it"
        }
        "lvr_undefined" => {
            "the variable has no value on this machine: the owner runs `kvendra vars set <key> --type <t>` in their terminal"
        }
        "lvr_unverified" => {
            "the variable is not verified on this machine (e.g. restored from a backup): the owner runs `kvendra vars verify <key>` in their terminal"
        }
        "lvr_type_invalid" => {
            "the stored value is not valid for its declared type: the owner re-sets it with `kvendra vars set`"
        }
        "lvr_path_not_canonical" => {
            "the path is not canonical (symlink or `..`): the owner re-sets it with its canonical form"
        }
        "lvr_position_unbounded" => {
            "a local reference is only accepted in a field the signed allowlist bounds (profile_id, cwd with a non-trivial cwd_pattern, an argv slot with a literal or prefix/* template, url, local operands); use ~/ or a workspace-relative path elsewhere"
        }
        "lvr_profile_not_in_vault" => {
            "the profile_id the variable resolves to does not exist in this vault"
        }
        "lvr_rate_limited" => "too many resolutions of this local variable; retry later",
        "lvr_value_in_free_text" => {
            "a free-text field contains the literal value of a local variable: write the reference {{lvr:<key>}}, ~/ or a relative path instead"
        }
        "cfg_ref_not_resolvable_by_broker" => {
            "the broker never resolves {{cfg:…}} references; declare a local variable ({{lvr:key}}) for values the broker consumes"
        }
        _ => "",
    }
}

/// `[a-z0-9][a-z0-9._-]{0,127}` — same key grammar as `{{cfg:…}}`.
pub fn is_valid_key(k: &str) -> bool {
    let b = k.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Read + decrypt a vars blob at `path` with `key`. A missing file is an empty
/// document. An unknown payload version is an error.
pub fn load_with_key(path: &Path, key: &[u8; 32]) -> KvendraResult<VarsDoc> {
    if !path.exists() {
        return Ok(VarsDoc::default());
    }
    let raw = std::fs::read_to_string(path)?;
    let blob = Blob::from_json(&raw)?;
    if blob.nonce.len() != NONCE_LEN {
        return Err(KvendraError::Vault(
            "local vars blob: nonce length invalid".into(),
        ));
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob.nonce);
    let pt = Zeroizing::new(open_aad(key, &nonce, &aad(), &blob.ciphertext)?);
    let doc: VarsDoc = serde_json::from_slice(&pt)
        .map_err(|_| KvendraError::Vault("local vars blob: payload malformed".into()))?;
    if doc.v != VARS_FORMAT_VERSION {
        return Err(KvendraError::Vault(format!(
            "local vars blob: unknown format version {}",
            doc.v
        )));
    }
    Ok(doc)
}

/// Encrypt + atomically write `doc` to `path`, rotating `path.1..3` first.
pub fn save_with_key(path: &Path, key: &[u8; 32], doc: &VarsDoc) -> KvendraResult<()> {
    let pt = Zeroizing::new(serde_json::to_vec(doc)?);
    let nonce = random_nonce();
    let ct = seal_aad(key, &nonce, &aad(), &pt)?;
    let blob = Blob::new(KdfParams::high_cost(vec![]), nonce.to_vec(), ct);
    let json = blob.to_json()?;

    if path.exists() {
        rotate_copies(path)?;
    }
    write_atomic_secure(path, json.as_bytes())
}

/// Write `bytes` to a sibling tmp file created `0600` from the start (unix),
/// then rename it over `path` (N3 — no umask + chmod window).
fn write_atomic_secure(path: &Path, bytes: &[u8]) -> KvendraResult<()> {
    use std::io::Write;
    let tmp = sibling(path, &format!("tmp-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    #[cfg(not(unix))]
    set_file_mode_secure(&tmp)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(suffix);
    path.with_file_name(name)
}

fn rotate_copies(path: &Path) -> KvendraResult<()> {
    for i in (1..VARS_BACKUP_COPIES).rev() {
        let from = sibling(path, &i.to_string());
        if from.exists() {
            std::fs::rename(&from, sibling(path, &(i + 1).to_string()))?;
        }
    }
    let first = sibling(path, "1");
    std::fs::copy(path, &first)?;
    set_file_mode_secure(&first)?;
    Ok(())
}

/// Load the vault's `vars.blob` (requires an unlocked vault).
pub fn load(vault: &Vault) -> KvendraResult<VarsDoc> {
    let key = vault.local_vars_key()?;
    load_with_key(&vault.vars_blob_path(), key.as_bytes())
}

/// Save the vault's `vars.blob` (requires an unlocked vault).
pub fn save(vault: &Vault, doc: &VarsDoc) -> KvendraResult<()> {
    let key = vault.local_vars_key()?;
    save_with_key(&vault.vars_blob_path(), key.as_bytes(), doc)
}

// ---------------------------------------------------------------------------
// Human operations (internal API). The CLI (`cli::vars`) gates every one of
// them behind `ensure_real_terminal` + a password typed on the TTY; they are
// exposed here so the logic is testable without a terminal.
// ---------------------------------------------------------------------------

/// Validate and store `raw` for `key`. Returns the normalized value.
/// `verified` is `true` only when the human confirmed the value on the TTY.
pub fn set_var(
    vault: &Vault,
    key: &str,
    var_type: VarType,
    raw: &str,
    verified: bool,
) -> KvendraResult<Zeroizing<String>> {
    if !is_valid_key(key) {
        return Err(LvrError::new("lvr_key_invalid", "").into());
    }
    let normalized =
        Zeroizing::new(validate::validate(var_type, raw).map_err(|c| LvrError::new(c, key))?);
    let mut doc = load(vault)?;
    let now = now_rfc3339();
    doc.vars.insert(
        key.to_string(),
        LocalVar {
            value: normalized.clone(),
            var_type,
            verified,
            updated_at: now.clone(),
            verified_at: verified.then_some(now),
            origin: VarOrigin::Set,
        },
    );
    save(vault, &doc)?;
    Ok(normalized)
}

/// Remove `key`. `Ok(false)` when it did not exist.
pub fn unset_var(vault: &Vault, key: &str) -> KvendraResult<bool> {
    let mut doc = load(vault)?;
    let existed = doc.vars.remove(key).is_some();
    if existed {
        save(vault, &doc)?;
    }
    Ok(existed)
}

/// Re-validate `key` by its type and mark it verified. The CLI only calls
/// this after the human confirmed the value shown on the TTY.
pub fn mark_verified(vault: &Vault, key: &str) -> KvendraResult<()> {
    let mut doc = load(vault)?;
    let var = doc
        .vars
        .get_mut(key)
        .ok_or_else(|| KvendraError::from(LvrError::new("lvr_undefined", key)))?;
    let normalized =
        validate::validate(var.var_type, &var.value).map_err(|c| LvrError::new(c, key))?;
    var.value = Zeroizing::new(normalized);
    var.verified = true;
    var.verified_at = Some(now_rfc3339());
    save(vault, &doc)
}

/// Backup restore (AC-LVR-6): re-seal the `vars.blob` restored into
/// `staging_home` with every variable `verified:false, origin:restore`. The
/// key is derived from `password` against the STAGING sentinel. No-op when the
/// staging dir has no `vars.blob`. Returns the number of variables reset.
pub fn mark_restored_unverified(staging_home: &Path, password: &[u8]) -> KvendraResult<usize> {
    let staging = Vault::new(staging_home.to_path_buf());
    let path = staging.vars_blob_path();
    if !path.exists() {
        return Ok(0);
    }
    let key = staging.local_vars_key_from_password(password)?;
    let mut doc = load_with_key(&path, key.as_bytes())?;
    let now = now_rfc3339();
    for var in doc.vars.values_mut() {
        var.verified = false;
        var.verified_at = None;
        var.origin = VarOrigin::Restore;
        var.updated_at = now.clone();
    }
    let n = doc.vars.len();
    // No rotated copies in staging: write in place.
    let pt = Zeroizing::new(serde_json::to_vec(&doc)?);
    let nonce = random_nonce();
    let ct = seal_aad(key.as_bytes(), &nonce, &aad(), &pt)?;
    let blob = Blob::new(KdfParams::high_cost(vec![]), nonce.to_vec(), ct);
    write_atomic_secure(&path, blob.to_json()?.as_bytes())?;
    Ok(n)
}

/// Value-free row of `vars list` / `vars status`.
#[derive(Debug, Clone, Serialize)]
pub struct VarSummary {
    pub key: String,
    #[serde(rename = "type")]
    pub var_type: &'static str,
    pub verified: bool,
    pub updated_at: String,
    pub verified_at: Option<String>,
    pub origin: VarOrigin,
}

/// Value-free listing.
pub fn list(doc: &VarsDoc) -> Vec<VarSummary> {
    doc.vars
        .iter()
        .map(|(k, v)| VarSummary {
            key: k.clone(),
            var_type: v.var_type.as_str(),
            verified: v.verified,
            updated_at: v.updated_at.clone(),
            verified_at: v.verified_at.clone(),
            origin: v.origin,
        })
        .collect()
}

/// One declaration read from the KB (`vars status --declared-stdin`).
#[derive(Debug, Clone, Deserialize)]
pub struct Declared {
    pub key: String,
    #[serde(rename = "type")]
    pub var_type: String,
}

/// One row of the `vars status` contract (IF-KVD-CLI-5D9FB5).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusRow {
    pub key: String,
    pub declared_type: String,
    pub present: bool,
    pub stored_type: Option<&'static str>,
    pub verified: bool,
    pub type_ok: bool,
}

/// `vars status` contract output.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusReport {
    pub vars: Vec<StatusRow>,
    pub undeclared_local: Vec<String>,
}

/// Compare the KB declarations with the local store. Value-free: `type_ok`
/// is the declared type matching the stored one AND the stored value still
/// validating for it.
pub fn status(doc: &VarsDoc, declared: &[Declared]) -> StatusReport {
    let mut rows = Vec::new();
    for d in declared {
        let stored = doc.vars.get(&d.key);
        let type_ok = match (stored, VarType::parse(&d.var_type)) {
            (Some(v), Some(t)) => v.var_type == t && validate::validate(t, &v.value).is_ok(),
            _ => false,
        };
        rows.push(StatusRow {
            key: d.key.clone(),
            declared_type: d.var_type.clone(),
            present: stored.is_some(),
            stored_type: stored.map(|v| v.var_type.as_str()),
            verified: stored.is_some_and(|v| v.verified),
            type_ok,
        });
    }
    let undeclared_local = doc
        .vars
        .keys()
        .filter(|k| !declared.iter().any(|d| &d.key == *k))
        .cloned()
        .collect();
    StatusReport {
        vars: rows,
        undeclared_local,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::kdf::KdfParams;

    fn fast_params() -> KdfParams {
        KdfParams {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: vec![3u8; 16],
        }
    }

    fn unlocked_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().canonicalize().unwrap().join("home");
        crate::config::ensure_layout(&home).unwrap();
        let v = Vault::new(home);
        v.create_with_params(b"kvd-vars-unit-pw", fast_params())
            .unwrap();
        v.unlock(b"kvd-vars-unit-pw", 30).unwrap();
        (dir, v)
    }

    #[test]
    fn key_grammar() {
        assert!(is_valid_key("ws"));
        assert!(is_valid_key("kvd.cli.ws-1_a"));
        assert!(!is_valid_key(""));
        assert!(!is_valid_key(".a"));
        assert!(!is_valid_key("A"));
        assert!(!is_valid_key(&"a".repeat(129)));
        assert!(is_valid_key(&"a".repeat(128)));
    }

    #[test]
    fn round_trip_and_rotation() {
        let (_d, v) = unlocked_vault();
        set_var(&v, "s1", VarType::String, "kvd-sentinel-one", true).unwrap();
        set_var(&v, "s2", VarType::String, "kvd-sentinel-two", false).unwrap();
        set_var(&v, "s3", VarType::String, "kvd-sentinel-three", false).unwrap();
        set_var(&v, "s4", VarType::String, "kvd-sentinel-four", false).unwrap();
        let doc = load(&v).unwrap();
        assert_eq!(doc.vars.len(), 4);
        assert_eq!(doc.vars["s1"].value.as_str(), "kvd-sentinel-one");
        assert!(doc.vars["s1"].verified);
        assert!(!doc.vars["s2"].verified);
        let p = v.vars_blob_path();
        for i in 1..=3 {
            assert!(sibling(&p, &i.to_string()).exists(), "copy {i}");
        }
        assert!(!sibling(&p, "4").exists());
        // The blob on disk never contains the plaintext.
        let raw = std::fs::read_to_string(&p).unwrap();
        assert!(!raw.contains("kvd-sentinel"));
    }

    /// N3 — the blob is 0600 (created so via the tmp file, not chmod'ed).
    #[cfg(unix)]
    #[test]
    fn blob_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, v) = unlocked_vault();
        set_var(&v, "s1", VarType::String, "kvd-sentinel-one", true).unwrap();
        let mode = std::fs::metadata(v.vars_blob_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(!sibling(&v.vars_blob_path(), &format!("tmp-{}", std::process::id())).exists());
    }

    #[test]
    fn unknown_version_is_rejected() {
        let (_d, v) = unlocked_vault();
        let key = v.local_vars_key().unwrap();
        let doc = VarsDoc {
            v: 9,
            ..Default::default()
        };
        save_with_key(&v.vars_blob_path(), key.as_bytes(), &doc).unwrap();
        assert!(load(&v).is_err());
    }

    #[test]
    fn status_reports_without_values() {
        let (_d, v) = unlocked_vault();
        set_var(&v, "s1", VarType::String, "kvd-sentinel-one", true).unwrap();
        set_var(&v, "extra", VarType::Port, "8443", false).unwrap();
        let doc = load(&v).unwrap();
        let rep = status(
            &doc,
            &[
                Declared {
                    key: "s1".into(),
                    var_type: "string".into(),
                },
                Declared {
                    key: "missing".into(),
                    var_type: "path".into(),
                },
            ],
        );
        assert_eq!(rep.vars.len(), 2);
        assert!(rep.vars[0].present && rep.vars[0].verified && rep.vars[0].type_ok);
        assert!(!rep.vars[1].present && !rep.vars[1].type_ok);
        assert_eq!(rep.undeclared_local, vec!["extra".to_string()]);
        let s = serde_json::to_string(&rep).unwrap();
        assert!(!s.contains("kvd-sentinel"));
        let l = serde_json::to_string(&list(&doc)).unwrap();
        assert!(!l.contains("kvd-sentinel") && !l.contains("8443"));
    }

    #[test]
    fn debug_never_shows_value() {
        let var = LocalVar {
            value: Zeroizing::new("kvd-sentinel-dbg".into()),
            var_type: VarType::String,
            verified: true,
            updated_at: String::new(),
            verified_at: None,
            origin: VarOrigin::Set,
        };
        assert!(!format!("{var:?}").contains("kvd-sentinel"));
    }
}
