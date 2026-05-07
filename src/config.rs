//! Configuration loaded from `~/.kvendra/config.toml`.
//!
//! Per ADR-KVD-012, `master_password.cache` defaults to `ram-only` and
//! `idle_timeout_minutes` defaults to 30. Detection severity defaults to
//! `warn` (REQ-KVD-002 AC-DET-2).
//!
//! Per REQ-KVD-008 / ISSUE-019 the document is signed with an HMAC-SHA256
//! computed over the TOML serialization of all preceding fields, persisted
//! as the trailing line `_hmac = "..."`. The HMAC sub-key is HKDF-derived
//! from the unlocked session key (info `kvendra/config-hmac/v1`). Loaders
//! reject the file if (a) the HMAC mismatches, or (b) `[vault] home_canonical`
//! does not match the canonicalized actual `KVENDRA_HOME`. Both checks defend
//! against L1 tampering and the KVENDRA_HOME-redirect attack.

use crate::approval::ApprovalMode;
use crate::error::{KvendraError, KvendraResult};
use crate::vault::Vault;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Floor del timeout configurable de approval (segundos).
pub const APPROVAL_TIMEOUT_FLOOR_SECONDS: u32 = 5;
/// Ceiling del timeout configurable de approval (segundos).
pub const APPROVAL_TIMEOUT_CEILING_SECONDS: u32 = 600;

/// Cache mode for the derived master key (ADR-KVD-012).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MasterPasswordCache {
    #[default]
    RamOnly,
    OsKeychain,
}

/// Detection layer severity (REQ-KVD-002 Bloque 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectionSeverity {
    #[default]
    Warn,
    Error,
    Block,
}

/// Top-level configuration document.
///
/// REQ-KVD-008: the document carries an `_hmac` trailer field that is
/// `skip_serializing` (the trailer is concatenated by [`Config::save`]
/// AFTER computing the HMAC over the rest) but kept in the type so the
/// loader can capture it from `toml::from_str`. Renamed to `_hmac` so it
/// reads naturally as the last line.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub vault: VaultConfig,
    pub detection: DetectionConfig,
    pub approval: ApprovalConfig,
    /// HMAC trailer captured on load. Never serialized — written by
    /// [`Config::save`] after computing the HMAC over the rest of the
    /// document. See module docs.
    #[serde(default, skip_serializing, rename = "_hmac")]
    pub hmac_hex: Option<String>,
}

/// Configuración del approval layer (REQ-KVD-003).
///
/// Default: `ask-destructive`, timeout 30s, cache 5 min (ADR-KVD-013..016).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApprovalConfig {
    pub mode: ApprovalMode,
    pub timeout_seconds: u32,
    pub cache_ttl_seconds: u32,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            mode: ApprovalMode::default(),
            timeout_seconds: 30,
            cache_ttl_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VaultConfig {
    pub master_password_cache: MasterPasswordCache,
    pub idle_timeout_minutes: u32,
    /// Canonical path of `kvendra_home()` at the time the config was last
    /// saved. Verified on load against the canonicalized actual home; a
    /// mismatch is treated as a `home_redirect_detected` attack and the
    /// loader refuses to start (REQ-KVD-008 AC-CONFIG-HMAC-3).
    ///
    /// `None` for legacy configs persisted by the alpha.6 binary; the first
    /// load post-upgrade auto-migrates them via
    /// [`auto_migrate_config_if_needed`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_canonical: Option<String>,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            master_password_cache: MasterPasswordCache::default(),
            idle_timeout_minutes: 30,
            home_canonical: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DetectionConfig {
    pub severity: DetectionSeverity,
}

impl Config {
    /// Load `~/.kvendra/config.toml` or return defaults when absent.
    ///
    /// `vault` is optional: callers that have not yet unlocked the vault
    /// (e.g. very first `kvendra config <subcommand>` against a freshly
    /// upgraded binary) can pass `None` — the HMAC verification step is
    /// then skipped with a soft-error if the file is signed. Callers
    /// SHOULD pass a vault whenever one is available so the verification
    /// runs on every load.
    pub fn load(home: &Path, vault: Option<&Vault>) -> KvendraResult<Self> {
        let path = home.join("config.toml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path)?;

        let (signed_payload, trailer_hmac) = strip_hmac_trailer(&raw);

        if let Some(hmac_hex) = trailer_hmac.as_deref() {
            // Signed document. Require an unlocked vault so we can verify.
            let v = vault.ok_or_else(|| {
                KvendraError::Config(
                    "config.toml is signed but vault is locked — cannot verify".into(),
                )
            })?;
            let key = v.config_hmac_key()?;
            let expected = crate::vault::compute_config_hmac(&key, signed_payload.as_bytes());
            use subtle::ConstantTimeEq;
            if expected.as_bytes().ct_eq(hmac_hex.as_bytes()).unwrap_u8() == 0 {
                tracing::error!(
                    target: "kvendra::config",
                    flag = "config_tampered_detected",
                    "~/.kvendra/config.toml HMAC mismatch — refusing to start"
                );
                return Err(KvendraError::Config(
                    "config_tampered_detected: ~/.kvendra/config.toml HMAC mismatch. \
                     Refusing to start. Re-run a `kvendra config <subcommand>` to re-sign \
                     or restore from backup."
                        .into(),
                ));
            }
        }

        let cfg: Config = toml::from_str(&raw).map_err(|e| KvendraError::Config(e.to_string()))?;
        cfg.validate()?;

        // AC-CONFIG-HMAC-3 — home_canonical comparison.
        if let Some(signed_home) = cfg.vault.home_canonical.as_deref() {
            let actual = std::fs::canonicalize(home).map_err(|e| {
                KvendraError::Config(format!("canonicalize home '{}': {e}", home.display()))
            })?;
            // If the signed_home no longer exists on disk we still report a
            // mismatch (it is the same security failure: the original vault
            // location is gone or moved without a rebind).
            let signed_canon = std::fs::canonicalize(signed_home)
                .unwrap_or_else(|_| std::path::PathBuf::from(signed_home));
            if actual != signed_canon {
                tracing::error!(
                    target: "kvendra::config",
                    flag = "home_redirect_detected",
                    "KVENDRA_HOME differs from the signed home_canonical"
                );
                return Err(KvendraError::Config(format!(
                    "home_redirect_detected: KVENDRA_HOME points to '{}' but vault was \
                     initialized at '{}'. Refusing to start. If you legitimately moved \
                     your vault, run 'kvendra config rebind-home --new-path <new>'.",
                    actual.display(),
                    signed_canon.display()
                )));
            }
        }

        Ok(cfg)
    }

    /// Valida invariantes runtime que no captura `serde` (e.g. floor/ceiling
    /// del timeout de approval).
    pub fn validate(&self) -> KvendraResult<()> {
        let t = self.approval.timeout_seconds;
        if !(APPROVAL_TIMEOUT_FLOOR_SECONDS..=APPROVAL_TIMEOUT_CEILING_SECONDS).contains(&t) {
            return Err(KvendraError::Config(format!(
                "[approval].timeout_seconds={t} out of range [{}..={}]",
                APPROVAL_TIMEOUT_FLOOR_SECONDS, APPROVAL_TIMEOUT_CEILING_SECONDS
            )));
        }
        Ok(())
    }

    /// Persist to `~/.kvendra/config.toml` with HMAC trailer + canonical home.
    ///
    /// Steps (REQ-KVD-008 AC-CONFIG-HMAC-1, 2):
    /// 1. Resolve the canonical path of `home` and stamp it into
    ///    `[vault] home_canonical` of the to-persist clone.
    /// 2. Serialize the rest of the document via `toml::to_string_pretty`
    ///    (the `_hmac` field is `skip_serializing`).
    /// 3. Compute HMAC-SHA256 over the serialized bytes with the
    ///    config-HMAC sub-key.
    /// 4. Concatenate the trailer line `_hmac = "<hex>"\n`.
    /// 5. Atomic write to a `*.tmp` sibling + rename, with 0600 perms on
    ///    both the temp and final files.
    pub fn save(&self, home: &Path, vault: &Vault) -> KvendraResult<()> {
        let mut to_persist = self.clone();
        // If the caller explicitly set `home_canonical` (e.g. `rebind-home`
        // re-pointing the config at the NEW location), respect it; otherwise
        // canonicalize `home` and stamp it as the signed value.
        if to_persist.vault.home_canonical.is_none() {
            let canonical = std::fs::canonicalize(home).map_err(|e| {
                KvendraError::Config(format!("canonicalize {}: {e}", home.display()))
            })?;
            to_persist.vault.home_canonical = Some(canonical.to_string_lossy().into_owned());
        }
        to_persist.hmac_hex = None;

        let raw =
            toml::to_string_pretty(&to_persist).map_err(|e| KvendraError::Config(e.to_string()))?;
        // Ensure the payload ends with exactly one '\n' so the trailer is on
        // its own line for downstream tooling. `to_string_pretty` already
        // emits a trailing newline; defensive normalisation here.
        let raw = if raw.ends_with('\n') {
            raw
        } else {
            format!("{raw}\n")
        };

        let key = vault.config_hmac_key()?;
        let hmac_hex = crate::vault::compute_config_hmac(&key, raw.as_bytes());
        let final_raw = format!("{raw}_hmac = \"{hmac_hex}\"\n");

        let path = home.join("config.toml");
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, &final_raw)?;
        set_file_mode_secure(&tmp)?;
        std::fs::rename(&tmp, &path)?;
        set_file_mode_secure(&path)?;
        Ok(())
    }
}

/// Detect the trailing `_hmac = "<hex>"` line of a signed config and return
/// `(payload_without_trailer, Some(hex))`. If no trailer is found, returns
/// `(raw_clone, None)`.
///
/// The signed payload is byte-exact: the trailer line and exactly one
/// preceding `\n` are removed. This matches what [`Config::save`] writes
/// (`{raw}_hmac = "<hex>"\n` where `raw` already ends in `\n`).
fn strip_hmac_trailer(raw: &str) -> (String, Option<String>) {
    let trimmed_end = raw.trim_end_matches(['\n', '\r']);
    if let Some(line_start) = trimmed_end.rfind('\n') {
        let last_line = &trimmed_end[line_start + 1..];
        if let Some(hex) = parse_hmac_line(last_line) {
            // Remove the last line + its preceding '\n' from the original
            // raw payload. The rest (including any trailing '\n' before
            // the trailer line) is preserved exactly.
            let cut = line_start + 1; // include the '\n' before the trailer
            let payload = &raw[..cut];
            return (payload.to_string(), Some(hex));
        }
    } else if let Some(hex) = parse_hmac_line(trimmed_end) {
        // Single-line file consisting only of the trailer.
        return (String::new(), Some(hex));
    }
    (raw.to_string(), None)
}

fn parse_hmac_line(line: &str) -> Option<String> {
    let line = line.trim_end_matches('\r');
    let rest = line.strip_prefix("_hmac")?.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let rest = rest.strip_suffix('"')?;
    if rest.len() == 64 && rest.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(rest.to_string())
    } else {
        None
    }
}

/// Auto-migrate a legacy `config.toml` (pre-REQ-008) on first load post-upgrade.
///
/// If the file exists but lacks an `_hmac` trailer line, we re-save it via
/// [`Config::save`] which signs it and stamps `home_canonical`. Idempotent
/// (no-op on already-signed files). Emits `tracing::info!` with flag
/// `config_hmac_migrated` so operators can correlate with their upgrade
/// timeline.
pub fn auto_migrate_config_if_needed(home: &Path, vault: &Vault) -> KvendraResult<()> {
    let path = home.join("config.toml");
    if !path.exists() {
        return Ok(());
    }
    let raw = std::fs::read_to_string(&path)?;
    let (_, existing) = strip_hmac_trailer(&raw);
    if existing.is_some() {
        return Ok(());
    }
    let cfg: Config = toml::from_str(&raw).map_err(|e| KvendraError::Config(e.to_string()))?;
    cfg.save(home, vault)?;
    tracing::info!(
        target: "kvendra::config",
        flag = "config_hmac_migrated",
        "Auto-signed legacy config.toml on first load post-REQ-008"
    );
    Ok(())
}

/// Compute the kvendra home directory.
///
/// Honours `$KVENDRA_HOME` for testing/sandboxing, falling back to
/// `~/.kvendra/` (`$HOME/.kvendra/`).
pub fn kvendra_home() -> KvendraResult<PathBuf> {
    if let Some(p) = std::env::var_os("KVENDRA_HOME")
        && !p.is_empty()
    {
        return Ok(PathBuf::from(p));
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| KvendraError::Config("HOME env var not set".into()))?;
    Ok(home.join(".kvendra"))
}

/// Ensure the `~/.kvendra/` layout exists.
pub fn ensure_layout(home: &Path) -> KvendraResult<()> {
    create_dir_secure(home)?;
    create_dir_secure(&home.join("secrets"))?;
    create_dir_secure(&home.join("allowlists"))?;
    create_dir_secure(&home.join("profiles"))?;
    Ok(())
}

/// Create a directory (idempotent) and tighten Unix perms to 0700.
///
/// Convention used by `~/.ssh`, `~/.gnupg`, `~/.password-store`. Other local
/// users cannot enumerate or enter the directory (defence-in-depth on top of
/// the per-file 0600 perms — see THREAT-MODEL V2).
pub fn create_dir_secure(path: &Path) -> KvendraResult<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

/// Set Unix perms of an existing file to 0600 (no-op on non-Unix).
///
/// Apply right after writing any sensitive vault file (sentinel, config,
/// recovery hashes, audit DB, profile blobs / metadata). Defence-in-depth.
pub fn set_file_mode_secure(path: &Path) -> KvendraResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Vault;
    use crate::vault::kdf::KdfParams;
    use tempfile::TempDir;

    fn fast_params() -> KdfParams {
        KdfParams {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: vec![1u8; 16],
        }
    }

    fn unlocked_vault(home: &Path) -> Vault {
        let v = Vault::new(home.to_path_buf());
        v.create_with_params(b"hunter2-test", fast_params())
            .unwrap();
        v.unlock(b"hunter2-test", 30).unwrap();
        v
    }

    /// REQ-KVD-008 AC-CONFIG-HMAC-1 — `Config::save` writes a trailing
    /// `_hmac = "..."` line.
    #[test]
    fn config_save_writes_hmac_trailer_line() {
        let tmp = TempDir::new().unwrap();
        ensure_layout(tmp.path()).unwrap();
        let v = unlocked_vault(tmp.path());
        let cfg = Config::default();
        cfg.save(tmp.path(), &v).unwrap();
        let raw = std::fs::read_to_string(tmp.path().join("config.toml")).unwrap();
        let last_line = raw.lines().last().unwrap();
        assert!(
            last_line.starts_with("_hmac = \""),
            "expected last line to start with `_hmac = \"`, got `{last_line}`"
        );
        assert!(last_line.ends_with('"'));
    }

    /// REQ-KVD-008 AC-CONFIG-HMAC-2 — a tampered HMAC byte fails the load.
    #[test]
    fn config_load_rejects_hmac_mismatch() {
        let tmp = TempDir::new().unwrap();
        ensure_layout(tmp.path()).unwrap();
        let v = unlocked_vault(tmp.path());
        let cfg = Config::default();
        cfg.save(tmp.path(), &v).unwrap();
        let path = tmp.path().join("config.toml");
        let raw = std::fs::read_to_string(&path).unwrap();
        // Replace the trailer with a bogus all-zeros HMAC of the same shape.
        let mut lines: Vec<&str> = raw.lines().collect();
        let last = lines.pop().unwrap();
        assert!(last.starts_with("_hmac = "));
        let bogus = format!("_hmac = \"{}\"", "0".repeat(64));
        lines.push(&bogus);
        let mut tampered = lines.join("\n");
        tampered.push('\n');
        std::fs::write(&path, tampered).unwrap();
        let r = Config::load(tmp.path(), Some(&v));
        assert!(
            matches!(r, Err(KvendraError::Config(ref m)) if m.contains("config_tampered_detected"))
        );
    }

    /// REQ-KVD-008 AC-CONFIG-HMAC-3 — `home_canonical` is persisted as the
    /// canonicalized path on save.
    #[test]
    fn home_canonical_persisted_canonical_on_save() {
        let tmp = TempDir::new().unwrap();
        ensure_layout(tmp.path()).unwrap();
        let v = unlocked_vault(tmp.path());
        let cfg = Config::default();
        cfg.save(tmp.path(), &v).unwrap();
        let reloaded = Config::load(tmp.path(), Some(&v)).unwrap();
        let signed = reloaded.vault.home_canonical.as_deref().unwrap();
        let canonical = std::fs::canonicalize(tmp.path()).unwrap();
        assert_eq!(signed, canonical.to_string_lossy());
    }

    /// REQ-KVD-008 — auto-migration of a pre-REQ-008 config (no `_hmac` line)
    /// is silent on first load.
    #[test]
    fn legacy_config_without_hmac_auto_signs_silent_on_first_load() {
        let tmp = TempDir::new().unwrap();
        ensure_layout(tmp.path()).unwrap();
        // Hand-write a legacy config (no `_hmac`).
        let legacy = "[vault]\n\
                      master_password_cache = \"ram-only\"\n\
                      idle_timeout_minutes = 30\n\
                      \n\
                      [detection]\n\
                      severity = \"warn\"\n\
                      \n\
                      [approval]\n\
                      mode = \"ask-destructive\"\n\
                      timeout_seconds = 30\n\
                      cache_ttl_seconds = 300\n";
        std::fs::write(tmp.path().join("config.toml"), legacy).unwrap();
        let v = unlocked_vault(tmp.path());
        // Auto-migrate — should be silent OK.
        auto_migrate_config_if_needed(tmp.path(), &v).unwrap();
        // Now the file is signed.
        let raw = std::fs::read_to_string(tmp.path().join("config.toml")).unwrap();
        assert!(raw.contains("_hmac = \""));
        // Idempotent: a second migration call is a no-op.
        auto_migrate_config_if_needed(tmp.path(), &v).unwrap();
        // Load now succeeds with the signed config.
        let cfg = Config::load(tmp.path(), Some(&v)).unwrap();
        assert!(cfg.vault.home_canonical.is_some());
    }

    /// REQ-KVD-008 AC-CONFIG-HMAC-3 — copy-attack: an attacker copies the
    /// signed config.toml + sentinel to a new home and points KVENDRA_HOME
    /// there. The signed `home_canonical` no longer matches the actual home
    /// → loader returns `home_redirect_detected`.
    #[test]
    fn config_load_rejects_kvendra_home_redirect_with_copy() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();
        ensure_layout(src.path()).unwrap();
        let v = unlocked_vault(src.path());
        Config::default().save(src.path(), &v).unwrap();
        // Copy the signed config to the new home.
        std::fs::copy(
            src.path().join("config.toml"),
            dst.path().join("config.toml"),
        )
        .unwrap();
        // The dst vault is the SAME (we re-use the vault under the new path
        // by attaching it to dst); but the signed `home_canonical` references
        // src — load against dst rejects.
        let r = Config::load(dst.path(), Some(&v));
        assert!(
            matches!(r, Err(KvendraError::Config(ref m)) if m.contains("home_redirect_detected")),
            "expected home_redirect_detected, got {r:?}"
        );
    }

    /// REQ-KVD-008 AC-CONFIG-HMAC-3 — modified `home_canonical` in a copy of
    /// the config triggers the HMAC mismatch check before the home check
    /// (the attacker cannot rewrite `home_canonical` without invalidating
    /// the trailer).
    #[test]
    fn config_load_rejects_modified_home_canonical_in_copy() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();
        ensure_layout(src.path()).unwrap();
        let v = unlocked_vault(src.path());
        Config::default().save(src.path(), &v).unwrap();
        // Read + modify home_canonical in the copy.
        let raw = std::fs::read_to_string(src.path().join("config.toml")).unwrap();
        let dst_canon = std::fs::canonicalize(dst.path()).unwrap();
        let dst_canon_str = dst_canon.to_string_lossy();
        let modified = raw.replace(
            &*std::fs::canonicalize(src.path()).unwrap().to_string_lossy(),
            &dst_canon_str,
        );
        std::fs::write(dst.path().join("config.toml"), modified).unwrap();
        let r = Config::load(dst.path(), Some(&v));
        // Either trips the HMAC mismatch (preferred) or the home redirect.
        assert!(
            matches!(r, Err(KvendraError::Config(ref m))
                if m.contains("config_tampered_detected")
                    || m.contains("home_redirect_detected")),
            "expected config_tampered_detected or home_redirect_detected, got {r:?}"
        );
    }

    /// REQ-KVD-008 AC-CONFIG-HMAC-3 — attacker-owned vault attempting to
    /// forge a signed config with their own `home_canonical` cannot do so
    /// because the HKDF sub-key differs (different sentinel → different
    /// derived key → different HMAC sub-key).
    #[test]
    fn config_load_rejects_attacker_owned_vault_with_forged_home_canonical() {
        let victim = TempDir::new().unwrap();
        let attacker = TempDir::new().unwrap();
        ensure_layout(victim.path()).unwrap();
        ensure_layout(attacker.path()).unwrap();
        // Victim vault.
        let v_victim = unlocked_vault(victim.path());
        Config::default().save(victim.path(), &v_victim).unwrap();
        // Attacker bootstraps their own vault with a different password +
        // signs a config with `home_canonical` pointing at the victim home.
        let v_atk = Vault::new(attacker.path().to_path_buf());
        v_atk
            .create_with_params(b"attacker-pw", fast_params())
            .unwrap();
        v_atk.unlock(b"attacker-pw", 30).unwrap();
        let mut forged = Config::default();
        forged.vault.home_canonical = Some(
            std::fs::canonicalize(victim.path())
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        );
        forged.save(attacker.path(), &v_atk).unwrap();
        // The attacker now drops their forged config.toml at the victim home.
        std::fs::copy(
            attacker.path().join("config.toml"),
            victim.path().join("config.toml"),
        )
        .unwrap();
        // The victim's vault sub-key cannot verify the attacker's HMAC.
        let r = Config::load(victim.path(), Some(&v_victim));
        assert!(
            matches!(r, Err(KvendraError::Config(ref m)) if m.contains("config_tampered_detected")),
            "expected config_tampered_detected, got {r:?}"
        );
    }

    /// macOS-only: canonicalize across `/Volumes` and `/Users` paths produces
    /// real canonical absolute paths (no `..`, no symlink). REQ-KVD-008 D5=A.
    #[cfg(target_os = "macos")]
    #[test]
    fn canonicalize_macos_volumes_and_users_paths() {
        let tmp = TempDir::new().unwrap();
        let canonical = std::fs::canonicalize(tmp.path()).unwrap();
        let s = canonical.to_string_lossy();
        // On macOS, TempDir lives under /var/folders/... which canonicalizes
        // to /private/var/folders/...; the only invariant we can assert is
        // absolute + symlink-resolved (== TempDir.path() canonicalized).
        assert!(canonical.is_absolute(), "canonical path must be absolute");
        assert!(
            !s.contains("/.."),
            "canonical path must not contain `/..` segments"
        );
    }
}
