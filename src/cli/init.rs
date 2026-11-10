//! `kvendra init` — vault bootstrap with full recovery UX (ADR-KVD-011).

use crate::audit::bootstrap::write_vault_created_event;
use crate::config::{Config, create_dir_secure, ensure_layout, kvendra_home};
use crate::error::{KvendraError, KvendraResult};
use crate::fault::maybe_fail;
use crate::vault::Vault;
use crate::vault::envelope::{NewVaultMaterial, create_v2_in_memory};
use crate::vault::fsutil;
use crate::vault::kdf::{KdfParams, random_salt};
use crate::vault::recovery::{RecoveryCodesFile, StoredCode, generate_codes};
use crate::vault::session::{HKDF_INFO_AUDIT_HMAC, hkdf_expand};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use clap::Args;
use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Maximum interactive attempts before `kvendra init` aborts when the
/// password and its confirmation disagree.
const MAX_CONFIRMATION_ATTEMPTS: u8 = 3;

/// Constant-time check that two candidate passwords match. The length check
/// is `==` (and therefore non-CT), but local-process timing is not in our
/// threat model — see ADR-KVD-010.
fn passwords_match(pw1: &str, pw2: &str) -> bool {
    pw1.len() == pw2.len() && bool::from(pw1.as_bytes().ct_eq(pw2.as_bytes()))
}

/// Prompt for the master password twice and confirm via constant-time
/// comparison. Loops up to `max_attempts` before erroring out — protects
/// against silent typos at vault setup, which would otherwise become
/// undetectable until the first `unlock` (AC-VAULT-1, REQ-KVD-002).
pub(crate) fn prompt_password_with_confirmation(
    max_attempts: u8,
) -> KvendraResult<Zeroizing<String>> {
    for attempt in 1..=max_attempts {
        println!("Enter a master password (will not echo):");
        let pw1 = Zeroizing::new(
            rpassword::read_password()
                .map_err(|e| KvendraError::Vault(format!("read password: {e}")))?,
        );
        println!("Confirm master password:");
        let pw2 = Zeroizing::new(
            rpassword::read_password()
                .map_err(|e| KvendraError::Vault(format!("read password confirmation: {e}")))?,
        );
        if passwords_match(&pw1, &pw2) {
            return Ok(pw1);
        }
        if attempt == max_attempts {
            return Err(KvendraError::Vault(format!(
                "master password did not match confirmation after {max_attempts} attempts — init aborted"
            )));
        }
        let remaining = max_attempts - attempt;
        eprintln!("Passwords do not match. Try again ({remaining} attempts remaining).");
    }
    unreachable!("loop returns or errors before exiting")
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Skip the interactive verification step (testing only).
    #[arg(long)]
    pub no_verify: bool,
    /// Read the master password from this env var instead of prompting.
    #[arg(long, env = "KVENDRA_INIT_PASSWORD", hide_env_values = true)]
    pub password_env: Option<String>,
    /// Pre-confirmation code (for non-interactive setups).
    #[arg(long, env = "KVENDRA_INIT_CONFIRM_CODE", hide_env_values = true)]
    pub confirm_code: Option<String>,
    /// Save recovery codes (mnemonic + numeric) to this path (warns about 0600).
    #[arg(long)]
    pub save_to: Option<PathBuf>,
    /// Override kvendra home (testing).
    #[arg(long, env = "KVENDRA_HOME")]
    pub home_override: Option<PathBuf>,
}

/// Text of the refusal when `sentinel.blob` already exists.
pub(crate) const ALREADY_INITIALIZED: &str = "vault already initialized. Forgot the master password? \
     `kvendra recover` (needs your 12-word phrase). To change it knowing the current one: \
     `kvendra passwd`.";

/// Name prefixes of init's writes (rollback sweep and orphan quarantine):
/// recovery material, audit DB and its sqlite/migration side files, config,
/// sentinel tmp.
const INIT_PREFIXES: &[&str] = &[
    "recovery.blob",
    "recovery_codes.json",
    "audit.db",
    "config.toml",
    "sentinel.blob",
];

const SENTINEL_TMP_SUFFIX: &str = "init-tmp";

/// Per-home lock serializing concurrent `kvendra init` runs (finding M2).
pub(crate) const INIT_LOCK_NAME: &str = ".init.lock";

pub async fn run(args: InitArgs) -> KvendraResult<()> {
    let home = args
        .home_override
        .clone()
        .map(Ok)
        .unwrap_or_else(kvendra_home)?;
    ensure_layout(&home)?;

    // Two concurrent inits on the same home would interleave their files:
    // the second one refuses while the first holds the lock (M2).
    let _init_lock = fsutil::try_lock_exclusive(&home.join(INIT_LOCK_NAME))?.ok_or_else(|| {
        KvendraError::Vault(
            "another `kvendra init` is running on this vault home — nothing was changed".into(),
        )
    })?;

    let vault = Vault::new(home.clone());
    if vault.sentinel_path().exists() {
        // An earlier init may have crashed between the publish (hard link)
        // and removing its tmp (B5).
        crate::rekey::cleanup_init_tmp_locked(&home)?;
        return Err(KvendraError::Vault(ALREADY_INITIALIZED.into()));
    }
    if let Some(dir) = quarantine_init_orphans(&home)? {
        eprintln!(
            "warning: found files from an aborted `kvendra init` (no sentinel.blob). \
             They were moved, not deleted, to {}",
            dir.display()
        );
    }

    let password = match args.password_env.clone() {
        Some(s) => Zeroizing::new(s),
        None => prompt_password_with_confirmation(MAX_CONFIRMATION_ATTEMPTS)?,
    };
    if password.len() < 8 {
        return Err(KvendraError::Vault(
            "master password must be ≥ 8 characters".into(),
        ));
    }

    // Everything is built in memory first: nothing touches the vault home
    // until the confirmation step has passed (F2, ISSUE-KVD-CLI-E73A9E).
    let material = create_v2_in_memory(password.as_bytes(), &init_kdf_params())?;
    let codes = generate_codes();
    let mnemonic = &material.mnemonic;

    println!();
    println!("════════════════════════════════════════════════════════════════");
    println!("  Recovery material — SAVE THESE NOW. They will not be shown again.");
    println!("════════════════════════════════════════════════════════════════");
    println!();
    println!("BIP-39 mnemonic (12 words):");
    println!("    {mnemonic}");
    println!();
    println!(
        "What the 12 words do: they recover access to THIS vault on this machine if you \
         forget the master password (`kvendra recover`). Anyone with them can set a new \
         password: keep them offline."
    );
    println!();
    println!("Numeric one-time codes (8 codes):");
    for c in &codes {
        println!("    {c}");
    }
    println!();
    println!(
        "What the 8 codes do: they authorise `kvendra config rebind-home` only. They do NOT \
         recover a forgotten password."
    );
    println!();
    println!("════════════════════════════════════════════════════════════════");
    println!();

    // Optional save-to file (same content as 0.8.0). Created exclusively,
    // O_NOFOLLOW, 0600 from the first byte (finding M1); removed again on
    // ANY later failure, its own write included: its phrase would belong to
    // a vault that does not exist.
    let mut save_to_written: Option<PathBuf> = None;
    let result = async {
        if let Some(path) = &args.save_to {
            write_save_to(path, mnemonic, &codes, &mut save_to_written)?;
            println!("Recovery material written to {} (0600).", path.display());
        }
        confirm_and_commit(&args, &home, &vault, &material, &codes).await
    }
    .await;
    if let Err(e) = result {
        if let Some(p) = save_to_written {
            let _ = std::fs::remove_file(&p);
            eprintln!(
                "init aborted: removed {} (its phrase belongs to a vault that was not created).",
                p.display()
            );
        }
        return Err(e);
    }

    println!("Vault initialized at {}", home.display());
    println!("Recovery phrase bound to this vault (recovery.blob).");
    Ok(())
}

/// Write the `--save-to` file. `written` is set as soon as THIS call created
/// the file, so the caller's rollback removes it even if a later write or
/// fsync fails; a pre-existing path (file or symlink) is refused untouched.
fn write_save_to(
    path: &Path,
    mnemonic: &bip39::Mnemonic,
    codes: &[String],
    written: &mut Option<PathBuf>,
) -> KvendraResult<()> {
    use std::fmt::Write as _;
    use std::io::Write as _;
    let mut content = Zeroizing::new(String::with_capacity(1024));
    content.push_str("# kvendra recovery codes — KEEP THIS FILE OFFLINE\n");
    content.push_str("mnemonic: ");
    write!(content, "{mnemonic}").map_err(|_| KvendraError::Internal)?;
    content.push('\n');
    content.push_str("codes:\n");
    for c in codes {
        content.push_str("  - ");
        content.push_str(c);
        content.push('\n');
    }
    let mut file = fsutil::create_new_secure(path).map_err(|e| match e {
        KvendraError::Io(io)
            if io.kind() == std::io::ErrorKind::AlreadyExists
                || io.raw_os_error() == Some(libc_eloop()) =>
        {
            KvendraError::Vault(format!(
                "refusing to write --save-to: {} already exists (file or symlink) — nothing was \
                 written there",
                path.display()
            ))
        }
        other => other,
    })?;
    *written = Some(path.to_path_buf());
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    maybe_fail("init.after_save_to")?;
    Ok(())
}

#[cfg(unix)]
fn libc_eloop() -> i32 {
    libc::ELOOP
}

#[cfg(not(unix))]
fn libc_eloop() -> i32 {
    -1
}

async fn confirm_and_commit(
    args: &InitArgs,
    home: &Path,
    vault: &Vault,
    material: &NewVaultMaterial,
    codes: &[String],
) -> KvendraResult<()> {
    // Pre-confirmation step (AC-VAULT-3).
    if !args.no_verify {
        let entered = match &args.confirm_code {
            Some(s) => s.clone(),
            None => {
                println!(
                    "To confirm you saved the recovery codes, enter ANY of the 8 numeric codes:"
                );
                let mut buf = String::new();
                std::io::stdin()
                    .read_line(&mut buf)
                    .map_err(|e| KvendraError::Vault(format!("read confirm: {e}")))?;
                buf.trim().to_string()
            }
        };
        if !codes.iter().any(|c| c == &entered) {
            return Err(KvendraError::Vault(
                "confirmation code did not match a generated recovery code — init aborted".into(),
            ));
        }
    }
    commit_new_vault(home, vault, material, codes).await
}

/// Steps 5–7 of the init SPEC: write `recovery_codes.json` →
/// `recovery.blob` → `audit.db` (`vault_created`) → signed `config.toml`,
/// then publish `sentinel.blob` (the commit point) by tmp + fsync + rename +
/// directory fsync. Any failure before the rename removes everything this
/// call wrote, so the home is left without a half-built vault.
pub(crate) async fn commit_new_vault(
    home: &Path,
    vault: &Vault,
    material: &NewVaultMaterial,
    codes: &[String],
) -> KvendraResult<()> {
    let before = top_level_names(home)?;
    let res = write_vault_files(home, vault, material, codes).await;
    vault.lock();
    if let Err(e) = res {
        rollback(home, &before);
        return Err(e);
    }
    Ok(())
}

async fn write_vault_files(
    home: &Path,
    vault: &Vault,
    material: &NewVaultMaterial,
    codes: &[String],
) -> KvendraResult<()> {
    // Precondition (M2): nothing of a vault may exist yet. Under the init
    // lock this always holds; it also protects library callers.
    for p in [
        vault.sentinel_path(),
        vault.recovery_blob_path(),
        vault.recovery_codes_path(),
        vault.audit_db_path(),
        home.join("config.toml"),
    ] {
        if p.exists() {
            return Err(KvendraError::Vault(ALREADY_INITIALIZED.into()));
        }
    }
    maybe_fail("init.before_recovery_codes")?;
    let stored = hash_codes(codes)?;
    fsutil::write_atomic(
        &vault.recovery_codes_path(),
        serde_json::to_string_pretty(&stored)?.as_bytes(),
    )?;
    maybe_fail("init.after_recovery_codes")?;

    maybe_fail("init.before_recovery_blob")?;
    fsutil::write_atomic(
        &vault.recovery_blob_path(),
        material.recovery.to_json()?.as_bytes(),
    )?;
    maybe_fail("init.after_recovery_blob")?;

    // Bootstrap the audit log with a `vault_created` row so forensics can
    // anchor the chain to the moment of initialisation rather than the
    // filesystem mtime of `audit.db` (mutable). ISSUE-KVD-CLI-003.
    maybe_fail("init.before_audit")?;
    let hmac_key = hkdf_expand(material.master_key.as_bytes(), HKDF_INFO_AUDIT_HMAC).to_vec();
    write_vault_created_event(&vault.audit_db_path(), hmac_key, env!("CARGO_PKG_VERSION")).await?;
    maybe_fail("init.after_audit")?;

    // Persist the default config WITH HMAC trailer + home_canonical
    // (REQ-KVD-008 AC-CONFIG-HMAC-1, 3) under the in-memory MK.
    maybe_fail("init.before_config")?;
    vault.unlock_with_master_key(material.master_key.clone(), 30);
    Config::default().save(home, vault)?;
    maybe_fail("init.after_config")?;

    // Commit point: sentinel.blob appears atomically.
    maybe_fail("init.before_sentinel_commit")?;
    let sentinel = vault.sentinel_path();
    let tmp = fsutil::sibling(&sentinel, SENTINEL_TMP_SUFFIX);
    let _ = std::fs::remove_file(&tmp);
    fsutil::write_new_synced(&tmp, material.sentinel.to_json()?.as_bytes())?;
    maybe_fail("init.before_sentinel_rename")?;
    // Never overwrite a sentinel that appeared meanwhile (M2).
    fsutil::publish_no_overwrite(&tmp, &sentinel).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            KvendraError::Vault(ALREADY_INITIALIZED.into())
        } else {
            e.into()
        }
    })?;
    // Past the rename the vault exists: a failure to fsync the directory
    // must not roll it back (that would delete a live vault's files).
    if let Err(e) = fsutil::fsync_dir(home) {
        tracing::warn!(target: "kvendra::init", "directory fsync after commit failed: {e}");
    }
    Ok(())
}

fn hash_codes(codes: &[String]) -> KvendraResult<RecoveryCodesFile> {
    let mut stored = RecoveryCodesFile::default();
    for code in codes {
        // Hash with Argon2id (params here: very fast — these are 10-digit codes,
        // not high-entropy material; we still hash them and salt per-code).
        let salt = crate::vault::kdf::random_salt();
        let params = crate::vault::kdf::KdfParams {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: salt.clone(),
        };
        let h = crate::vault::kdf::derive(code.as_bytes(), &params)?;
        stored.codes.push(StoredCode {
            hash_b64: B64.encode(h.as_bytes()),
            salt_b64: B64.encode(&salt),
            used_at: None,
            used_for: None,
        });
    }
    Ok(stored)
}

/// Production Argon2id cost. With the `test-hooks` feature only,
/// `KVENDRA_TEST_FAST_KDF=1` lowers it so the fault-injection matrix runs in
/// reasonable time; a published build never reads that variable.
fn init_kdf_params() -> KdfParams {
    #[cfg(feature = "test-hooks")]
    if std::env::var("KVENDRA_TEST_FAST_KDF").is_ok_and(|v| v == "1") {
        return KdfParams {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: random_salt(),
        };
    }
    KdfParams::high_cost(random_salt())
}

fn top_level_names(home: &Path) -> KvendraResult<HashSet<OsString>> {
    let mut out = HashSet::new();
    for e in std::fs::read_dir(home)? {
        out.insert(e?.file_name());
    }
    Ok(out)
}

/// Remove every top-level init artifact that did not exist before the
/// commit started (registered writes + sqlite side files + sentinel tmp).
fn rollback(home: &Path, before: &HashSet<OsString>) {
    let Ok(entries) = std::fs::read_dir(home) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        if before.contains(&name) {
            continue;
        }
        let n = name.to_string_lossy();
        // Never the published sentinel itself: if it is not in `before`, a
        // successful commit put it there (rollback only runs on failure
        // before the publish) or another writer did.
        if n == "sentinel.blob" {
            continue;
        }
        if INIT_PREFIXES.iter().any(|p| n.starts_with(p)) && e.path().is_file() {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Fresh `.init-orphans-<unix_ts>[-n]/` (0700) under `home`.
pub(crate) fn new_orphans_dir(home: &Path) -> KvendraResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut dir = home.join(format!(".init-orphans-{ts}"));
    let mut n = 1;
    while dir.exists() {
        dir = home.join(format!(".init-orphans-{ts}-{n}"));
        n += 1;
    }
    create_dir_secure(&dir)?;
    Ok(dir)
}

/// Without `sentinel.blob`, any init artifact is a leftover of an aborted
/// init. Move them (never delete) to `.init-orphans-<unix_ts>/` (0700).
fn quarantine_init_orphans(home: &Path) -> KvendraResult<Option<PathBuf>> {
    let mut found: Vec<PathBuf> = Vec::new();
    for e in std::fs::read_dir(home)? {
        let e = e?;
        let n = e.file_name().to_string_lossy().into_owned();
        if e.path().is_file() && INIT_PREFIXES.iter().any(|p| n.starts_with(p)) {
            found.push(e.path());
        }
    }
    if found.is_empty() {
        return Ok(None);
    }
    let dir = new_orphans_dir(home)?;
    for p in found {
        if let Some(name) = p.file_name() {
            std::fs::rename(&p, dir.join(name))?;
        }
    }
    Ok(Some(dir))
}

#[cfg(test)]
mod tests {
    use super::passwords_match;

    #[test]
    fn passwords_match_returns_true_for_identical_inputs() {
        assert!(passwords_match("hunter2-test", "hunter2-test"));
        assert!(passwords_match("", ""));
    }

    #[test]
    fn passwords_match_returns_false_for_mismatch() {
        assert!(!passwords_match("hunter2-test", "hunter2-tesT"));
        assert!(!passwords_match("hunter2-test", "hunter2-tes"));
        assert!(!passwords_match("a", "ab"));
        assert!(!passwords_match("ab", "a"));
    }

    /// M2 — a second commit on a home that already holds a vault refuses
    /// before writing and leaves the first vault coherent (its phrase still
    /// recovers, the second phrase does not).
    #[tokio::test]
    async fn second_commit_never_overwrites_an_existing_vault() {
        use crate::vault::Vault;
        use crate::vault::envelope::create_v2_in_memory;
        use crate::vault::kdf::KdfParams;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        crate::config::ensure_layout(home).unwrap();
        let fast = || KdfParams {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: vec![2u8; 16],
        };
        let a = create_v2_in_memory(b"kvd-init-a-pass", &fast()).unwrap();
        let b = create_v2_in_memory(b"kvd-init-b-pass", &fast()).unwrap();
        let codes = crate::vault::recovery::generate_codes();
        let v = Vault::new(home.to_path_buf());
        super::commit_new_vault(home, &v, &a, &codes).await.unwrap();
        let before = std::fs::read(v.recovery_blob_path()).unwrap();
        let err = super::commit_new_vault(home, &v, &b, &codes)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already initialized"), "{err}");
        assert_eq!(std::fs::read(v.recovery_blob_path()).unwrap(), before);
        assert!(v.open_recovery(&a.mnemonic).is_ok());
        assert!(v.open_recovery(&b.mnemonic).is_err());
        v.unlock(b"kvd-init-a-pass", 30).unwrap();
    }
}
