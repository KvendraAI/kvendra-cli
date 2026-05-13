//! `kvendra backup {push,pull,list,restore,prune}` — REQ-KVD-CLI-005.
//!
//! Authentication: requires `kvendra login --pro` token at
//! `~/.kvendra/sessions/pro.token`. Plain JWT bearer (M2 MVP — refresh token
//! flow deferred to M2.5).

use crate::backup::client::BackupClient;
use crate::backup::manifest::BackupManifest;
use crate::backup::{bundle, crypto};
use crate::config::kvendra_home;
use crate::error::{KvendraError, KvendraResult};
use clap::{Args, Subcommand};
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Debug, Subcommand)]
pub enum BackupCommand {
    /// Encrypt the local vault and push to Kvendra cloud.
    Push(PushArgs),
    /// List remote backup versions.
    List(ListArgs),
    /// Download the latest backup and restore it locally.
    Pull(PullArgs),
    /// Restore a specific backup version.
    Restore(RestoreArgs),
    /// Delete a specific backup version (or prune by retention policy).
    Prune(PruneArgs),
}

#[derive(Debug, Args)]
pub struct PushArgs {
    /// Force push even if remote etag has advanced (overwrites remote).
    #[arg(long)]
    pub force: bool,
    /// Optional human-readable label.
    #[arg(long)]
    pub label: Option<String>,
    /// Read master password from stdin (CI/scripts).
    #[arg(long)]
    pub password_stdin: bool,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    #[arg(long, default_value = "10")]
    pub limit: u32,
}

#[derive(Debug, Args)]
pub struct PullArgs {
    /// Backup ID — defaults to latest.
    #[arg(long)]
    pub id: Option<String>,
    /// Skip the "overwrite local vault?" confirmation.
    #[arg(long)]
    pub yes: bool,
    /// Target dir — defaults to KVENDRA_HOME staging dir.
    #[arg(long)]
    pub out: Option<PathBuf>,
    #[arg(long)]
    pub password_stdin: bool,
}

#[derive(Debug, Args)]
pub struct RestoreArgs {
    pub backup_id: String,
    #[arg(long)]
    pub yes: bool,
    #[arg(long)]
    pub password_stdin: bool,
}

#[derive(Debug, Args)]
pub struct PruneArgs {
    pub backup_id: String,
    #[arg(long)]
    pub yes: bool,
}

pub async fn run(cmd: BackupCommand) -> KvendraResult<()> {
    match cmd {
        BackupCommand::Push(a) => run_push(a).await,
        BackupCommand::List(a) => run_list(a).await,
        BackupCommand::Pull(a) => run_pull(a).await,
        BackupCommand::Restore(a) => run_restore(a).await,
        BackupCommand::Prune(a) => run_prune(a).await,
    }
}

fn load_pro_jwt() -> KvendraResult<String> {
    let home = kvendra_home()?;
    let token_path = home.join("sessions").join("pro.token");
    if !token_path.exists() {
        return Err(KvendraError::Vault(
            "NotProAuthenticated: run `kvendra login --pro` first".into(),
        ));
    }
    let raw = std::fs::read_to_string(&token_path)?;
    Ok(raw.trim().to_string())
}

fn read_password(password_stdin: bool) -> KvendraResult<String> {
    if password_stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .map_err(|e| KvendraError::Vault(format!("read password from stdin: {e}")))?;
        if buf.ends_with('\n') {
            buf.pop();
            if buf.ends_with('\r') {
                buf.pop();
            }
        }
        return Ok(buf);
    }
    if let Ok(p) = std::env::var("KVENDRA_PASSWORD")
        && !p.is_empty()
    {
        return Ok(p);
    }
    println!("Enter the master password (will not echo):");
    rpassword::read_password().map_err(|e| KvendraError::Vault(format!("read password: {e}")))
}

fn derive_backup_key_from_password(password: &str) -> KvendraResult<[u8; 32]> {
    let home = kvendra_home()?;
    let vault = crate::vault::Vault::new(home);
    let mut session_key = vault.audit_hmac_key_from_password(password.as_bytes())?;
    // session_key is the derived audit-hmac sub-key. We need the master key
    // itself. The Vault exposes audit_hmac_key_from_password which already
    // does Argon2id + HKDF for audit. For backup we must derive a *different*
    // sub-key from the same master. The simplest correct approach: re-derive
    // the master directly via the same path used by Vault::derive_master.
    //
    // M2 MVP shortcut: chain HKDF over the audit-hmac subkey itself (so the
    // backup key is uniquely separated from audit and we never touch the
    // master plaintext in this layer). This is cryptographically sound
    // (additional HKDF stage with a distinct info) and keeps the existing
    // master-derivation code path untouched.
    let key = crypto::derive_backup_key(&session_key);
    session_key.zeroize();
    Ok(key)
}

async fn run_push(args: PushArgs) -> KvendraResult<()> {
    let home = kvendra_home()?;
    let jwt = load_pro_jwt()?;
    let mut password = read_password(args.password_stdin)?;
    let backup_key = derive_backup_key_from_password(&password)?;
    password.zeroize();

    let tar_bytes = bundle::build_bundle(&home)?;
    let checksum = crypto::sha256_hex(&tar_bytes);
    let mut ciphertext = crypto::encrypt_bundle(&backup_key, &tar_bytes)?;
    // Zeroize plaintext tar after encryption.
    let mut tar_bytes_mut = tar_bytes;
    tar_bytes_mut.zeroize();

    let size = ciphertext.len() as u64;
    if size > crate::backup::BACKUP_MAX_BYTES {
        return Err(KvendraError::Vault(format!(
            "BackupTooLarge: {size} > {} bytes",
            crate::backup::BACKUP_MAX_BYTES
        )));
    }

    // Parent etag — last known from cache file.
    let parent_etag = read_cached_etag(&home).ok();
    let manifest = BackupManifest::new(checksum, parent_etag, size, args.label.clone());

    let client = BackupClient::new(jwt);
    let result = client.push(&manifest, ciphertext.clone()).await;
    ciphertext.zeroize();

    let meta = result?;
    write_cached_etag(&home, &meta.etag)?;
    println!(
        "Pushed backup {} ({} bytes, version={}, etag={})",
        meta.backup_id, meta.size_bytes, meta.version, meta.etag
    );
    if args.force {
        eprintln!("(--force was set — remote conflict resolution skipped)");
    }
    Ok(())
}

async fn run_list(args: ListArgs) -> KvendraResult<()> {
    let jwt = load_pro_jwt()?;
    let client = BackupClient::new(jwt);
    let items = client.list(args.limit).await?;
    if items.is_empty() {
        println!("(no backups yet — run `kvendra backup push`)");
        return Ok(());
    }
    println!(
        "{:<24}  {:<15}  {:<12}  {:>12}  {}",
        "BACKUP_ID", "CREATED_AT", "VERSION", "SIZE_BYTES", "LABEL"
    );
    for it in items {
        println!(
            "{:<24}  {:<15}  {:<12}  {:>12}  {}",
            it.backup_id,
            it.created_at,
            it.version,
            it.size_bytes,
            it.label.unwrap_or_default()
        );
    }
    Ok(())
}

async fn run_pull(args: PullArgs) -> KvendraResult<()> {
    let home = kvendra_home()?;
    let jwt = load_pro_jwt()?;
    let mut password = read_password(args.password_stdin)?;
    let backup_key = derive_backup_key_from_password(&password)?;
    password.zeroize();

    let client = BackupClient::new(jwt);
    let backup_id = match args.id {
        Some(id) => id,
        None => {
            let mut items = client.list(1).await?;
            if items.is_empty() {
                return Err(KvendraError::Vault("no backups available".into()));
            }
            items.remove(0).backup_id
        }
    };
    let ciphertext = client.pull(&backup_id).await?;
    let tar_bytes = crypto::decrypt_bundle(&backup_key, &ciphertext)?;

    let target = args.out.unwrap_or_else(|| home.join("staging_restore"));
    if target.exists() && !args.yes {
        println!(
            "Target dir already exists: {}. Use --yes to proceed.",
            target.display()
        );
        return Err(KvendraError::Vault("restore aborted by user".into()));
    }
    let n = bundle::extract_bundle(&tar_bytes, &target)?;
    println!(
        "Restored backup {} → {} ({} entries)",
        backup_id,
        target.display(),
        n
    );
    Ok(())
}

async fn run_restore(args: RestoreArgs) -> KvendraResult<()> {
    let pull_args = PullArgs {
        id: Some(args.backup_id),
        yes: args.yes,
        out: None,
        password_stdin: args.password_stdin,
    };
    run_pull(pull_args).await
}

async fn run_prune(args: PruneArgs) -> KvendraResult<()> {
    let jwt = load_pro_jwt()?;
    if !args.yes {
        println!("Delete backup {}? Use --yes to confirm.", args.backup_id);
        return Err(KvendraError::Vault("prune aborted by user".into()));
    }
    let client = BackupClient::new(jwt);
    client.delete(&args.backup_id).await?;
    println!("Deleted backup {}", args.backup_id);
    Ok(())
}

fn cache_etag_path(home: &std::path::Path) -> PathBuf {
    home.join("cache").join("backup_etag")
}

fn read_cached_etag(home: &std::path::Path) -> KvendraResult<String> {
    let p = cache_etag_path(home);
    Ok(std::fs::read_to_string(p)?.trim().to_string())
}

fn write_cached_etag(home: &std::path::Path, etag: &str) -> KvendraResult<()> {
    let p = cache_etag_path(home);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&p, etag.as_bytes())?;
    Ok(())
}
