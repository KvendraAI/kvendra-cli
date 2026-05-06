//! `kvendra secret <subcommand>` — profile management (Pase B real flows).
//!
//! Supported actions:
//!   - `add <profile_id> [--secret-env VAR | --secret-file PATH]`
//!   - `list`
//!   - `get-meta <profile_id>` (no plaintext)
//!   - `rotate <profile_id> [--secret-env VAR]`
//!   - `revoke <profile_id>`
//!   - `validate <profile_id> | --all`
//!   - `set-allowlist <profile_id> --file PATH`

use crate::allowlist::{ProfileSpec, validate as allowlist_validate};
use crate::config::kvendra_home;
use crate::error::{KvendraError, KvendraResult};
use crate::vault::{Profile, Vault};
use clap::{Args, Subcommand};
use std::path::PathBuf;
use time::OffsetDateTime;

#[derive(Debug, Subcommand)]
pub enum SecretCommand {
    /// Add a new secret profile (encrypts plaintext into the vault).
    Add(AddArgs),
    /// List existing profiles.
    List,
    /// Print metadata for a profile (no plaintext).
    GetMeta { profile_id: String },
    /// Rotate a profile's secret.
    Rotate(RotateArgs),
    /// Revoke a profile (delete blob + metadata + allowlist).
    Revoke { profile_id: String },
    /// Validate the allowlist of a profile (or `--all`).
    Validate(ValidateArgs),
    /// Set the YAML allowlist for a profile.
    SetAllowlist(SetAllowlistArgs),
}

#[derive(Debug, Args)]
pub struct AddArgs {
    pub profile_id: String,
    /// Secret type label (e.g. github_pat, npm_token, ...).
    #[arg(long, default_value = "generic")]
    pub secret_type: String,
    /// Read plaintext from this env var.
    #[arg(long)]
    pub secret_env: Option<String>,
    /// Read plaintext from this file (UTF-8).
    #[arg(long)]
    pub secret_file: Option<PathBuf>,
    /// Allow the unsafe.raw_token escape hatch on this profile.
    #[arg(long)]
    pub unsafe_raw_token_enabled: bool,
    /// Optional ISO-8601 expiration date.
    #[arg(long)]
    pub expiration: Option<String>,
}

#[derive(Debug, Args)]
pub struct RotateArgs {
    pub profile_id: String,
    #[arg(long)]
    pub secret_env: Option<String>,
    #[arg(long)]
    pub secret_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ValidateArgs {
    pub profile_id: Option<String>,
    /// Validate every profile present on disk.
    #[arg(long)]
    pub all: bool,
}

#[derive(Debug, Args)]
pub struct SetAllowlistArgs {
    pub profile_id: String,
    #[arg(long)]
    pub file: PathBuf,
}

pub async fn run(cmd: SecretCommand) -> KvendraResult<()> {
    let home = kvendra_home()?;
    let vault = Vault::new(home);

    match cmd {
        SecretCommand::Add(args) => add(&vault, args).await,
        SecretCommand::List => list(&vault),
        SecretCommand::GetMeta { profile_id } => get_meta(&vault, &profile_id),
        SecretCommand::Rotate(args) => rotate(&vault, args).await,
        SecretCommand::Revoke { profile_id } => revoke(&vault, &profile_id),
        SecretCommand::Validate(args) => validate_cmd(&vault, args),
        SecretCommand::SetAllowlist(args) => set_allowlist(&vault, args),
    }
}

fn read_secret(env: Option<&str>, file: Option<&PathBuf>) -> KvendraResult<Vec<u8>> {
    if let Some(name) = env {
        let v = std::env::var(name)
            .map_err(|_| KvendraError::InvalidArgs(format!("env var '{name}' not set")))?;
        return Ok(v.into_bytes());
    }
    if let Some(path) = file {
        return Ok(std::fs::read(path)?);
    }
    Err(KvendraError::InvalidArgs(
        "must pass --secret-env <VAR> or --secret-file <PATH>".into(),
    ))
}

async fn add(vault: &Vault, args: AddArgs) -> KvendraResult<()> {
    if !vault.is_unlocked() {
        return Err(KvendraError::VaultLocked);
    }
    let plaintext = read_secret(args.secret_env.as_deref(), args.secret_file.as_ref())?;
    vault.put_secret(&args.profile_id, &plaintext)?;

    let meta = Profile {
        profile_id: args.profile_id.clone(),
        secret_type: args.secret_type,
        created_at: OffsetDateTime::now_utc().to_string(),
        expiration: args.expiration,
        unsafe_raw_token_enabled: args.unsafe_raw_token_enabled,
        quarantined: false,
    };
    vault.save_profile_meta(&meta)?;

    println!("Profile '{}' added.", args.profile_id);
    Ok(())
}

fn list(vault: &Vault) -> KvendraResult<()> {
    let profiles = vault.list_profiles()?;
    if profiles.is_empty() {
        println!("(no profiles)");
    } else {
        for p in profiles {
            println!("{p}");
        }
    }
    Ok(())
}

fn get_meta(vault: &Vault, profile_id: &str) -> KvendraResult<()> {
    let meta = vault.load_profile_meta(profile_id)?;
    println!("{}", serde_json::to_string_pretty(&meta)?);
    Ok(())
}

async fn rotate(vault: &Vault, args: RotateArgs) -> KvendraResult<()> {
    if !vault.is_unlocked() {
        return Err(KvendraError::VaultLocked);
    }
    let plaintext = read_secret(args.secret_env.as_deref(), args.secret_file.as_ref())?;
    vault.put_secret(&args.profile_id, &plaintext)?;
    println!("Profile '{}' rotated.", args.profile_id);
    Ok(())
}

fn revoke(vault: &Vault, profile_id: &str) -> KvendraResult<()> {
    vault.delete_profile(profile_id)?;
    println!("Profile '{profile_id}' revoked.");
    Ok(())
}

fn set_allowlist(vault: &Vault, args: SetAllowlistArgs) -> KvendraResult<()> {
    let raw = std::fs::read_to_string(&args.file)?;
    let spec: ProfileSpec = serde_yml::from_str(&raw)?;
    if spec.profile_id != args.profile_id {
        return Err(KvendraError::AllowlistParse(format!(
            "allowlist profile_id '{}' does not match argument '{}'",
            spec.profile_id, args.profile_id
        )));
    }
    allowlist_validate(&spec)?;
    std::fs::create_dir_all(vault.allowlists_dir())?;
    let target = vault.profile_allowlist_path(&args.profile_id);
    std::fs::write(&target, raw)?;
    println!("Allowlist for '{}' set.", args.profile_id);
    Ok(())
}

fn validate_cmd(vault: &Vault, args: ValidateArgs) -> KvendraResult<()> {
    let ids = if args.all {
        vault.list_profiles()?
    } else {
        match args.profile_id {
            Some(s) => vec![s],
            None => {
                return Err(KvendraError::InvalidArgs(
                    "pass <profile_id> or --all".into(),
                ));
            }
        }
    };
    let mut overall_ok = true;
    for id in ids {
        let ok = print_validation(vault, &id);
        if !ok {
            overall_ok = false;
        }
        println!();
    }
    if overall_ok {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

fn print_validation(vault: &Vault, profile_id: &str) -> bool {
    println!("Profile: {profile_id}");
    let meta = match vault.load_profile_meta(profile_id) {
        Ok(m) => m,
        Err(e) => {
            println!("Status: REJECTED");
            println!("Issues:");
            println!("  - {e}");
            return false;
        }
    };

    let allow_path = vault.profile_allowlist_path(profile_id);
    if !allow_path.exists() {
        println!("Status: REJECTED");
        println!("Issues:");
        println!("  - Allowlist YAML missing at {}", allow_path.display());
        println!("  - Use `kvendra secret set-allowlist {profile_id} --file <path>`");
        return false;
    }
    let raw = match std::fs::read_to_string(&allow_path) {
        Ok(s) => s,
        Err(e) => {
            println!("Status: REJECTED");
            println!("Issues:");
            println!("  - Cannot read allowlist: {e}");
            return false;
        }
    };
    let spec: ProfileSpec = match serde_yml::from_str(&raw) {
        Ok(s) => s,
        Err(e) => {
            println!("Status: REJECTED");
            println!("Issues:");
            println!("  - Allowlist YAML parse error: {e}");
            return false;
        }
    };

    let mut issues: Vec<String> = Vec::new();
    if let Err(e) = allowlist_validate(&spec) {
        issues.push(e.to_string());
    }
    if crate::allowlist::validator::is_expired(&spec) {
        issues.push(format!(
            "Expiration: {} — expired",
            spec.expiration.clone().unwrap_or_default()
        ));
    }
    if !["minimal", "standard", "full"].contains(&spec.audit_level.as_str()) {
        issues.push(format!(
            "audit_level '{}' must be one of: minimal, standard, full",
            spec.audit_level
        ));
    }

    if issues.is_empty() {
        println!("Status: VALID");
        println!("Secret type: {}", meta.secret_type);
        println!("Allowlist:");
        for prim in &spec.allowlist.primitives {
            for op in &prim.operations {
                for op_name in op.keys() {
                    println!("  - {}.{op_name}", prim.name);
                }
            }
            if prim.name == "kvendra.unsafe.raw_token" && prim.unsafe_raw_token_allowed {
                println!("  - {} (unsafe escape hatch)", prim.name);
            }
        }
        if let Some(exp) = &spec.expiration {
            println!("Expiration: {exp}");
        } else {
            println!("Expiration: (none — recommend setting one)");
        }
        println!("Audit level: {}", spec.audit_level);
        if meta.unsafe_raw_token_enabled {
            println!("Unsafe escape hatch: ENABLED on profile metadata");
        }
        if meta.quarantined {
            println!("WARNING: profile is QUARANTINED (detection layer Block trigger)");
        }
        true
    } else {
        println!("Status: REJECTED");
        println!("Issues:");
        for i in &issues {
            println!("  - {i}");
        }
        false
    }
}
