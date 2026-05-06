//! `kvendra secret <subcommand>` — Pase A scaffold.

use crate::config::kvendra_home;
use crate::error::KvendraResult;
use crate::vault::Vault;
use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum SecretCommand {
    /// Add a new secret profile.
    Add { profile_id: String },
    /// List existing profiles.
    List,
    /// Print metadata for a profile (no plaintext).
    GetMeta { profile_id: String },
    /// Rotate a profile's secret.
    Rotate { profile_id: String },
    /// Revoke a profile (delete blob + allowlist).
    Revoke { profile_id: String },
    /// Validate the allowlist of a profile.
    Validate { profile_id: String },
}

pub async fn run(cmd: SecretCommand) -> KvendraResult<()> {
    let home = kvendra_home()?;
    let vault = Vault::new(home);

    match cmd {
        SecretCommand::List => {
            let profiles = vault.list_profiles()?;
            if profiles.is_empty() {
                println!("(no profiles)");
            } else {
                for p in profiles {
                    println!("{p}");
                }
            }
        }
        SecretCommand::Add { profile_id } => {
            println!("kvendra secret add '{profile_id}' — Pase A scaffold");
        }
        SecretCommand::GetMeta { profile_id } => {
            println!("kvendra secret get-meta '{profile_id}' — Pase A scaffold");
        }
        SecretCommand::Rotate { profile_id } => {
            println!("kvendra secret rotate '{profile_id}' — Pase A scaffold");
        }
        SecretCommand::Revoke { profile_id } => {
            println!("kvendra secret revoke '{profile_id}' — Pase A scaffold");
        }
        SecretCommand::Validate { profile_id } => {
            println!("kvendra secret validate '{profile_id}' — Pase A scaffold");
        }
    }
    Ok(())
}
