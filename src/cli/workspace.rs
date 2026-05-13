//! `kvendra workspace <subcommand>` — admin/member operations against the
//! broker (REQ-KVD-CLI-004 AC-RESOLVER-7, REQ-KVD-CLI-009).

use crate::config::kvendra_home;
use crate::error::{KvendraError, KvendraResult};
use crate::protocol::v1::CreateProfileRequest;
use crate::session::{SessionState, list_active_sessions};
use crate::workspace::WorkspaceClient;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum WorkspaceCommand {
    /// Add a new workspace secret (owner/admin only — server-side RBAC).
    AddSecret(AddSecretArgs),
    /// Allowlist subcommands.
    #[command(subcommand)]
    Allowlist(AllowlistCommand),
    /// Members subcommands.
    #[command(subcommand)]
    Members(MembersCommand),
    /// Profiles subcommands.
    #[command(subcommand)]
    Profiles(ProfilesCommand),
}

#[derive(Debug, Args)]
pub struct AddSecretArgs {
    pub profile_id: String,
    #[arg(long)]
    pub secret_type: String,
    #[arg(long)]
    pub template_id: String,
    /// Read plaintext from env var.
    #[arg(long)]
    pub secret_env: Option<String>,
    /// Read plaintext from file (UTF-8).
    #[arg(long)]
    pub secret_file: Option<PathBuf>,
    /// Optional RFC3339 expiration timestamp.
    #[arg(long)]
    pub expiration_at: Option<String>,
    /// Override the active workspace (defaults to the only session present).
    #[arg(long)]
    pub workspace: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum AllowlistCommand {
    /// Force a full re-sync of allowlists from the broker.
    Refresh(AllowlistRefreshArgs),
}

#[derive(Debug, Args)]
pub struct AllowlistRefreshArgs {
    #[arg(long)]
    pub workspace: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum MembersCommand {
    /// List members of the workspace.
    List(WorkspaceQueryArgs),
}

#[derive(Debug, Subcommand)]
pub enum ProfilesCommand {
    /// List profiles registered in the workspace.
    List(WorkspaceQueryArgs),
}

#[derive(Debug, Args)]
pub struct WorkspaceQueryArgs {
    #[arg(long)]
    pub workspace: Option<String>,
}

pub async fn run(cmd: WorkspaceCommand) -> KvendraResult<()> {
    match cmd {
        WorkspaceCommand::AddSecret(args) => add_secret(args).await,
        WorkspaceCommand::Allowlist(AllowlistCommand::Refresh(args)) => refresh_allowlists(args).await,
        WorkspaceCommand::Members(MembersCommand::List(args)) => list_members(args).await,
        WorkspaceCommand::Profiles(ProfilesCommand::List(args)) => list_profiles(args).await,
    }
}

fn resolve_workspace_id(override_ws: Option<String>) -> KvendraResult<(String, SessionState)> {
    let home = kvendra_home()?;
    let ws_id = match override_ws {
        Some(id) => id,
        None => {
            let active = list_active_sessions(&home)?;
            match active.len() {
                0 => {
                    return Err(KvendraError::SessionStore(
                        "no workspace session active — run `kvendra login --workspace <id>` first"
                            .into(),
                    ));
                }
                1 => active[0].clone(),
                _ => std::env::var("KVENDRA_ACTIVE_WORKSPACE")
                    .map_err(|_| KvendraError::MultipleWorkspaceSessionsAmbiguous)?,
            }
        }
    };
    let state = SessionState::load(&home, &ws_id)?
        .ok_or_else(|| KvendraError::SessionStore(format!("no session for '{ws_id}'")))?;
    Ok((ws_id, state))
}

async fn add_secret(args: AddSecretArgs) -> KvendraResult<()> {
    let (ws_id, state) = resolve_workspace_id(args.workspace.clone())?;
    let plaintext = read_plaintext(&args)?;
    let plaintext_b64 = B64.encode(plaintext.as_bytes());
    let client = WorkspaceClient::new(state.jwt.clone())?;
    let req = CreateProfileRequest {
        profile_id: args.profile_id.clone(),
        secret_type: args.secret_type,
        template_id: args.template_id,
        plaintext_b64,
        expiration_at: args.expiration_at,
    };
    let created = client.create_profile(&ws_id, &req).await?;
    println!(
        "Workspace profile '{}' created (template={}, secret_type={}, created_by={}).",
        created.profile_id, created.template_id, created.secret_type, created.created_by
    );
    Ok(())
}

fn read_plaintext(args: &AddSecretArgs) -> KvendraResult<String> {
    if let Some(env_name) = &args.secret_env {
        return std::env::var(env_name)
            .map_err(|_| KvendraError::InvalidArgs(format!("env var '{env_name}' not set")));
    }
    if let Some(path) = &args.secret_file {
        return std::fs::read_to_string(path)
            .map_err(|e| KvendraError::InvalidArgs(format!("read --secret-file: {e}")));
    }
    Err(KvendraError::InvalidArgs(
        "exactly one of --secret-env or --secret-file is required".into(),
    ))
}

async fn refresh_allowlists(args: AllowlistRefreshArgs) -> KvendraResult<()> {
    let (ws_id, state) = resolve_workspace_id(args.workspace)?;
    let home = kvendra_home()?;
    let report =
        crate::workspace::allowlist_sync::sync_once(&home, &ws_id, &state.jwt, true).await?;
    println!(
        "Allowlist sync: {} fetched, {} unchanged, {} failed.",
        report.fetched, report.not_modified, report.failed
    );
    Ok(())
}

async fn list_members(args: WorkspaceQueryArgs) -> KvendraResult<()> {
    let (ws_id, state) = resolve_workspace_id(args.workspace)?;
    let client = WorkspaceClient::new(state.jwt.clone())?;
    let list = client.list_members(&ws_id).await?;
    for m in list.items {
        let suffix = if m.revoked_at.is_some() {
            " [revoked]"
        } else {
            ""
        };
        println!("{}\t{}\t{}{}", m.member_id, m.email, m.role, suffix);
    }
    Ok(())
}

async fn list_profiles(args: WorkspaceQueryArgs) -> KvendraResult<()> {
    let (ws_id, state) = resolve_workspace_id(args.workspace)?;
    let client = WorkspaceClient::new(state.jwt.clone())?;
    let list = client.list_profiles(&ws_id).await?;
    for p in list.items {
        let exp = p.expiration_at.unwrap_or_else(|| "never".into());
        println!(
            "{}\t{}\ttemplate={}\texpires={}\tcreated_by={}",
            p.profile_id, p.secret_type, p.template_id, exp, p.created_by
        );
    }
    Ok(())
}
