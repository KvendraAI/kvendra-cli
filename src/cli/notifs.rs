//! `kvendra notifs settings {get|put}` — REQ-KVD-CLI-006.
//!
//! Thin wrapper around `GET/PUT /v1/users/me/notifications` per
//! IF-KVD-ENTERPRISE-002 v1.3.0. Requires either a workspace session OR a
//! `--pro` JWT at `~/.kvendra/sessions/pro.token`.

use crate::config::kvendra_home;
use crate::error::{KvendraError, KvendraResult};
use crate::session::{SessionState, list_active_sessions};
use clap::{Args, Subcommand};
use std::path::Path;
use std::time::Duration;

const DEFAULT_API_BASE: &str = "https://api.kvendra.cloud";

#[derive(Debug, Subcommand)]
pub enum NotifsCommand {
    /// User-personal notification preferences (channels + thresholds).
    #[command(subcommand)]
    Settings(SettingsCommand),
}

#[derive(Debug, Subcommand)]
pub enum SettingsCommand {
    /// Print the current settings as JSON.
    Get,
    /// Update the settings from JSON read on stdin or via `--json`.
    Put(PutArgs),
}

#[derive(Debug, Args)]
pub struct PutArgs {
    /// JSON body. If omitted, the body is read from stdin.
    #[arg(long)]
    pub json: Option<String>,
}

pub async fn run(cmd: NotifsCommand) -> KvendraResult<()> {
    match cmd {
        NotifsCommand::Settings(SettingsCommand::Get) => settings_get().await,
        NotifsCommand::Settings(SettingsCommand::Put(args)) => settings_put(args).await,
    }
}

async fn settings_get() -> KvendraResult<()> {
    let jwt = load_any_jwt()?;
    let client = http_client()?;
    let url = format!("{}/v1/users/me/notifications", api_base());
    let resp = client
        .get(&url)
        .bearer_auth(jwt)
        .send()
        .await
        .map_err(remap_err)?;
    let status = resp.status();
    let body = resp.text().await.map_err(remap_err)?;
    if !status.is_success() {
        return Err(KvendraError::Http(format!(
            "GET notifs HTTP {status}: {body}"
        )));
    }
    println!("{body}");
    Ok(())
}

async fn settings_put(args: PutArgs) -> KvendraResult<()> {
    let jwt = load_any_jwt()?;
    let body = match args.json {
        Some(s) => s,
        None => {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| KvendraError::InvalidArgs(format!("read stdin: {e}")))?;
            buf
        }
    };
    // Validate that the body is well-formed JSON before sending.
    let _: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| KvendraError::InvalidArgs(format!("invalid JSON body: {e}")))?;

    let client = http_client()?;
    let url = format!("{}/v1/users/me/notifications", api_base());
    let resp = client
        .put(&url)
        .bearer_auth(jwt)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(remap_err)?;
    let status = resp.status();
    let resp_body = resp.text().await.map_err(remap_err)?;
    if !status.is_success() {
        return Err(KvendraError::Http(format!(
            "PUT notifs HTTP {status}: {resp_body}"
        )));
    }
    println!("{resp_body}");
    Ok(())
}

fn api_base() -> String {
    std::env::var("KVENDRA_API_BASE").unwrap_or_else(|_| DEFAULT_API_BASE.to_string())
}

fn http_client() -> KvendraResult<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .user_agent(concat!("kvendra-cli/", env!("CARGO_PKG_VERSION"), " (rust)"))
        .build()
        .map_err(|e| KvendraError::Http(format!("http client: {e}")))
}

fn remap_err(e: reqwest::Error) -> KvendraError {
    if e.is_connect() || e.is_timeout() {
        KvendraError::BrokerUnreachable(format!("notifs: {e}"))
    } else {
        KvendraError::Http(format!("notifs: {e}"))
    }
}

/// Try a workspace session first; if none, fall back to `pro.token`.
pub fn load_any_jwt() -> KvendraResult<String> {
    let home = kvendra_home()?;
    if let Some(jwt) = load_first_workspace_jwt(&home)? {
        return Ok(jwt);
    }
    load_pro_jwt(&home)
}

fn load_first_workspace_jwt(home: &Path) -> KvendraResult<Option<String>> {
    let active = list_active_sessions(home)?;
    // Prefer a non-"pro" id (the pro token is also list-detectable but lives
    // outside the SessionState schema).
    let chosen = active.into_iter().find(|w| w != "pro");
    let Some(ws_id) = chosen else { return Ok(None) };
    let Some(state) = SessionState::load(home, &ws_id)? else { return Ok(None) };
    Ok(Some(state.jwt))
}

fn load_pro_jwt(home: &Path) -> KvendraResult<String> {
    let token_path = home.join("sessions").join("pro.token");
    if !token_path.exists() {
        return Err(KvendraError::Vault(
            "NotAuthenticated: run `kvendra login --pro` or `kvendra login --workspace <id>` first"
                .into(),
        ));
    }
    let raw = std::fs::read_to_string(&token_path)?;
    Ok(raw.trim().to_string())
}
