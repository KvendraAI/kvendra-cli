//! `kvendra mcp serve` — start the JSON-RPC MCP server on stdio.
//!
//! The MCP server runs in the same process as the unlocked vault session
//! (the Argon2id-derived key is RAM-only per ADR-KVD-012). For non-
//! interactive use, pass `--password-env KVENDRA_MCP_PASSWORD`.

use crate::config::{Config, kvendra_home};
use crate::error::{KvendraError, KvendraResult};
use clap::{Args, Subcommand};

#[derive(Debug, Subcommand)]
pub enum McpCommand {
    /// Start the MCP server on stdio (JSON-RPC 2.0).
    Serve(ServeArgs),
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Read master password from this env var (CI/non-interactive).
    #[arg(long, env = "KVENDRA_MCP_PASSWORD")]
    pub password_env: Option<String>,
    /// Skip the unlock step (audit log will be disabled — V4 relaxed).
    #[arg(long)]
    pub no_unlock: bool,
}

pub async fn run(cmd: McpCommand) -> KvendraResult<()> {
    match cmd {
        McpCommand::Serve(args) => {
            let home = kvendra_home()?;
            crate::config::ensure_layout(&home)?;
            let cfg = Config::load(&home).unwrap_or_default();
            let vault = crate::vault::Vault::new(home.clone());
            if !args.no_unlock && vault.sentinel_path().exists() {
                let password = match args.password_env {
                    Some(s) => s,
                    None => {
                        eprintln!("Enter the master password (will not echo):");
                        rpassword::read_password()
                            .map_err(|e| KvendraError::Vault(format!("read password: {e}")))?
                    }
                };
                vault.unlock(password.as_bytes(), cfg.vault.idle_timeout_minutes)?;
            }
            crate::mcp::server::serve_with_vault(vault).await
        }
    }
}
