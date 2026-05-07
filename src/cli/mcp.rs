//! `kvendra mcp serve` — start the JSON-RPC MCP server on stdio.
//!
//! The MCP server runs in the same process as the unlocked vault session
//! (the Argon2id-derived key is RAM-only per ADR-KVD-012).
//!
//! Three mutually exclusive ways to provide the master password:
//! - `--use-keychain` (REQ-KVD-005, macOS only) — read from the OS
//!   keychain with biometric/presence ACL. Recommended for IDE/Desktop
//!   MCP clients (Claude Code, Cursor, ...) — the prompt is OS-mediated
//!   and never touches `/dev/tty`, mitigating the TTY hijack documented
//!   in PAT-KVD-007.
//! - `--password-env` (legacy, also reads `KVENDRA_MCP_PASSWORD`) —
//!   plaintext env var. Required workaround on Windows / Linux until
//!   cross-platform ACL ships in a future ROAD.
//! - interactive prompt — falls back to `rpassword` on TTY when neither
//!   of the above is supplied.

use crate::config::{Config, kvendra_home};
use crate::error::{KvendraError, KvendraResult};
use crate::keychain_acl::{self, BiometricError};
use clap::{Args, Subcommand};

const MCP_PASSWORD_LABEL: &str = "kvendra/mcp-password/v1";

#[derive(Debug, Subcommand)]
pub enum McpCommand {
    /// Start the MCP server on stdio (JSON-RPC 2.0).
    Serve(ServeArgs),
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Read master password from this env var (CI/non-interactive, legacy path).
    #[arg(
        long,
        env = "KVENDRA_MCP_PASSWORD",
        conflicts_with_all = ["use_keychain", "no_unlock"]
    )]
    pub password_env: Option<String>,
    /// Read master password from the OS keychain with biometric/presence ACL
    /// (macOS only in this release — see REQ-KVD-005 / PAT-KVD-007).
    #[arg(long, conflicts_with_all = ["password_env", "no_unlock"])]
    pub use_keychain: bool,
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
                let password = resolve_password(&args).await?;
                vault.unlock(password.as_bytes(), cfg.vault.idle_timeout_minutes)?;
            }
            crate::mcp::server::serve_with_vault(vault).await
        }
    }
}

async fn resolve_password(args: &ServeArgs) -> KvendraResult<String> {
    if args.use_keychain {
        return read_keychain_password();
    }
    match &args.password_env {
        Some(s) => Ok(s.clone()),
        None => {
            eprintln!("Enter the master password (will not echo):");
            rpassword::read_password()
                .map_err(|e| KvendraError::Vault(format!("read password: {e}")))
        }
    }
}

fn read_keychain_password() -> KvendraResult<String> {
    match keychain_acl::read_with_user_presence(MCP_PASSWORD_LABEL) {
        Ok(p) => {
            tracing::info!(
                target: "kvendra::mcp",
                flag = "mcp_password_keychain_acl_unlock",
                "MCP password retrieved from keychain via presence ACL"
            );
            Ok(p)
        }
        Err(BiometricError::Rejected) => {
            tracing::warn!(
                target: "kvendra::mcp",
                flag = "mcp_password_keychain_acl_rejected",
                "User rejected biometric/presence prompt"
            );
            Err(KvendraError::BiometricRejected)
        }
        Err(BiometricError::NotFound(label)) => {
            tracing::error!(
                target: "kvendra::mcp",
                flag = "mcp_password_keychain_item_missing",
                %label,
                "No keychain entry — run `kvendra config mcp-password enable` first"
            );
            Err(KvendraError::Vault(format!(
                "keychain item '{label}' not found — run `kvendra config mcp-password enable`"
            )))
        }
        Err(BiometricError::Unavailable(msg)) => {
            tracing::error!(
                target: "kvendra::mcp",
                flag = "mcp_password_keychain_unavailable",
                "{msg}"
            );
            Err(KvendraError::BiometricUnavailable(msg))
        }
        Err(BiometricError::Backend(msg)) => {
            tracing::error!(
                target: "kvendra::mcp",
                flag = "mcp_password_keychain_unavailable",
                "{msg}"
            );
            Err(KvendraError::Keychain(msg))
        }
    }
}
