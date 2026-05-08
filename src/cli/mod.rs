//! CLI surface — clap derive enums + dispatch.

pub mod audit;
pub mod completion;
pub mod config_approval;
pub mod config_cmd;
pub mod config_mcp_password;
pub mod config_rebind;
pub mod config_recovery_codes;
pub mod dashboard;
pub mod init;
pub mod lock;
pub mod mcp;
pub mod primitive;
pub mod recover;
pub mod secret;
pub mod unlock;

use clap::{Parser, Subcommand};

/// Kvendra — capability broker via MCP with zero-knowledge local vault.
#[derive(Debug, Parser)]
#[command(
    name = "kvendra",
    version,
    about = "Capability broker via MCP with zero-knowledge local vault",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Bootstrap the vault (interactive setup with master password + recovery).
    Init(init::InitArgs),
    /// Unlock the vault for the current session.
    Unlock(unlock::UnlockArgs),
    /// Lock the vault (zeroize derived key).
    Lock,
    /// Reset the master password using the BIP-39 mnemonic (ADR-KVD-011).
    Recover(recover::RecoverArgs),
    /// Manage stored secret profiles.
    #[command(subcommand)]
    Secret(secret::SecretCommand),
    /// Inspect MCP capability primitives.
    #[command(subcommand)]
    Primitive(primitive::PrimitiveCommand),
    /// MCP server commands (broker entrypoint).
    #[command(subcommand)]
    Mcp(mcp::McpCommand),
    /// Inspect or verify the audit log.
    Audit(audit::AuditArgs),
    /// Live dashboard TUI (vault state + recent audit).
    Dashboard,
    /// Generate shell completion script (AC-CLI-3).
    Completion(completion::CompletionArgs),
    /// Manage CLI configuration (keychain etc.).
    #[command(subcommand)]
    Config(config_cmd::ConfigCommand),
}
