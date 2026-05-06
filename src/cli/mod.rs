//! CLI surface — clap derive enums + dispatch.

pub mod audit;
pub mod init;
pub mod lock;
pub mod mcp;
pub mod primitive;
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
}
