//! `kvendra mcp serve` — start the JSON-RPC MCP server on stdio.

use crate::config::kvendra_home;
use crate::error::KvendraResult;
use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum McpCommand {
    /// Start the MCP server on stdio (JSON-RPC 2.0).
    Serve,
}

pub async fn run(cmd: McpCommand) -> KvendraResult<()> {
    match cmd {
        McpCommand::Serve => {
            let home = kvendra_home()?;
            crate::mcp::server::serve(home).await
        }
    }
}
