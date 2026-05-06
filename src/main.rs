//! Binary entry point for `kvendra`.

use clap::Parser;
use kvendra::cli::{Cli, Commands};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // tracing init: respect RUST_LOG if present, default to info on stderr.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .compact()
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Init(args) => kvendra::cli::init::run(args).await?,
        Commands::Unlock(args) => kvendra::cli::unlock::run(args).await?,
        Commands::Lock => kvendra::cli::lock::run().await?,
        Commands::Recover(args) => kvendra::cli::recover::run(args).await?,
        Commands::Secret(cmd) => kvendra::cli::secret::run(cmd).await?,
        Commands::Primitive(cmd) => kvendra::cli::primitive::run(cmd).await?,
        Commands::Mcp(cmd) => kvendra::cli::mcp::run(cmd).await?,
        Commands::Audit(args) => kvendra::cli::audit::run(args).await?,
        Commands::Dashboard => kvendra::cli::dashboard::run().await?,
        Commands::Completion(args) => kvendra::cli::completion::run(args)?,
        Commands::Config(cmd) => kvendra::cli::config_cmd::run(cmd).await?,
    }
    Ok(())
}
