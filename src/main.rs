//! Binary entry point for `kvendra`.

use clap::Parser;
use kvendra::cli::{Cli, Commands, SessionCommand};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        // SIGPIPE handler — terminate silently on broken pipe instead of panic.
        // Without this, `kvendra ... | head -1` panics with
        // "failed printing to stdout: Broken pipe (os error 32)" (exit 101).
        // SIG_DFL makes the kernel terminate the process with SIGPIPE (exit 141),
        // matching standard CLI behavior. Fixes ISSUE-KVD-CLI-042.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    }

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
        Commands::Login(args) => kvendra::cli::login::run(args).await?,
        Commands::Logout(args) => kvendra::cli::logout::run(args).await?,
        Commands::Session(cmd) => match cmd {
            SessionCommand::Info(args) => kvendra::cli::session_info::run(args).await?,
        },
        Commands::Workspace(cmd) => kvendra::cli::workspace::run(cmd).await?,
        Commands::Recover(args) => kvendra::cli::recover::run(args).await?,
        Commands::Secret(cmd) => kvendra::cli::secret::run(cmd).await?,
        Commands::Primitive(cmd) => kvendra::cli::primitive::run(cmd).await?,
        Commands::Mcp(cmd) => kvendra::cli::mcp::run(cmd).await?,
        Commands::Audit(args) => kvendra::cli::audit::run(args).await?,
        Commands::Dashboard => kvendra::cli::dashboard::run().await?,
        Commands::Completion(args) => kvendra::cli::completion::run(args)?,
        Commands::Config(cmd) => kvendra::cli::config_cmd::run(cmd).await?,
        Commands::Backup(cmd) => kvendra::cli::backup::run(cmd).await?,
    }
    Ok(())
}
