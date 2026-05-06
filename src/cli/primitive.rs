//! `kvendra primitive <list|info>` — capability catalog inspection.

use crate::error::KvendraResult;
use crate::primitives::catalog;
use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum PrimitiveCommand {
    /// List all capability primitives.
    List,
    /// Show details for a single primitive.
    Info { name: String },
}

pub async fn run(cmd: PrimitiveCommand) -> KvendraResult<()> {
    match cmd {
        PrimitiveCommand::List => {
            for p in catalog() {
                let unsafe_marker = if p.is_unsafe { " [UNSAFE]" } else { "" };
                println!("{}{unsafe_marker} — {}", p.name, p.summary);
            }
        }
        PrimitiveCommand::Info { name } => match catalog().iter().find(|p| p.name == name) {
            Some(p) => {
                println!("Name: {}", p.name);
                println!("Summary: {}", p.summary);
                println!("Unsafe: {}", p.is_unsafe);
                println!("Operations:");
                for op in p.operations {
                    println!("  - {op}");
                }
            }
            None => {
                println!("primitive '{name}' not found");
            }
        },
    }
    Ok(())
}
