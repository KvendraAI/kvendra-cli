//! `kvendra completion <shell>` — generate shell completion script (AC-CLI-3).

use crate::error::KvendraResult;
use clap::{Args, CommandFactory, ValueEnum};
use clap_complete::{Generator, Shell, generate};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
    Elvish,
}

impl CompletionShell {
    fn to_clap(self) -> Shell {
        match self {
            CompletionShell::Bash => Shell::Bash,
            CompletionShell::Zsh => Shell::Zsh,
            CompletionShell::Fish => Shell::Fish,
            CompletionShell::Powershell => Shell::PowerShell,
            CompletionShell::Elvish => Shell::Elvish,
        }
    }
}

#[derive(Debug, Args)]
pub struct CompletionArgs {
    /// Target shell.
    pub shell: CompletionShell,
}

pub fn run(args: CompletionArgs) -> KvendraResult<()> {
    let mut cmd = super::Cli::command();
    let name = cmd.get_name().to_string();
    let shell = args.shell.to_clap();
    let mut stdout = std::io::stdout();
    let _: Box<dyn Generator> = Box::new(shell);
    generate(shell, &mut cmd, name, &mut stdout);
    Ok(())
}
