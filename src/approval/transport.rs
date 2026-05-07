//! Transport variant for the approval flow (REQ-KVD-006 / ISSUE-KVD-CLI-020).
//!
//! `Transport::Cli` → CLI commands (`kvendra <subcommand>`). Approval prompts
//! via `/dev/tty` (the user is at the shell, that's where they expect prompts).
//! `Transport::Mcp` → MCP server stdio (`kvendra mcp serve`). Approval prompts
//! via OS-mediated biometric/popup (macOS) — never `/dev/tty`. Mitigates the
//! TTY hijack pattern documented in PAT-KVD-007.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Transport {
    #[default]
    Cli,
    Mcp,
}

impl Transport {
    pub fn is_mcp(self) -> bool {
        matches!(self, Transport::Mcp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_mcp_matches() {
        assert!(Transport::Mcp.is_mcp());
        assert!(!Transport::Cli.is_mcp());
    }

    #[test]
    fn default_is_cli() {
        assert_eq!(Transport::default(), Transport::Cli);
    }
}
