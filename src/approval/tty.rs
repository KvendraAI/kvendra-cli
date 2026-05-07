//! TTY backend del approval prompt (ADR-KVD-013).
//!
//! Imprime un ASCII box directamente a `/dev/tty` (Unix) o `CONOUT$` (Windows)
//! para evitar contaminar el stdio JSON-RPC del MCP server. Lee del `/dev/tty`
//! / `CONIN$` con `tokio::time::timeout` envolviendo `spawn_blocking`.

use crate::approval::{ApprovalBackend, ApprovalContext, ApprovalDecision};
use std::fs::OpenOptions;
use std::future::Future;
use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::pin::Pin;
use std::time::Duration;

#[cfg(unix)]
const TTY_OUTPUT_PATH: &str = "/dev/tty";
#[cfg(unix)]
const TTY_INPUT_PATH: &str = "/dev/tty";
#[cfg(windows)]
const TTY_OUTPUT_PATH: &str = "CONOUT$";
#[cfg(windows)]
const TTY_INPUT_PATH: &str = "CONIN$";

/// Backend canónico para producción.
#[derive(Default)]
pub struct TtyApprovalBackend;

impl ApprovalBackend for TtyApprovalBackend {
    fn ask(
        &self,
        ctx: ApprovalContext,
    ) -> Pin<Box<dyn Future<Output = ApprovalDecision> + Send + '_>> {
        Box::pin(async move {
            let mut output = match OpenOptions::new().write(true).open(TTY_OUTPUT_PATH) {
                Ok(f) => f,
                Err(_) => return ApprovalDecision::NoTty,
            };
            if !output.is_terminal() {
                return ApprovalDecision::NoTty;
            }

            let box_ascii = format_box(&ctx);
            if writeln!(output, "{box_ascii}").is_err() {
                return ApprovalDecision::NoTty;
            }
            let _ = output.flush();

            let input = match OpenOptions::new().read(true).open(TTY_INPUT_PATH) {
                Ok(f) => f,
                Err(_) => return ApprovalDecision::NoTty,
            };
            if !input.is_terminal() {
                return ApprovalDecision::NoTty;
            }

            let timeout = Duration::from_secs(u64::from(ctx.timeout_seconds));
            let read_handle = tokio::task::spawn_blocking(move || {
                let mut reader = BufReader::new(input);
                let mut buf = String::new();
                reader.read_line(&mut buf).ok().map(|_| buf)
            });

            match tokio::time::timeout(timeout, read_handle).await {
                Ok(Ok(Some(line))) => parse_response(line.trim()),
                Ok(Ok(None)) => ApprovalDecision::Denied,
                Ok(Err(_)) => ApprovalDecision::Denied,
                Err(_) => ApprovalDecision::Timeout,
            }
        })
    }
}

/// Construye el ASCII box mostrado al user.
pub fn format_box(ctx: &ApprovalContext) -> String {
    let mode_label = crate::approval::policy::mode_name(ctx.mode);
    let dest_label = if ctx.destructive {
        "destructive=true"
    } else {
        "destructive=false"
    };
    let mut out = String::new();
    out.push_str("\n╭─ Kvendra approval requested ──────────────────────────────╮\n");
    out.push_str(&format!("│ Profile:    {}\n", ctx.profile_id));
    out.push_str(&format!(
        "│ Operation:  {}.{}\n",
        ctx.primitive, ctx.operation
    ));
    out.push_str(&format!("│ Args:       {}\n", ctx.args_summary));
    out.push_str(&format!("│ Detected:   {dest_label}, mode={mode_label}\n"));
    out.push_str(&format!(
        "│ Mode:       {mode_label} (timeout {}s)\n",
        ctx.timeout_seconds
    ));
    out.push_str("╰─ [y]es / [N]o / [a]pprove-all-5min ─────────────────────────╯");
    out
}

/// Parsea la respuesta del user. Sin respuesta o cualquier valor no afirmativo
/// se interpreta como `Denied` (default conservador).
pub fn parse_response(s: &str) -> ApprovalDecision {
    match s.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => ApprovalDecision::Granted,
        "a" | "approve-all" | "approve_all" => ApprovalDecision::GrantedAllForFiveMin,
        _ => ApprovalDecision::Denied,
    }
}

/// Backend test-only: siempre concede.
pub struct AutoApproveBackend;

impl ApprovalBackend for AutoApproveBackend {
    fn ask(
        &self,
        _ctx: ApprovalContext,
    ) -> Pin<Box<dyn Future<Output = ApprovalDecision> + Send + '_>> {
        Box::pin(async { ApprovalDecision::Granted })
    }
}

/// Backend test-only: siempre deniega.
pub struct AutoDenyBackend;

impl ApprovalBackend for AutoDenyBackend {
    fn ask(
        &self,
        _ctx: ApprovalContext,
    ) -> Pin<Box<dyn Future<Output = ApprovalDecision> + Send + '_>> {
        Box::pin(async { ApprovalDecision::Denied })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::ApprovalMode;

    fn ctx() -> ApprovalContext {
        ApprovalContext {
            profile_id: "p".into(),
            primitive: "kvendra.github".into(),
            operation: "read_repo".into(),
            args_summary: "repo=k/c".into(),
            destructive: false,
            mode: ApprovalMode::AskDestructive,
            timeout_seconds: 30,
        }
    }

    #[test]
    fn parse_response_yes_variants() {
        assert_eq!(parse_response("y"), ApprovalDecision::Granted);
        assert_eq!(parse_response("Y"), ApprovalDecision::Granted);
        assert_eq!(parse_response("yes"), ApprovalDecision::Granted);
        assert_eq!(parse_response("YES"), ApprovalDecision::Granted);
        assert_eq!(parse_response(" y "), ApprovalDecision::Granted);
    }

    #[test]
    fn parse_response_approve_all_variants() {
        assert_eq!(parse_response("a"), ApprovalDecision::GrantedAllForFiveMin);
        assert_eq!(
            parse_response("approve-all"),
            ApprovalDecision::GrantedAllForFiveMin
        );
        assert_eq!(
            parse_response("approve_all"),
            ApprovalDecision::GrantedAllForFiveMin
        );
    }

    #[test]
    fn parse_response_default_is_denied() {
        assert_eq!(parse_response(""), ApprovalDecision::Denied);
        assert_eq!(parse_response("n"), ApprovalDecision::Denied);
        assert_eq!(parse_response("no"), ApprovalDecision::Denied);
        assert_eq!(parse_response("foo"), ApprovalDecision::Denied);
    }

    #[test]
    fn box_includes_metadata() {
        let s = format_box(&ctx());
        assert!(s.contains("Kvendra approval requested"));
        assert!(s.contains("kvendra.github.read_repo"));
        assert!(s.contains("repo=k/c"));
        assert!(s.contains("ask-destructive"));
        assert!(s.contains("[y]es / [N]o / [a]pprove-all-5min"));
    }

    #[tokio::test]
    async fn auto_approve_backend_returns_granted() {
        let b = AutoApproveBackend;
        assert_eq!(b.ask(ctx()).await, ApprovalDecision::Granted);
    }

    #[tokio::test]
    async fn auto_deny_backend_returns_denied() {
        let b = AutoDenyBackend;
        assert_eq!(b.ask(ctx()).await, ApprovalDecision::Denied);
    }
}
