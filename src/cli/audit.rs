//! `kvendra audit [--json] [--verify] [--watch]` — audit log inspection.

use crate::audit::reader::{list_all, open_readonly, verify_chain};
use crate::config::kvendra_home;
use crate::error::{KvendraError, KvendraResult};
use clap::Args;
use zeroize::Zeroize;

#[derive(Debug, Args)]
pub struct AuditArgs {
    /// Export the full log as JSON to stdout.
    #[arg(long)]
    pub json: bool,
    /// Verify the HMAC chain integrity.
    ///
    /// Default behaviour: if the current process holds the unlocked vault
    /// session (e.g. you ran `kvendra unlock` and `kvendra audit --verify`
    /// in the same shell process — only possible from inside `mcp serve`),
    /// the in-memory HMAC sub-key is reused. Otherwise the master password
    /// is read from `--password-stdin`, the env var `KVENDRA_PASSWORD`, or
    /// (for TTY callers) an interactive prompt, and the sub-key is
    /// re-derived in-process via HKDF (ADR-KVD-010 + ADR-KVD-012, opción B).
    #[arg(long)]
    pub verify: bool,
    /// Read the master password from stdin (recommended for scripts).
    /// Only meaningful with `--verify`.
    #[arg(long)]
    pub password_stdin: bool,
    /// Live-tail with the ratatui watch TUI (AC-TUI-2).
    #[arg(long)]
    pub watch: bool,
    /// Filter to a specific profile_id (use with --watch).
    #[arg(long)]
    pub profile: Option<String>,
    /// Filter to a specific primitive name (use with --watch).
    #[arg(long = "primitive", value_name = "NAME")]
    pub primitive_filter: Option<String>,
    /// Time window for the watcher (e.g. `5m`, `1h`).
    #[arg(long)]
    pub since: Option<String>,
}

pub async fn run(args: AuditArgs) -> KvendraResult<()> {
    let home = kvendra_home()?;
    let db = home.join("audit.db");

    if !db.exists() {
        println!("(no audit log yet — run `kvendra mcp serve` to generate events)");
        return Ok(());
    }

    let conn = open_readonly(&db)?;

    if args.verify {
        let vault = crate::vault::Vault::new(home);
        let mut key = match vault.audit_hmac_key() {
            // Same-process unlock fallback (e.g. embedded inside `mcp serve`).
            Ok(k) => k,
            Err(_) => {
                // Cross-process path (default for CLI standalone).
                let password = read_password_for_verify(args.password_stdin)?;
                let derived = vault.audit_hmac_key_from_password(password.as_bytes());
                let mut pw = password;
                pw.zeroize();
                derived?
            }
        };
        let result = verify_chain(&conn, &key);
        // Zeroize the sub-key as soon as we are done with it.
        key.zeroize();
        match result {
            Ok(()) => {
                let n = list_all(&conn)?.len();
                println!("Audit chain valid ({n} rows verified)");
            }
            Err(KvendraError::AuditChainBroken(row)) => {
                println!("CORRUPTION DETECTED at row #{row} (HMAC mismatch)");
                return Err(KvendraError::AuditChainBroken(row));
            }
            Err(e) => println!("audit chain BROKEN: {e}"),
        }
        return Ok(());
    }

    if args.watch {
        // Live TUI per AC-TUI-2.
        return crate::tui::audit_watch::run_watch(
            home,
            args.profile,
            args.primitive_filter,
            args.since,
        )
        .await;
    }

    let events = list_all(&conn)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&events)?);
        return Ok(());
    }

    for ev in events {
        println!(
            "{:>5} {} {:>15} {:<26} {:<10} {} {}",
            ev.id, ev.ts_unix_ms, ev.profile_id, ev.primitive, ev.action, ev.status, ev.severity
        );
    }
    Ok(())
}

/// Resolve the master password for `audit verify` cross-process flow.
///
/// Priority (highest → lowest):
/// 1. `--password-stdin`: read a single line from stdin (newline-terminated,
///    trimmed). Recommended for CI/scripts.
/// 2. Env var `KVENDRA_PASSWORD` (same name used by `kvendra unlock`).
/// 3. Interactive prompt via `rpassword` (only if stdin is a TTY).
fn read_password_for_verify(password_stdin: bool) -> KvendraResult<String> {
    if password_stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .map_err(|e| KvendraError::Vault(format!("read password from stdin: {e}")))?;
        // Strip trailing newline only — keep any leading/trailing spaces the
        // caller chose to include (matches the unlock semantics).
        if buf.ends_with('\n') {
            buf.pop();
            if buf.ends_with('\r') {
                buf.pop();
            }
        }
        return Ok(buf);
    }
    if let Ok(p) = std::env::var("KVENDRA_PASSWORD")
        && !p.is_empty()
    {
        return Ok(p);
    }
    println!("Enter the master password (will not echo):");
    rpassword::read_password().map_err(|e| KvendraError::Vault(format!("read password: {e}")))
}
