//! `kvendra audit [--json] [--verify] [--watch]` — audit log inspection.

use crate::audit::reader::{list_all, open_readonly, verify_chain};
use crate::config::kvendra_home;
use crate::error::KvendraResult;
use clap::Args;

#[derive(Debug, Args)]
pub struct AuditArgs {
    /// Export the full log as JSON to stdout.
    #[arg(long)]
    pub json: bool,
    /// Verify the HMAC chain integrity (requires unlocked vault).
    #[arg(long)]
    pub verify: bool,
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
        // HMAC key per ADR-KVD-010 + ADR-KVD-012: derived from the unlocked
        // session via HKDF. Vault must be unlocked to verify.
        let vault = crate::vault::Vault::new(home);
        let key = match vault.audit_hmac_key() {
            Ok(k) => k,
            Err(_) => {
                println!("audit verify: vault is locked. Run `kvendra unlock` first.");
                return Ok(());
            }
        };
        match verify_chain(&conn, &key) {
            Ok(()) => println!("audit chain OK"),
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
