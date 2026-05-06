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
    /// Verify the HMAC chain integrity.
    #[arg(long)]
    pub verify: bool,
    /// Live-tail (Pase B full TUI; Pase A is a polling stub).
    #[arg(long)]
    pub watch: bool,
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
        // HMAC key in Pase A: derived placeholder. Pase B chains to vault session key.
        let key = b"kvendra-pase-a-placeholder-hmac-key";
        match verify_chain(&conn, key) {
            Ok(()) => println!("audit chain OK"),
            Err(e) => println!("audit chain BROKEN: {e}"),
        }
        return Ok(());
    }

    let events = list_all(&conn)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&events)?);
        return Ok(());
    }

    if args.watch {
        println!("kvendra audit --watch — Pase A polling stub; live TUI lands in Pase B");
    }

    for ev in events {
        println!(
            "{:>5} {} {:>15} {:<26} {:<10} {} {}",
            ev.id, ev.ts_unix_ms, ev.profile_id, ev.primitive, ev.action, ev.status, ev.severity
        );
    }
    Ok(())
}
