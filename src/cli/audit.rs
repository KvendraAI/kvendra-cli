//! `kvendra audit [--json] [--verify] [--watch]` + `audit export` + `audit verify-export`.

use crate::audit::export::bundle::ExportFilters;
use crate::audit::export::filter::ExportFilter;
use crate::audit::export::pdf_format::BrandConfig;
use crate::audit::export::verify::VerifyOutcome;
use crate::audit::export::{bundle, csv_format, json_canonical, pdf_format, verify};
use crate::audit::reader::{list_all, open_readonly, verify_chain};
use crate::config::kvendra_home;
use crate::error::{KvendraError, KvendraResult};
use clap::{Args, Subcommand};
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Debug, Args)]
pub struct AuditArgs {
    /// Export the full log as JSON to stdout (legacy flag).
    #[arg(long)]
    pub json: bool,
    /// Verify the HMAC chain integrity (legacy flag).
    #[arg(long)]
    pub verify: bool,
    /// Read the master password from stdin (recommended for scripts).
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

    /// New REQ-KVD-CLI-007 subcommands (export / verify-export).
    #[command(subcommand)]
    pub subcommand: Option<AuditSub>,
}

#[derive(Debug, Subcommand)]
pub enum AuditSub {
    /// Export signed audit log (PDF + CSV + JSON canonical) — REQ-KVD-CLI-007.
    Export(ExportArgs),
    /// Verify integrity of a previously generated JSON canonical export.
    VerifyExport(VerifyExportArgs),
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    /// ISO 8601 lower bound (inclusive). Default: 30 days ago.
    #[arg(long)]
    pub from: Option<String>,
    /// ISO 8601 upper bound (inclusive). Default: now.
    #[arg(long)]
    pub to: Option<String>,
    /// Filter expression — e.g. `profile_id=alice,primitive=kvendra.git`.
    #[arg(long)]
    pub filter: Option<String>,
    /// Comma-separated formats: pdf,csv,json. Default: pdf,csv,json.
    #[arg(long, default_value = "pdf,csv,json")]
    pub format: String,
    /// Output directory (default: current directory).
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Bypass redaction — include raw args summaries (warning printed).
    #[arg(long)]
    pub include_raw_args: bool,
    /// Read master password from stdin (needed to derive HMAC chain seed).
    #[arg(long)]
    pub password_stdin: bool,
}

#[derive(Debug, Args)]
pub struct VerifyExportArgs {
    /// Path to `*.json` canonical export.
    pub path: PathBuf,
}

pub async fn run(args: AuditArgs) -> KvendraResult<()> {
    if let Some(sub) = args.subcommand {
        return match sub {
            AuditSub::Export(a) => run_export(a).await,
            AuditSub::VerifyExport(a) => run_verify_export(a),
        };
    }
    run_legacy(args).await
}

async fn run_legacy(args: AuditArgs) -> KvendraResult<()> {
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
            Ok(k) => k,
            Err(_) => {
                let password = read_password_for_verify(args.password_stdin)?;
                let derived = vault.audit_hmac_key_from_password(password.as_bytes());
                let mut pw = password;
                pw.zeroize();
                derived?
            }
        };
        let result = verify_chain(&conn, &key);
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

fn read_password_for_verify(password_stdin: bool) -> KvendraResult<String> {
    if password_stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .map_err(|e| KvendraError::Vault(format!("read password from stdin: {e}")))?;
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

async fn run_export(args: ExportArgs) -> KvendraResult<()> {
    let home = kvendra_home()?;
    let db = home.join("audit.db");
    if !db.exists() {
        return Err(KvendraError::Audit(
            "no audit log present — nothing to export".into(),
        ));
    }
    let conn = open_readonly(&db)?;

    let vault = crate::vault::Vault::new(home.clone());
    let mut key = match vault.audit_hmac_key() {
        Ok(k) => k,
        Err(_) => {
            let password = read_password_for_verify(args.password_stdin)?;
            let derived = vault.audit_hmac_key_from_password(password.as_bytes());
            let mut pw = password;
            pw.zeroize();
            derived?
        }
    };
    let chain_key_seed_hex = hex::encode(&key);

    let mut events = list_all(&conn)?;

    let from_ms = args
        .from
        .as_deref()
        .and_then(parse_iso8601_to_unix_ms)
        .unwrap_or_else(|| now_unix_ms() - 30 * 86_400_000);
    let to_ms = args
        .to
        .as_deref()
        .and_then(parse_iso8601_to_unix_ms)
        .unwrap_or_else(now_unix_ms);
    events.retain(|ev| ev.ts_unix_ms >= from_ms && ev.ts_unix_ms <= to_ms);

    let filter = args
        .filter
        .as_deref()
        .map(ExportFilter::parse)
        .unwrap_or_default();
    if !filter.is_empty() {
        events.retain(|ev| filter.matches(ev));
    }

    let brand = load_brand().unwrap_or_default();
    let exported_by = if brand.legal_name.is_empty() {
        "Generated by Kvendra CLI".to_string()
    } else {
        brand.legal_name.clone()
    };

    let bundle = bundle::build_bundle(
        &events,
        &exported_by,
        ExportFilters {
            from: args.from.clone(),
            to: args.to.clone(),
            raw: args.filter.clone(),
        },
        chain_key_seed_hex,
    );

    if args.include_raw_args {
        eprintln!(
            "warning: --include-raw-args set — args summaries may contain redacted-by-default \
             secret patterns. Review output before sharing."
        );
    }

    let out_dir = args
        .out
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    std::fs::create_dir_all(&out_dir)?;

    let today = today_iso_date();
    let stem = format!("kvendra-audit-{today}");

    let formats: Vec<String> = args
        .format
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .collect();

    let mut written: Vec<PathBuf> = Vec::new();
    if formats.iter().any(|s| s == "json") {
        let path = out_dir.join(format!("{stem}.json"));
        json_canonical::write_json(&path, &bundle)?;
        written.push(path);
    }
    if formats.iter().any(|s| s == "csv") {
        let path = out_dir.join(format!("{stem}.csv"));
        csv_format::write_csv(&path, &bundle)?;
        written.push(path);
    }
    if formats.iter().any(|s| s == "pdf") {
        let path = out_dir.join(format!("{stem}.pdf"));
        pdf_format::write_pdf(&path, &bundle, &brand)?;
        written.push(path);
    }

    key.zeroize();

    println!(
        "Exported {} events ({} → {}) to:",
        bundle.events.len(),
        bundle.filters.from.as_deref().unwrap_or("-30d"),
        bundle.filters.to.as_deref().unwrap_or("now"),
    );
    for p in &written {
        println!("  {}", p.display());
    }
    println!("Verify online: {}", bundle.verifier_url);
    println!("Or run: kvendra audit verify-export {}.json", stem);
    Ok(())
}

fn run_verify_export(args: VerifyExportArgs) -> KvendraResult<()> {
    let outcome = verify::verify_path(&args.path)?;
    match outcome {
        VerifyOutcome::Pass { events_count } => {
            println!("PASS — {events_count} events verified, chain integrity OK.");
            Ok(())
        }
        VerifyOutcome::Fail {
            first_deviation_at,
            reason,
        } => {
            println!("FAIL — first deviation at event index {first_deviation_at}: {reason}");
            Err(KvendraError::Audit(format!(
                "audit verify failed at index {first_deviation_at}: {reason}"
            )))
        }
    }
}

fn now_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn parse_iso8601_to_unix_ms(s: &str) -> Option<i64> {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    if let Ok(t) = OffsetDateTime::parse(s, &Rfc3339) {
        return Some(t.unix_timestamp() * 1000);
    }
    if s.len() == 10 {
        let extended = format!("{s}T00:00:00Z");
        if let Ok(t) = OffsetDateTime::parse(&extended, &Rfc3339) {
            return Some(t.unix_timestamp() * 1000);
        }
    }
    None
}

fn today_iso_date() -> String {
    use time::OffsetDateTime;
    let now = OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}",
        now.year(),
        u8::from(now.month()),
        now.day()
    )
}

fn load_brand() -> Option<BrandConfig> {
    // Best-effort: read audit.brand.* via env vars (config.toml integration
    // deferred — config is HMAC-signed and requires vault unlock, which would
    // force export to unlock first only for branding. Env-override is cheap.).
    let legal_name = std::env::var("KVENDRA_AUDIT_BRAND_NAME").unwrap_or_default();
    let email = std::env::var("KVENDRA_AUDIT_BRAND_EMAIL").unwrap_or_default();
    if legal_name.is_empty() && email.is_empty() {
        return None;
    }
    Some(BrandConfig { legal_name, email })
}
