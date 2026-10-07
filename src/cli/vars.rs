//! `kvendra vars …` — local variables `{{lvr:key}}` (REQ-KVD-11F906).
//!
//! Two surfaces with different trust:
//!
//! - **Human (S0)**: `set`, `unset`, `reveal`, `verify`. Values are read from
//!   and shown on the real TTY ONLY (no stdin/stderr fallback on any
//!   platform); on Windows `set`/`reveal`/`verify` refuse ("no soportado en
//!   esta plataforma: requiere una consola real"). ALWAYS behind
//!   `ensure_real_terminal()` (the 3-layer anti-captured-env guard) and a
//!   master password read from the TTY handle, even when the vault is already
//!   unlocked. No `--password-stdin`, no `KVENDRA_PASSWORD`: an agent that
//!   only has Bash cannot write or read a value. `reveal`/`verify` print the
//!   value ONLY to `/dev/tty`, never to stdout.
//! - **Skills / hooks**: `list`, `status --declared-stdin --json`,
//!   `scan --stdin --json`. No password (active session blob), never a value.
//!   `scan` (O7) requires the unlocked vault, is rate-limited, needs ≥16 bytes
//!   and ≤1 MiB of input, returns only keys + counts (never positions) and
//!   writes one audit row per call.
//!
//! Masking scope (N2): the broker filter and `scan` match LITERAL occurrences
//! of a value (also inside JSON text). Encoded forms (`%2F`, base64, doubled
//! escapes) are NOT detected — a guarantee for the literal, a brake for the
//! rest.
//!
//! Exit codes of `status` / `scan` (IF-KVD-CLI-5D9FB5 `cli_commands_for_skills`):
//! `0` ok / no hits, `3` hits (scan), `4` vault locked or no variables (scan),
//! `2` invalid input or rate limited.

use crate::audit::{AuditEvent, AuditWriter, PRIMITIVE_SYSTEM, Severity, Status};
use crate::captured_env::{TtyHandle, UnlockRejection, ensure_real_terminal};
use crate::config::{Config, kvendra_home};
use crate::error::{KvendraError, KvendraResult};
use crate::vars::{self, VarType};
use crate::vault::Vault;
use clap::Subcommand;
use std::io::Read;
use std::path::Path;
use zeroize::Zeroize;

/// Maximum `scan` input (1 MiB).
pub const SCAN_MAX_INPUT: usize = 1024 * 1024;
/// Minimum `scan` input (anti prefix-oracle, O7).
pub const SCAN_MIN_INPUT: usize = 16;
/// `scan` calls allowed per rolling minute (persisted across invocations).
pub const SCAN_MAX_PER_MINUTE: usize = 60;

pub const EXIT_HITS: i32 = 3;
pub const EXIT_LOCKED: i32 = 4;
pub const EXIT_BAD_INPUT: i32 = 2;

/// Literal warning of a scan skipped because the vault is locked (O3): it
/// never claims the content is clean.
pub const SCAN_SKIPPED_LOCKED: &str = "scan omitido: vault bloqueado";

#[derive(Debug, Subcommand)]
pub enum VarsCommand {
    /// Set a local variable (human only: real TTY + master password). The
    /// value is read from the terminal, never from argv or stdin.
    Set {
        key: String,
        /// path | host | port | profile_id | string
        #[arg(long = "type", value_name = "TYPE")]
        var_type: String,
    },
    /// Remove a local variable (human only: real TTY + master password).
    Unset { key: String },
    /// Show a value on the terminal only (human only: real TTY + password).
    Reveal { key: String },
    /// Re-validate and confirm values on the terminal → `verified:true`
    /// (human only: real TTY + password).
    Verify {
        key: Option<String>,
        #[arg(long, conflicts_with = "key")]
        all: bool,
    },
    /// List variables (keys, types, verified) — never values.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Compare KB declarations (JSON on stdin) with the local store.
    Status {
        #[arg(long)]
        declared_stdin: bool,
        #[arg(long)]
        json: bool,
    },
    /// Scan stdin for literal local values. Keys + counts only.
    Scan {
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        json: bool,
    },
}

pub async fn run(cmd: VarsCommand) -> KvendraResult<()> {
    match cmd {
        VarsCommand::Set { key, var_type } => run_set(&key, &var_type).await,
        VarsCommand::Unset { key } => run_unset(&key).await,
        VarsCommand::Reveal { key } => run_reveal(&key).await,
        VarsCommand::Verify { key, all } => run_verify(key.as_deref(), all).await,
        VarsCommand::List { json } => run_list(json),
        VarsCommand::Status { declared_stdin, .. } => run_status(declared_stdin),
        VarsCommand::Scan { stdin, .. } => run_scan(stdin).await,
    }
}

// ───────────────────────── human surface ─────────────────────────

/// `vars_rejected_*` code for a TTY-guard rejection.
pub fn rejection_code(r: &UnlockRejection) -> &'static str {
    match r {
        UnlockRejection::NoControllingTty { .. } => "vars_rejected_no_controlling_tty",
        UnlockRejection::StdioNotOwned { .. } => "vars_rejected_stdio_not_owned",
    }
}

/// S0 gate: real terminal, then the password from the TTY handle, verified
/// in a fresh in-process vault. Returns the handle and the unlocked vault.
fn human_gate(command: &str) -> KvendraResult<(TtyHandle, Vault, std::path::PathBuf)> {
    // Security review blocker: on Windows the TTY handle has no real-console
    // path for values (no stdin/stderr fallback), so the commands that read
    // or show a value refuse up front, before any password prompt.
    #[cfg(windows)]
    if matches!(command, "set" | "reveal" | "verify") {
        eprintln!(
            "kvendra vars {command}: {}",
            crate::captured_env::VALUE_CONSOLE_UNSUPPORTED
        );
        return Err(KvendraError::LocalVar {
            code: "vars_unsupported_platform",
            key: String::new(),
        });
    }
    let handle = match ensure_real_terminal() {
        Ok(h) => h,
        Err(rejection) => {
            let code = rejection_code(&rejection);
            tracing::warn!(target: "kvendra::vars", flag = code, "vars {command} rejected");
            eprintln!(
                "kvendra vars {command}: this command must run in YOUR OWN terminal (real TTY), \
                 never from an agent or a captured shell. Values are written and read only by a \
                 human."
            );
            return Err(KvendraError::LocalVar {
                code,
                key: String::new(),
            });
        }
    };
    let home = kvendra_home()?;
    let cfg = Config::load(&home, None).unwrap_or_default();
    let vault = Vault::new(home.clone());
    if !vault.sentinel_path().exists() {
        return Err(KvendraError::Vault(
            "vault not initialized. Run `kvendra init` first.".into(),
        ));
    }
    let mut password = handle
        .read_password("Master password (will not echo): ")
        .map_err(|e| KvendraError::Vault(format!("read password: {e}")))?;
    let res = vault.unlock(password.as_bytes(), cfg.vault.idle_timeout_minutes);
    password.zeroize();
    res?;
    Ok((handle, vault, home))
}

fn tty_err(e: std::io::Error) -> KvendraError {
    KvendraError::Vault(format!("terminal io: {e}"))
}

fn confirm(handle: &TtyHandle, prompt: &str) -> KvendraResult<bool> {
    let answer = handle.read_line(prompt).map_err(tty_err)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

async fn run_set(key: &str, var_type: &str) -> KvendraResult<()> {
    let (handle, vault, home) = human_gate("set")?;
    if !vars::is_valid_key(key) {
        return Err(KvendraError::InvalidArgs(
            "key must match [a-z0-9][a-z0-9._-]{0,127}".into(),
        ));
    }
    let t = VarType::parse(var_type).ok_or_else(|| {
        KvendraError::InvalidArgs("--type must be path|host|port|profile_id|string".into())
    })?;
    let mut raw = handle
        .read_line(&format!("Value for '{key}' ({}): ", t.as_str()))
        .map_err(tty_err)?;
    let normalized = vars::validate::validate(t, &raw);
    raw.zeroize();
    let mut normalized = normalized.map_err(|code| KvendraError::LocalVar {
        code,
        key: key.to_string(),
    })?;
    handle
        .write_tty(&format!("  {key} = {normalized}\n"))
        .map_err(tty_err)?;
    let verified = confirm(&handle, "Is this value correct for this machine? [y/N] ")?;
    let res = vars::set_var(&vault, key, t, &normalized, verified);
    normalized.zeroize();
    res?;
    audit_human(&vault, &home, "vars_set", key).await;
    vault.lock();
    println!(
        "local variable '{key}' set ({}, {})",
        t.as_str(),
        if verified { "verified" } else { "unverified" }
    );
    Ok(())
}

async fn run_unset(key: &str) -> KvendraResult<()> {
    let (_handle, vault, home) = human_gate("unset")?;
    let existed = vars::unset_var(&vault, key)?;
    if existed {
        audit_human(&vault, &home, "vars_unset", key).await;
    }
    vault.lock();
    if existed {
        println!("local variable '{key}' removed");
    } else {
        println!("local variable '{key}' did not exist");
    }
    Ok(())
}

async fn run_reveal(key: &str) -> KvendraResult<()> {
    let (handle, vault, home) = human_gate("reveal")?;
    let doc = vars::load(&vault)?;
    let var = doc.vars.get(key).ok_or_else(|| KvendraError::LocalVar {
        code: "lvr_undefined",
        key: key.to_string(),
    })?;
    handle
        .write_tty(&format!(
            "{key} ({}, {}) = {}\n",
            var.var_type.as_str(),
            if var.verified {
                "verified"
            } else {
                "unverified"
            },
            var.value.as_str()
        ))
        .map_err(tty_err)?;
    audit_human(&vault, &home, "vars_revealed", key).await;
    vault.lock();
    Ok(())
}

async fn run_verify(key: Option<&str>, all: bool) -> KvendraResult<()> {
    if key.is_none() && !all {
        return Err(KvendraError::InvalidArgs(
            "`kvendra vars verify` needs a <key> or --all".into(),
        ));
    }
    let (handle, vault, home) = human_gate("verify")?;
    let doc = vars::load(&vault)?;
    let keys: Vec<String> = match key {
        Some(k) => vec![k.to_string()],
        None => doc.vars.keys().cloned().collect(),
    };
    let mut verified_n = 0;
    for k in &keys {
        let Some(var) = doc.vars.get(k) else {
            handle
                .write_tty(&format!("{k}: not set on this machine\n"))
                .map_err(tty_err)?;
            continue;
        };
        if let Err(code) = vars::validate::validate(var.var_type, &var.value) {
            handle
                .write_tty(&format!(
                    "{k}: {code} — re-set it with `kvendra vars set`\n"
                ))
                .map_err(tty_err)?;
            continue;
        }
        handle
            .write_tty(&format!(
                "{k} ({}) = {}\n",
                var.var_type.as_str(),
                var.value.as_str()
            ))
            .map_err(tty_err)?;
        if confirm(&handle, "Correct for this machine? [y/N] ")? {
            vars::mark_verified(&vault, k)?;
            audit_human(&vault, &home, "vars_verified", k).await;
            verified_n += 1;
        }
    }
    vault.lock();
    println!("{verified_n} local variable(s) verified");
    Ok(())
}

/// One audit row for a human operation: flag + `lvr:<key>`, never the value.
async fn audit_human(vault: &Vault, home: &Path, flag: &str, key: &str) {
    let Ok(hmac) = vault.audit_hmac_key() else {
        return;
    };
    let detail = serde_json::json!({ "key": key });
    let _ = record_event(home, hmac, &format!("{flag},lvr:{key}"), flag, &detail).await;
}

async fn record_event(
    home: &Path,
    hmac_key: Vec<u8>,
    flags: &str,
    action: &str,
    detail: &serde_json::Value,
) -> KvendraResult<()> {
    let writer = AuditWriter::spawn(home.join("audit.db"), hmac_key)?;
    let event = AuditEvent {
        ts_unix_ms: chrono::Utc::now().timestamp_millis(),
        profile_id: PRIMITIVE_SYSTEM.into(),
        primitive: PRIMITIVE_SYSTEM.into(),
        action: action.into(),
        args_hash_hex: crate::audit::reader::args_hash_hex(detail),
        status: Status::Ok,
        severity: Severity::Info,
        flags: flags.into(),
        remote_audit_id: None,
        error_code: None,
        error_message: None,
    };
    writer.record(event).await?;
    writer.shutdown().await;
    Ok(())
}

// ───────────────────────── skills / hooks surface ─────────────────────────

/// Unlock from the active session blob (no password). `None` when there is
/// no valid session (the vault is locked for this machine).
pub fn session_vault(home: &Path) -> Option<Vault> {
    let state = crate::session::local::load(home).ok()?;
    let cfg = Config::load(home, None).unwrap_or_default();
    let vault = Vault::new(home.to_path_buf());
    vault
        .unlock_from_derived_key(&state.derived_key, cfg.vault.idle_timeout_minutes)
        .ok()?;
    Some(vault)
}

fn exit_json(code: i32, body: serde_json::Value) -> ! {
    println!("{body}");
    std::process::exit(code);
}

fn run_list(json: bool) -> KvendraResult<()> {
    let home = kvendra_home()?;
    let Some(vault) = session_vault(&home) else {
        eprintln!("kvendra vars list: vault bloqueado — run `kvendra unlock` in your terminal");
        exit_json(EXIT_LOCKED, serde_json::json!({"error": "vault_locked"}));
    };
    let doc = vars::load(&vault)?;
    let rows = vars::list(&doc);
    if json {
        println!("{}", serde_json::json!({ "vars": rows }));
    } else if rows.is_empty() {
        println!("(no local variables on this machine)");
    } else {
        for r in rows {
            println!(
                "{:<32} {:<10} {}",
                r.key,
                r.var_type,
                if r.verified { "verified" } else { "unverified" }
            );
        }
    }
    Ok(())
}

fn read_stdin_capped(cap: usize) -> Result<String, &'static str> {
    let mut buf = Vec::new();
    std::io::stdin()
        .take(cap as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|_| "stdin_unreadable")?;
    if buf.len() > cap {
        return Err("input_too_large");
    }
    String::from_utf8(buf).map_err(|_| "input_not_utf8")
}

fn run_status(declared_stdin: bool) -> KvendraResult<()> {
    if !declared_stdin {
        return Err(KvendraError::InvalidArgs(
            "`kvendra vars status` requires --declared-stdin".into(),
        ));
    }
    let input = match read_stdin_capped(SCAN_MAX_INPUT) {
        Ok(s) => s,
        Err(e) => exit_json(EXIT_BAD_INPUT, serde_json::json!({ "error": e })),
    };
    let declared: Vec<vars::Declared> = match serde_json::from_str(&input) {
        Ok(d) => d,
        Err(_) => exit_json(
            EXIT_BAD_INPUT,
            serde_json::json!({"error": "declared_malformed"}),
        ),
    };
    let home = kvendra_home()?;
    let Some(vault) = session_vault(&home) else {
        exit_json(EXIT_LOCKED, serde_json::json!({"error": "vault_locked"}));
    };
    let doc = vars::load(&vault)?;
    let report = vars::status(&doc, &declared);
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

/// Outcome of a scan, value-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanOutcome {
    Hits(Vec<(String, usize)>),
    BadInput(&'static str),
    RateLimited,
}

/// Core of `vars scan` (testable without stdin/exit): input bounds, the
/// persisted rate limit and the value-free match.
pub fn scan_text(home: &Path, vault: &Vault, input: &str) -> KvendraResult<ScanOutcome> {
    if input.len() < SCAN_MIN_INPUT {
        return Ok(ScanOutcome::BadInput("input_too_short"));
    }
    if input.len() > SCAN_MAX_INPUT {
        return Ok(ScanOutcome::BadInput("input_too_large"));
    }
    if !scan_rate_take(home) {
        return Ok(ScanOutcome::RateLimited);
    }
    let doc = vars::load(vault)?;
    let known = vars::filter::KnownValues::from_doc(&doc);
    Ok(ScanOutcome::Hits(known.contains_any(input)))
}

/// Rolling-minute limiter persisted in `cache/vars_scan.rate` (one unix-ms
/// timestamp per line). A brake against a membership / prefix oracle: a
/// same-uid process can delete the file, so it is not a control.
fn scan_rate_take(home: &Path) -> bool {
    let path = home.join("cache").join("vars_scan.rate");
    let now = chrono::Utc::now().timestamp_millis();
    let mut stamps: Vec<i64> = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .filter(|t: &i64| now - *t < 60_000)
        .collect();
    if stamps.len() >= SCAN_MAX_PER_MINUTE {
        return false;
    }
    stamps.push(now);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let body: Vec<String> = stamps.iter().map(i64::to_string).collect();
    let _ = std::fs::write(&path, body.join("\n"));
    true
}

async fn run_scan(stdin: bool) -> KvendraResult<()> {
    if !stdin {
        return Err(KvendraError::InvalidArgs(
            "`kvendra vars scan` requires --stdin".into(),
        ));
    }
    let home = kvendra_home()?;
    let Some(vault) = session_vault(&home) else {
        eprintln!("{SCAN_SKIPPED_LOCKED}");
        exit_json(EXIT_LOCKED, serde_json::json!({"error": "vault_locked"}));
    };
    if !vault.vars_blob_path().exists() {
        eprintln!("scan omitido: sin variables locales en esta máquina");
        exit_json(EXIT_LOCKED, serde_json::json!({"error": "no_local_vars"}));
    }
    let input = match read_stdin_capped(SCAN_MAX_INPUT) {
        Ok(s) => s,
        Err(e) => exit_json(EXIT_BAD_INPUT, serde_json::json!({ "error": e })),
    };
    match scan_text(&home, &vault, &input)? {
        ScanOutcome::BadInput(e) => exit_json(EXIT_BAD_INPUT, serde_json::json!({ "error": e })),
        ScanOutcome::RateLimited => {
            exit_json(EXIT_BAD_INPUT, serde_json::json!({"error": "rate_limited"}))
        }
        ScanOutcome::Hits(hits) => {
            let total: usize = hits.iter().map(|(_, c)| c).sum();
            if let Ok(hmac) = vault.audit_hmac_key() {
                let mut flags = vec!["vars_scan".to_string(), format!("hits:{total}")];
                flags.extend(hits.iter().map(|(k, _)| format!("lvr:{k}")));
                let detail = serde_json::json!({ "hits": total, "bytes": input.len() });
                let _ = record_event(&home, hmac, &flags.join(","), "vars_scan", &detail).await;
            }
            let body = serde_json::json!({
                "hits": hits
                    .iter()
                    .map(|(k, c)| serde_json::json!({"key": k, "count": c}))
                    .collect::<Vec<_>>()
            });
            if hits.is_empty() {
                println!("{body}");
                Ok(())
            } else {
                exit_json(EXIT_HITS, body)
            }
        }
    }
}
