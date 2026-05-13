//! `kvendra secret <subcommand>` — profile management (Pase B real flows).
//!
//! Supported actions:
//!   - `add <profile_id> [--secret-env VAR | --secret-file PATH]`
//!   - `list`
//!   - `get-meta <profile_id>` (no plaintext)
//!   - `rotate <profile_id> [--secret-env VAR]`
//!   - `revoke <profile_id>`
//!   - `validate <profile_id> | --all`
//!   - `set-allowlist <profile_id> --file PATH`

use crate::allowlist::dsl::OperationConstraints;
use crate::allowlist::{ProfileSpec, catalog, validate as allowlist_validate};
use crate::config::{Config, kvendra_home};
use crate::error::{KvendraError, KvendraResult};
use crate::vault::{Profile, Vault};
use clap::{Args, Subcommand};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use zeroize::Zeroize;

#[derive(Debug, Subcommand)]
pub enum SecretCommand {
    /// Add a new secret profile (encrypts plaintext into the vault).
    Add(AddArgs),
    /// List existing profiles.
    List,
    /// Print metadata for a profile (no plaintext).
    GetMeta { profile_id: String },
    /// Rotate a profile's secret.
    Rotate(RotateArgs),
    /// Revoke a profile (delete blob + metadata + allowlist).
    Revoke { profile_id: String },
    /// Validate the allowlist of a profile (or `--all`).
    Validate(ValidateArgs),
    /// Set the YAML allowlist for a profile.
    SetAllowlist(SetAllowlistArgs),
}

#[derive(Debug, Args)]
pub struct AddArgs {
    pub profile_id: String,
    /// Secret type label (e.g. github_pat, npm_token, ...).
    #[arg(long, default_value = "generic")]
    pub secret_type: String,
    /// Read plaintext from this env var.
    #[arg(long)]
    pub secret_env: Option<String>,
    /// Read plaintext from this file (UTF-8).
    #[arg(long)]
    pub secret_file: Option<PathBuf>,
    /// Allow the unsafe.raw_token escape hatch on this profile.
    #[arg(long)]
    pub unsafe_raw_token_enabled: bool,
    /// Optional ISO-8601 expiration date.
    #[arg(long)]
    pub expiration: Option<String>,
    /// Read master password from stdin (recommended for scripts).
    #[arg(long)]
    pub password_stdin: bool,
}

#[derive(Debug, Args)]
pub struct RotateArgs {
    pub profile_id: String,
    #[arg(long)]
    pub secret_env: Option<String>,
    #[arg(long)]
    pub secret_file: Option<PathBuf>,
    /// Read master password from stdin (recommended for scripts).
    #[arg(long)]
    pub password_stdin: bool,
}

#[derive(Debug, Args)]
pub struct ValidateArgs {
    pub profile_id: Option<String>,
    /// Validate every profile present on disk.
    #[arg(long)]
    pub all: bool,
}

#[derive(Debug, Args)]
pub struct SetAllowlistArgs {
    pub profile_id: String,
    #[arg(long)]
    pub file: PathBuf,
    /// Read master password from stdin (recommended for scripts).
    #[arg(long)]
    pub password_stdin: bool,
}

pub async fn run(cmd: SecretCommand) -> KvendraResult<()> {
    let home = kvendra_home()?;
    let vault = Vault::new(home.clone());

    // REQ-KVD-CLI-004 AC-RESOLVER-7 — in workspace mode, `secret add` and
    // `secret rotate` are restricted to admin/owner. Members are bounced
    // here with a clear hint pointing at `kvendra workspace add-secret`,
    // which goes through the broker and respects server-side RBAC.
    if is_workspace_mode(&home)? {
        match &cmd {
            SecretCommand::Add(_) | SecretCommand::Rotate(_) => {
                return Err(KvendraError::InsufficientPrivilege(format!(
                    "`kvendra secret {}` is local-only. \
                     In workspace mode use `kvendra workspace add-secret` \
                     (owner/admin only)",
                    match &cmd {
                        SecretCommand::Add(_) => "add",
                        SecretCommand::Rotate(_) => "rotate",
                        _ => "<op>",
                    }
                )));
            }
            _ => {}
        }
    }

    match cmd {
        SecretCommand::Add(args) => add(&vault, &home, args).await,
        SecretCommand::List => list(&vault),
        SecretCommand::GetMeta { profile_id } => get_meta(&vault, &profile_id),
        SecretCommand::Rotate(args) => rotate(&vault, &home, args).await,
        SecretCommand::Revoke { profile_id } => revoke(&vault, &profile_id),
        SecretCommand::Validate(args) => validate_cmd(&vault, args),
        SecretCommand::SetAllowlist(args) => set_allowlist(&vault, &home, args),
    }
}

/// Returns true when at least one `~/.kvendra/sessions/*.token` file is
/// present. The presence of a session is the canonical signal that the
/// process is bound to a workspace (cf. REQ-KVD-CLI-004 AC-RESOLVER-4).
fn is_workspace_mode(home: &Path) -> KvendraResult<bool> {
    let sessions = crate::session::list_active_sessions(home)?;
    Ok(!sessions.is_empty())
}

/// Resolve the master password and ensure the vault is unlocked in-process.
///
/// If the vault is already unlocked (e.g. inside an embedded `mcp serve`),
/// returns immediately. Otherwise, reads the master password from one of:
/// 1. `--password-stdin` (recommended for scripts).
/// 2. Env var `KVENDRA_PASSWORD` (same name used by `kvendra unlock`).
/// 3. Interactive prompt via `rpassword` (only if stdin is a TTY).
///
/// Then re-derives the session key in-process. The password is zeroized
/// before this function returns. Mirrors the canonical pattern used by
/// `kvendra audit verify` (per ADR-KVD-012, opción B owner).
fn ensure_unlocked(vault: &Vault, home: &Path, password_stdin: bool) -> KvendraResult<()> {
    if vault.is_unlocked() {
        return Ok(());
    }
    // The vault may already be unlocked from an earlier `kvendra unlock`;
    // pass it through so a signed config is verified end-to-end. If still
    // locked we fall back to the unsigned-or-default load.
    let cfg = Config::load(
        home,
        if vault.is_unlocked() {
            Some(vault)
        } else {
            None
        },
    )
    .unwrap_or_default();
    let mut password = read_master_password(password_stdin)?;
    let result = vault.unlock(password.as_bytes(), cfg.vault.idle_timeout_minutes);
    password.zeroize();
    result
}

fn read_master_password(password_stdin: bool) -> KvendraResult<String> {
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

fn read_secret(env: Option<&str>, file: Option<&PathBuf>) -> KvendraResult<Vec<u8>> {
    if let Some(name) = env {
        let v = std::env::var(name)
            .map_err(|_| KvendraError::InvalidArgs(format!("env var '{name}' not set")))?;
        return Ok(v.into_bytes());
    }
    if let Some(path) = file {
        return Ok(std::fs::read(path)?);
    }
    Err(KvendraError::InvalidArgs(
        "must pass --secret-env <VAR> or --secret-file <PATH>".into(),
    ))
}

async fn add(vault: &Vault, home: &Path, args: AddArgs) -> KvendraResult<()> {
    ensure_unlocked(vault, home, args.password_stdin)?;
    let plaintext = read_secret(args.secret_env.as_deref(), args.secret_file.as_ref())?;
    vault.put_secret(&args.profile_id, &plaintext)?;

    let meta = Profile {
        profile_id: args.profile_id.clone(),
        secret_type: args.secret_type,
        created_at: OffsetDateTime::now_utc().to_string(),
        expiration: args.expiration,
        unsafe_raw_token_enabled: args.unsafe_raw_token_enabled,
        quarantined: false,
        allowlist_hmac_hex: None,
    };
    vault.save_profile_meta(&meta)?;

    println!("Profile '{}' added.", args.profile_id);
    Ok(())
}

fn list(vault: &Vault) -> KvendraResult<()> {
    let profiles = vault.list_profiles()?;
    if profiles.is_empty() {
        println!("(no profiles)");
    } else {
        for p in profiles {
            println!("{p}");
        }
    }
    Ok(())
}

fn get_meta(vault: &Vault, profile_id: &str) -> KvendraResult<()> {
    let meta = vault.load_profile_meta(profile_id)?;
    println!("{}", serde_json::to_string_pretty(&meta)?);
    Ok(())
}

async fn rotate(vault: &Vault, home: &Path, args: RotateArgs) -> KvendraResult<()> {
    ensure_unlocked(vault, home, args.password_stdin)?;
    let plaintext = read_secret(args.secret_env.as_deref(), args.secret_file.as_ref())?;
    vault.put_secret(&args.profile_id, &plaintext)?;
    println!("Profile '{}' rotated.", args.profile_id);
    Ok(())
}

fn revoke(vault: &Vault, profile_id: &str) -> KvendraResult<()> {
    vault.delete_profile(profile_id)?;
    println!("Profile '{profile_id}' revoked.");
    Ok(())
}

fn set_allowlist(vault: &Vault, home: &Path, args: SetAllowlistArgs) -> KvendraResult<()> {
    // REQ-KVD-007 / ISSUE-018 — `set-allowlist` persists an HMAC of the YAML
    // signed with the `kvendra/allowlist-hmac/v1` HKDF sub-key. The sub-key
    // only exists while the session is unlocked, so we must unlock here even
    // if the caller assumed locked-vault semantics from prior releases.
    ensure_unlocked(vault, home, args.password_stdin)?;

    let raw = std::fs::read_to_string(&args.file)?;
    let spec: ProfileSpec = serde_yml::from_str(&raw)?;
    if spec.profile_id != args.profile_id {
        return Err(KvendraError::AllowlistParse(format!(
            "allowlist profile_id '{}' does not match argument '{}'",
            spec.profile_id, args.profile_id
        )));
    }
    allowlist_validate(&spec)?;
    crate::config::create_dir_secure(&vault.allowlists_dir())?;
    let target = vault.profile_allowlist_path(&args.profile_id);
    std::fs::write(&target, &raw)?;
    crate::config::set_file_mode_secure(&target)?;

    // REQ-KVD-007 / ISSUE-018: persist HMAC of the YAML so the runtime can
    // detect tampering. Requires the vault to be unlocked.
    let key = vault.allowlist_hmac_key()?;
    let hmac_hex = crate::vault::compute_allowlist_hmac(&key, raw.as_bytes());
    let mut profile = vault.load_profile_meta(&args.profile_id)?;
    profile.allowlist_hmac_hex = Some(hmac_hex);
    vault.save_profile_meta(&profile)?;

    println!("Allowlist for '{}' set (HMAC persisted).", args.profile_id);
    Ok(())
}

fn validate_cmd(vault: &Vault, args: ValidateArgs) -> KvendraResult<()> {
    let ids = if args.all {
        vault.list_profiles()?
    } else {
        match args.profile_id {
            Some(s) => vec![s],
            None => {
                return Err(KvendraError::InvalidArgs(
                    "pass <profile_id> or --all".into(),
                ));
            }
        }
    };
    let mut overall_ok = true;
    for id in ids {
        let ok = print_validation(vault, &id);
        if !ok {
            overall_ok = false;
        }
        println!();
    }
    if overall_ok {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

fn print_validation(vault: &Vault, profile_id: &str) -> bool {
    println!("Profile: {profile_id}");
    let meta = match vault.load_profile_meta(profile_id) {
        Ok(m) => m,
        Err(e) => {
            println!("Status: REJECTED");
            println!("Issues:");
            println!("  - {e}");
            return false;
        }
    };

    let allow_path = vault.profile_allowlist_path(profile_id);
    if !allow_path.exists() {
        println!("Status: REJECTED");
        println!("Issues:");
        println!("  - Allowlist YAML missing at {}", allow_path.display());
        println!("  - Use `kvendra secret set-allowlist {profile_id} --file <path>`");
        return false;
    }
    let raw = match std::fs::read_to_string(&allow_path) {
        Ok(s) => s,
        Err(e) => {
            println!("Status: REJECTED");
            println!("Issues:");
            println!("  - Cannot read allowlist: {e}");
            return false;
        }
    };
    let spec: ProfileSpec = match serde_yml::from_str(&raw) {
        Ok(s) => s,
        Err(e) => {
            println!("Status: REJECTED");
            println!("Issues:");
            println!("  - Allowlist YAML parse error: {e}");
            return false;
        }
    };

    let mut issues: Vec<String> = Vec::new();
    if let Err(e) = allowlist_validate(&spec) {
        issues.push(e.to_string());
    }
    if crate::allowlist::validator::is_expired(&spec) {
        issues.push(format!(
            "Expiration: {} — expired",
            spec.expiration.clone().unwrap_or_default()
        ));
    }
    if !["minimal", "standard", "full"].contains(&spec.audit_level.as_str()) {
        issues.push(format!(
            "audit_level '{}' must be one of: minimal, standard, full",
            spec.audit_level
        ));
    }

    if issues.is_empty() {
        println!("Status: VALID ✓");
        println!("Secret type: {}", meta.secret_type);
        println!("Allowlist:");
        for prim in &spec.allowlist.primitives {
            for op in &prim.operations {
                for (op_name, constraints) in op {
                    let suffix = format_constraints(constraints);
                    let mark = destructive_mark(&prim.name, op_name, constraints);
                    let line_body = if suffix.is_empty() {
                        format!("  - {}.{op_name}", prim.name)
                    } else {
                        format!("  - {}.{op_name} {suffix}", prim.name)
                    };
                    if mark.is_empty() {
                        println!("{line_body}");
                    } else {
                        println!("{line_body} {mark}");
                    }
                }
            }
            if prim.name == "kvendra.unsafe.raw_token" && prim.unsafe_raw_token_allowed {
                println!("  - {} (unsafe escape hatch)", prim.name);
            }
        }
        match &spec.expiration {
            Some(exp) => println!("Expiration: {}", format_expiration(exp)),
            None => println!("Expiration: (none — recommend setting one)"),
        }
        println!("Audit level: {}", spec.audit_level);
        if meta.unsafe_raw_token_enabled {
            println!("Unsafe escape hatch: ENABLED on profile metadata");
        }
        if meta.quarantined {
            println!("WARNING: profile is QUARANTINED (detection layer Block trigger)");
        }
        true
    } else {
        println!("Status: REJECTED ✗");
        println!("Issues:");
        for i in &issues {
            println!("  - {i}");
        }
        false
    }
}

/// Format an `OperationConstraints` for display next to its operation name.
/// Returns either an empty string (no constraints set) or a parenthesised
/// summary like `(repos: a, b) (refs: main)`. Lets the user see the actual
/// scope a profile was granted without having to inspect the YAML manually.
fn format_constraints(c: &crate::allowlist::OperationConstraints) -> String {
    fn list(label: &str, v: &Option<Vec<String>>) -> Option<String> {
        v.as_ref()
            .filter(|xs| !xs.is_empty())
            .map(|xs| format!("({label}: {})", xs.join(", ")))
    }
    fn flag(label: &str, v: Option<bool>) -> Option<String> {
        v.filter(|b| *b).map(|_| format!("({label})"))
    }
    [
        list("repos", &c.repos),
        list("refs", &c.refs),
        list("forbidden_args", &c.forbidden_args),
        list("tag_pattern", &c.tag_pattern),
        list("org", &c.org),
        list("repo", &c.repo),
        list("fields_allowed", &c.fields_allowed),
        list("forbidden_fields", &c.forbidden_fields),
        list("binaries", &c.binaries),
        list("env_vars_to_inject", &c.env_vars_to_inject),
        list(
            "forbidden_env_export_to_agent",
            &c.forbidden_env_export_to_agent,
        ),
        list("url_pattern_regex", &c.url_pattern_regex),
        list("methods", &c.methods),
        list("forbidden_methods", &c.forbidden_methods),
        list("buckets", &c.buckets),
        list("distributions", &c.distributions),
        list("functions", &c.functions),
        list("packages", &c.packages),
        list("projects", &c.projects),
        list("endpoints", &c.endpoints),
        c.cwd_pattern
            .as_ref()
            .map(|s| format!("(cwd_pattern: {s})")),
        flag("accept_broad_scope", c.accept_broad_scope),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ")
}

/// Render a `YYYY-MM-DD` expiration string with a `(N days remaining)` /
/// `(expires today)` / `(expired N days ago)` suffix when parseable.
/// Falls back to the raw string when parsing fails (defensive).
fn format_expiration(exp: &str) -> String {
    use time::Date;
    use time::macros::format_description;
    let fmt = format_description!("[year]-[month]-[day]");
    let Ok(date) = Date::parse(exp, &fmt) else {
        return exp.to_string();
    };
    let today = OffsetDateTime::now_utc().date();
    let days = (date - today).whole_days();
    match days.cmp(&0) {
        std::cmp::Ordering::Greater => format!("{exp} ({days} days remaining)"),
        std::cmp::Ordering::Equal => format!("{exp} (expires today)"),
        std::cmp::Ordering::Less => format!("{exp} (expired {} days ago)", -days),
    }
}

/// REQ-KVD-004 / ADR-KVD-019 — marca inline para `kvendra secret validate`.
/// Devuelve `""` si la operación no es destructive ni annotated.
fn destructive_mark(primitive: &str, op: &str, c: &OperationConstraints) -> &'static str {
    let canonical_destructive = catalog::could_be_destructive(primitive, op, c);
    let user_declared = c.destructive.unwrap_or(false);
    if canonical_destructive || user_declared {
        if c.accept_destructive.unwrap_or(false) {
            "[\u{26a0} DESTRUCTIVE \u{2014} owner accepted]"
        } else {
            // Defensivo: el validator habría rechazado el profile antes de
            // llegar aquí. Si el user fuerza load (e.g. test) lo señalamos.
            "[\u{26a0} DESTRUCTIVE \u{2014} MISSING accept_destructive]"
        }
    } else {
        let synthetic = catalog::constraints_to_args_value(c);
        if catalog::is_annotated(primitive, op, &synthetic) {
            "[\u{26a0} ANNOTATED]"
        } else {
            ""
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{destructive_mark, format_constraints, format_expiration};
    use crate::allowlist::OperationConstraints;
    use time::OffsetDateTime;

    #[test]
    fn format_constraints_empty_for_default() {
        let c = OperationConstraints::default();
        assert_eq!(format_constraints(&c), "");
    }

    #[test]
    fn format_constraints_renders_repos_and_refs() {
        let c = OperationConstraints {
            repos: Some(vec!["KvendraAI/kvendra-cli".into()]),
            refs: Some(vec!["main".into(), "feat/*".into()]),
            ..Default::default()
        };
        let s = format_constraints(&c);
        assert!(s.contains("(repos: KvendraAI/kvendra-cli)"), "got: {s}");
        assert!(s.contains("(refs: main, feat/*)"), "got: {s}");
    }

    #[test]
    fn format_expiration_includes_days_remaining_for_future() {
        let future = OffsetDateTime::now_utc().date() + time::Duration::days(29);
        let s = format!(
            "{:04}-{:02}-{:02}",
            future.year(),
            u8::from(future.month()),
            future.day()
        );
        let out = format_expiration(&s);
        assert!(out.contains("29 days remaining"), "got: {out}");
    }

    #[test]
    fn format_expiration_marks_expired_for_past() {
        let past = OffsetDateTime::now_utc().date() - time::Duration::days(5);
        let s = format!(
            "{:04}-{:02}-{:02}",
            past.year(),
            u8::from(past.month()),
            past.day()
        );
        let out = format_expiration(&s);
        assert!(out.contains("expired 5 days ago"), "got: {out}");
    }

    #[test]
    fn format_expiration_falls_back_for_unparseable() {
        assert_eq!(format_expiration("not-a-date"), "not-a-date");
    }

    #[test]
    fn destructive_mark_destructive_with_opt_in() {
        let c = OperationConstraints {
            accept_destructive: Some(true),
            ..Default::default()
        };
        let mark = destructive_mark("kvendra.aws", "lambda_invoke", &c);
        assert!(mark.contains("DESTRUCTIVE"), "got: {mark}");
        assert!(mark.contains("owner accepted"), "got: {mark}");
    }

    #[test]
    fn destructive_mark_destructive_without_opt_in_is_defensive() {
        let c = OperationConstraints::default();
        let mark = destructive_mark("kvendra.aws", "lambda_invoke", &c);
        assert!(mark.contains("MISSING accept_destructive"), "got: {mark}");
    }

    #[test]
    fn destructive_mark_annotated() {
        let c = OperationConstraints::default();
        let mark = destructive_mark("kvendra.aws", "cloudfront_invalidate", &c);
        assert_eq!(mark, "[\u{26a0} ANNOTATED]");
    }

    #[test]
    fn destructive_mark_safe_returns_empty() {
        let c = OperationConstraints::default();
        let mark = destructive_mark("kvendra.github", "read_repo", &c);
        assert_eq!(mark, "");
    }
}
