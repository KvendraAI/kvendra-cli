//! `kvendra session info [-v] [--json]` — REQ-KVD-CLI-004 AC-RESOLVER-5,
//! REQ-KVD-CLI-008 AC-JWT-3.

use crate::auth::discovery::DEFAULT_AUTH_BASE;
use crate::config::kvendra_home;
use crate::error::KvendraResult;
use crate::session::local::status as local_session_status;
use crate::session::{SessionState, list_active_sessions};
use chrono::{DateTime, Utc};
use clap::Args;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Args)]
pub struct SessionInfoArgs {
    /// Verbose output — adds refresh_token_expires_at, audience,
    /// last_token_refresh_at, last_allowlist_sync_at, broker_url, auth_url.
    #[arg(short, long)]
    pub verbose: bool,
    /// Machine-readable JSON output (parseable by E2E tests).
    #[arg(long)]
    pub json: bool,
}

/// Local master session view (REQ-KVD-CLI-011). Reports whether the
/// `~/.kvendra/sessions/active.blob` is valid for the current machine.
#[derive(Debug, Clone, Serialize)]
struct LocalSessionView {
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blob_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seconds_until_expiry: Option<i64>,
}

/// Pro tier session view (REQ-KVD-CLI-005 AC-BACKUP-7). Reports presence of
/// `~/.kvendra/sessions/pro.token` plus a best-effort decode of the JWT
/// claims for UX (BUG-A / ISSUE-KVD-CLI-170F9D — previously `session info`
/// rendered "Free tier" even when a valid pro.token existed).
#[derive(Debug, Clone, Serialize)]
struct ProSessionView {
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seconds_until_expiry: Option<i64>,
    blob_path: PathBuf,
}

#[derive(Debug, Serialize)]
struct SessionView {
    mode: String,
    /// Local master session (REQ-KVD-CLI-011 / ADR-KVD-029). Independent
    /// from the workspace JWT below — both can be active at once.
    #[serde(skip_serializing_if = "Option::is_none")]
    local: Option<LocalSessionView>,
    /// Pro tier JWT session (REQ-KVD-CLI-005). Independent from `local`
    /// and `workspace_id` — `pro.token` can coexist with either; the `mode`
    /// field decides which one is primary for human rendering.
    #[serde(skip_serializing_if = "Option::is_none")]
    pro: Option<ProSessionView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    member_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    member_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwt_expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seconds_until_expiry: Option<i64>,
    // Verbose-only fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token_expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_token_refresh_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_allowlist_sync_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    broker_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_url: Option<String>,
}

pub async fn run(args: SessionInfoArgs) -> KvendraResult<()> {
    let home = kvendra_home()?;
    let sessions = list_active_sessions(&home)?;
    let local_view = read_local_view(&home);
    let pro_view = read_pro_view(&home);
    let mut view = match sessions.len() {
        0 => SessionView {
            // BUG-A (ISSUE-KVD-CLI-170F9D): when only pro.token exists
            // we render "Mode: pro" instead of misleading "Free tier".
            mode: if pro_view.is_some() { "pro".into() } else { "local".into() },
            local: None,
            pro: None,
            workspace_id: None,
            tenant_id: None,
            member_id: None,
            member_email: None,
            jwt_expires_at: None,
            seconds_until_expiry: None,
            refresh_token_expires_at: None,
            issuer: None,
            audience: None,
            last_token_refresh_at: None,
            last_allowlist_sync_at: None,
            broker_url: if args.verbose {
                Some(
                    std::env::var("KVENDRA_BROKER_URL")
                        .unwrap_or_else(|_| crate::workspace::client::DEFAULT_BROKER_BASE.into()),
                )
            } else {
                None
            },
            auth_url: if args.verbose {
                Some(std::env::var("KVENDRA_AUTH_URL").unwrap_or_else(|_| DEFAULT_AUTH_BASE.into()))
            } else {
                None
            },
        },
        1 => {
            let ws_id = &sessions[0];
            let state = SessionState::load(&home, ws_id)?.expect("present, just listed");
            build_workspace_view(state, args.verbose)
        }
        _ => {
            // Multi-session — show the one pointed to by env var, or first one.
            let pick = std::env::var("KVENDRA_ACTIVE_WORKSPACE")
                .ok()
                .filter(|p| sessions.contains(p))
                .unwrap_or_else(|| sessions[0].clone());
            let state = SessionState::load(&home, &pick)?.expect("present, just listed");
            build_workspace_view(state, args.verbose)
        }
    };

    view.local = local_view.clone();
    view.pro = pro_view.clone();

    if args.json {
        // JSON output is machine-readable and always carries the full
        // payload — the caller filters fields, not us. Build a verbose
        // view regardless of the `-v` flag.
        let mut full = match sessions.len() {
            0 => SessionView {
                broker_url: Some(
                    std::env::var("KVENDRA_BROKER_URL")
                        .unwrap_or_else(|_| crate::workspace::client::DEFAULT_BROKER_BASE.into()),
                ),
                auth_url: Some(
                    std::env::var("KVENDRA_AUTH_URL").unwrap_or_else(|_| DEFAULT_AUTH_BASE.into()),
                ),
                ..view
            },
            _ => {
                let pick = std::env::var("KVENDRA_ACTIVE_WORKSPACE")
                    .ok()
                    .filter(|p| sessions.contains(p))
                    .unwrap_or_else(|| sessions[0].clone());
                let state = SessionState::load(&home, &pick)?.expect("present, just listed");
                build_workspace_view(state, true)
            }
        };
        full.local = local_view;
        full.pro = pro_view;
        println!("{}", serde_json::to_string_pretty(&full)?);
    } else {
        print_human(&view, args.verbose);
    }
    Ok(())
}

fn print_local_section(local: Option<&LocalSessionView>) {
    match local {
        Some(l) if l.active => {
            println!("Local session: active");
            if let Some(t) = l.created_at {
                println!("  Created: {}", t.format("%Y-%m-%d %H:%M:%S UTC"));
            }
            if let Some(t) = l.expires_at {
                let mins = l.seconds_until_expiry.unwrap_or(0).max(0) / 60;
                println!(
                    "  Expires: {} (in {} minutes)",
                    t.format("%Y-%m-%d %H:%M:%S UTC"),
                    mins
                );
            }
            if let Some(p) = &l.blob_path {
                println!("  Blob:    {}", p.display());
            }
            println!();
        }
        _ => {
            println!("Local session: inactive (run `kvendra unlock` in a terminal)");
            println!();
        }
    }
}

/// Read the Pro tier token from `~/.kvendra/sessions/pro.token` (if any)
/// and best-effort decode the JWT for UX rendering. The signature is NOT
/// verified — the broker re-validates on every call. Returns `None` when
/// the file does not exist, unreadable, or is not a parseable 3-segment
/// JWT (in which case we still want to surface that *something* is there;
/// but absent a parseable payload we conservatively return `None` so the
/// caller falls back to "local" mode and the operator re-runs
/// `kvendra login --pro`).
fn read_pro_view(home: &Path) -> Option<ProSessionView> {
    let access_path = home.join("sessions/pro.token");
    if !access_path.is_file() {
        return None;
    }
    // Prefer `pro.id_token` for UX claims (email, issuer, exp). OIDC
    // by-design: the access_token is opaque to clients and carries no
    // user claims; only the id_token has `email`, `name`, `sub`, etc.
    // Fall back to `pro.token` for backwards compat with installs from
    // before 0.4.0-alpha.4 that persisted only the access_token. Fix
    // for ISSUE-KVD-CLI-940018.
    let id_path = home.join("sessions/pro.id_token");
    let jwt_for_claims = if id_path.is_file() {
        std::fs::read_to_string(&id_path).ok()
    } else {
        std::fs::read_to_string(&access_path).ok()
    };
    let claims = jwt_for_claims
        .as_deref()
        .and_then(|s| crate::cli::login::decode_jwt_payload(s.trim()))
        .unwrap_or_default();
    let expires_at = claims
        .exp
        .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0));
    let seconds_until_expiry = expires_at.map(|e| (e - Utc::now()).num_seconds());
    Some(ProSessionView {
        active: true,
        email: claims.email,
        issuer: claims.iss,
        expires_at,
        seconds_until_expiry,
        // User-visible "Token:" path points to the access_token because that
        // is the file consumed by `kvendra backup *` (bearer JWT).
        blob_path: access_path,
    })
}

/// Read the local-session status into a serialisable view. Returns `None`
/// when there is no active session — keeps `kvendra session status` quiet
/// for fresh installs.
fn read_local_view(home: &std::path::Path) -> Option<LocalSessionView> {
    let s = local_session_status(home);
    if !s.active {
        return None;
    }
    let seconds_until_expiry = s.expires_at.map(|e| (e - Utc::now()).num_seconds());
    Some(LocalSessionView {
        active: true,
        expires_at: s.expires_at,
        created_at: s.created_at,
        ttl_seconds: s.ttl_seconds,
        blob_path: s.blob_path,
        seconds_until_expiry,
    })
}

fn build_workspace_view(state: SessionState, verbose: bool) -> SessionView {
    let now = Utc::now();
    let seconds_until_expiry = (state.jwt_expires_at - now).num_seconds();
    let auth_url = std::env::var("KVENDRA_AUTH_URL").unwrap_or_else(|_| DEFAULT_AUTH_BASE.into());
    let broker_url = std::env::var("KVENDRA_BROKER_URL")
        .unwrap_or_else(|_| crate::workspace::client::DEFAULT_BROKER_BASE.into());
    SessionView {
        mode: "workspace".into(),
        local: None,
        pro: None,
        workspace_id: Some(state.workspace_id),
        tenant_id: Some(state.tenant_id),
        member_id: Some(state.member_id),
        member_email: Some(state.member_email),
        jwt_expires_at: Some(state.jwt_expires_at),
        seconds_until_expiry: Some(seconds_until_expiry),
        refresh_token_expires_at: if verbose {
            state.refresh_token_expires_at
        } else {
            None
        },
        issuer: if verbose { Some(state.issuer) } else { None },
        audience: if verbose { Some(state.audience) } else { None },
        last_token_refresh_at: if verbose {
            Some(state.last_refresh_at)
        } else {
            None
        },
        last_allowlist_sync_at: if verbose {
            state.last_allowlist_sync_at
        } else {
            None
        },
        broker_url: if verbose { Some(broker_url) } else { None },
        auth_url: if verbose { Some(auth_url) } else { None },
    }
}

fn print_pro_section(pro: Option<&ProSessionView>) {
    if let Some(p) = pro {
        println!("Pro session: active");
        if let Some(e) = &p.email {
            println!("  Email:   {e}");
        }
        if let Some(t) = p.expires_at {
            let mins = p.seconds_until_expiry.unwrap_or(0).max(0) / 60;
            println!(
                "  Expires: {} (in {} minutes)",
                t.format("%Y-%m-%d %H:%M:%S UTC"),
                mins
            );
        }
        if let Some(i) = &p.issuer {
            println!("  Issuer:  {i}");
        }
        println!("  Token:   {}", p.blob_path.display());
        println!();
    }
}

fn print_human(view: &SessionView, verbose: bool) {
    print_local_section(view.local.as_ref());
    print_pro_section(view.pro.as_ref());
    if view.mode == "local" {
        println!("Mode: local (Free tier)");
        if verbose {
            if let Some(b) = &view.broker_url {
                println!("Broker URL: {b}");
            }
            if let Some(a) = &view.auth_url {
                println!("Auth URL: {a}");
            }
        }
        return;
    }
    if view.mode == "pro" {
        println!("Mode: pro (cloud backup)");
        if verbose {
            if let Some(b) = &view.broker_url {
                println!("Broker URL: {b}");
            }
            if let Some(a) = &view.auth_url {
                println!("Auth URL: {a}");
            }
        }
        return;
    }
    println!("Mode: workspace");
    if view.pro.is_some() {
        println!("(Pro session also active — see section above.)");
    }
    if let Some(w) = &view.workspace_id {
        println!("Workspace: {w}");
    }
    if verbose {
        if let Some(t) = &view.tenant_id {
            println!("Tenant: {t}");
        }
    }
    if let Some(e) = &view.member_email {
        println!("Member: {e}");
    }
    if verbose {
        if let Some(id) = &view.member_id {
            println!("Member id: {id}");
        }
    }
    if let Some(t) = view.jwt_expires_at {
        let secs = view.seconds_until_expiry.unwrap_or(0);
        let mins = secs.max(0) / 60;
        println!("JWT expires at: {t} ({mins} minutes from now)");
    }
    if verbose {
        if let Some(t) = view.refresh_token_expires_at {
            println!("Refresh token expires at: {t}");
        }
        if let Some(t) = view.last_token_refresh_at {
            println!("Last token refresh: {t}");
        }
        if let Some(t) = view.last_allowlist_sync_at {
            println!("Last allowlist sync: {t}");
        }
        if let Some(i) = &view.issuer {
            println!("Issuer: {i}");
        }
        if let Some(a) = &view.audience {
            println!("Audience (client_id): {a}");
        }
        if let Some(b) = &view.broker_url {
            println!("Broker URL: {b}");
        }
        if let Some(a) = &view.auth_url {
            println!("Auth URL: {a}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
    use tempfile::tempdir;

    fn make_jwt(payload: serde_json::Value) -> String {
        let header = B64URL.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let body = B64URL.encode(payload.to_string().as_bytes());
        let sig = B64URL.encode(b"sig");
        format!("{header}.{body}.{sig}")
    }

    /// Regression for BUG-A (ISSUE-KVD-CLI-170F9D): `read_pro_view` must
    /// return a populated view when `~/.kvendra/sessions/pro.token` is
    /// present and the JWT carries email/iss/exp claims.
    #[test]
    fn read_pro_view_returns_some_when_pro_token_exists() {
        let home = tempdir().unwrap();
        let sessions = home.path().join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        // exp ~24h in the future so seconds_until_expiry is positive.
        let exp = (Utc::now() + chrono::Duration::hours(24)).timestamp();
        let jwt = make_jwt(serde_json::json!({
            "email": "pro@kvendra.cloud",
            "iss":   "https://auth.kvendra.cloud",
            "exp":   exp,
        }));
        std::fs::write(sessions.join("pro.token"), jwt.as_bytes()).unwrap();

        let view = read_pro_view(home.path()).expect("must find pro.token");
        assert!(view.active);
        assert_eq!(view.email.as_deref(), Some("pro@kvendra.cloud"));
        assert_eq!(view.issuer.as_deref(), Some("https://auth.kvendra.cloud"));
        assert!(view.expires_at.is_some(), "exp must decode");
        let secs = view.seconds_until_expiry.unwrap();
        assert!(
            (23 * 3600..=25 * 3600).contains(&secs),
            "expected ~24h, got {secs}"
        );
        assert!(view.blob_path.ends_with("sessions/pro.token"));
    }

    /// Negative: no pro.token → `None`. Keeps the "Free tier" rendering
    /// for fresh installs (BUG-A coexistence with the Free tier UX).
    #[test]
    fn read_pro_view_returns_none_when_no_pro_token() {
        let home = tempdir().unwrap();
        assert!(read_pro_view(home.path()).is_none());
    }

    /// Defensive: pro.token with garbled JWT still returns `Some` with
    /// `active:true` and empty claims, because the file's existence is
    /// the source of truth for "Pro session present" — claims are
    /// best-effort UX only.
    #[test]
    fn read_pro_view_returns_some_with_empty_claims_when_jwt_unparseable() {
        let home = tempdir().unwrap();
        let sessions = home.path().join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        std::fs::write(sessions.join("pro.token"), b"not-a-jwt").unwrap();
        let view = read_pro_view(home.path()).expect("file exists → Some");
        assert!(view.active);
        assert!(view.email.is_none());
        assert!(view.issuer.is_none());
        assert!(view.expires_at.is_none());
    }

    /// Regression for ISSUE-KVD-CLI-940018: when both `pro.token` (access
    /// token, opaque, no claims) and `pro.id_token` (claims-carrying) are
    /// present, `read_pro_view` MUST decode email/issuer/exp from the
    /// id_token, not from the access_token. OIDC by-design: access_token
    /// carries no `email` claim.
    #[test]
    fn read_pro_view_prefers_id_token_for_email() {
        let home = tempdir().unwrap();
        let sessions = home.path().join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        // access_token: NO email claim (mimics Cognito opaque access_token).
        let access_jwt = make_jwt(serde_json::json!({
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "iss": "https://auth.kvendra.cloud",
            "token_use": "access",
        }));
        // id_token: carries the email claim.
        let exp = (Utc::now() + chrono::Duration::hours(24)).timestamp();
        let id_jwt = make_jwt(serde_json::json!({
            "email": "owner@kvendra.cloud",
            "sub":   "550e8400-e29b-41d4-a716-446655440000",
            "iss":   "https://auth.kvendra.cloud",
            "exp":   exp,
            "token_use": "id",
        }));
        std::fs::write(sessions.join("pro.token"), access_jwt.as_bytes()).unwrap();
        std::fs::write(sessions.join("pro.id_token"), id_jwt.as_bytes()).unwrap();

        let view = read_pro_view(home.path()).expect("must find pro.token");
        assert!(view.active);
        assert_eq!(
            view.email.as_deref(),
            Some("owner@kvendra.cloud"),
            "email MUST be sourced from id_token, not access_token"
        );
        assert_eq!(view.issuer.as_deref(), Some("https://auth.kvendra.cloud"));
        assert!(
            view.expires_at.is_some(),
            "exp must decode from id_token"
        );
        // blob_path stays pointing to pro.token (the backup-consumed bearer).
        assert!(view.blob_path.ends_with("sessions/pro.token"));
    }

    /// Regression for ISSUE-KVD-CLI-940018 backwards-compat path: installs
    /// that pre-date 0.4.0-alpha.4 only have `pro.token` (access_token);
    /// no `pro.id_token` sidecar. `read_pro_view` must still return a view
    /// without crashing — claims fall back to whatever the access_token
    /// happens to expose (usually nothing useful, hence the email shows
    /// as None until the operator re-runs `kvendra login --pro`).
    #[test]
    fn read_pro_view_falls_back_to_access_token_when_no_id_token() {
        let home = tempdir().unwrap();
        let sessions = home.path().join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        // Cognito-shaped access_token: no email claim.
        let access_jwt = make_jwt(serde_json::json!({
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "iss": "https://auth.kvendra.cloud",
            "token_use": "access",
        }));
        std::fs::write(sessions.join("pro.token"), access_jwt.as_bytes()).unwrap();

        let view = read_pro_view(home.path()).expect("file exists → Some");
        assert!(view.active);
        assert!(
            view.email.is_none(),
            "no id_token sidecar AND access_token has no email → None (expected pre-fix behaviour)"
        );
        assert_eq!(view.issuer.as_deref(), Some("https://auth.kvendra.cloud"));
        assert!(view.blob_path.ends_with("sessions/pro.token"));
    }
}
