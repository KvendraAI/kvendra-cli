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
use std::path::PathBuf;

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

#[derive(Debug, Serialize)]
struct SessionView {
    mode: String,
    /// Local master session (REQ-KVD-CLI-011 / ADR-KVD-029). Independent
    /// from the workspace JWT below — both can be active at once.
    #[serde(skip_serializing_if = "Option::is_none")]
    local: Option<LocalSessionView>,
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
    let mut view = match sessions.len() {
        0 => SessionView {
            mode: "local".into(),
            local: None,
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

fn print_human(view: &SessionView, verbose: bool) {
    print_local_section(view.local.as_ref());
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
    println!("Mode: workspace");
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
