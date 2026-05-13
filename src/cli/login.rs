//! `kvendra login [--workspace <id>]` — REQ-KVD-CLI-004 AC-RESOLVER-5.
//!
//! Two modes:
//!  - **standalone** (no `--workspace`): legacy vault unlock. The subcommand
//!    is a thin alias around `kvendra unlock` that allows scripts to use a
//!    single verb regardless of the active tier.
//!  - **workspace**: full OIDC PKCE flow against the IdP, persists a
//!    session token under `~/.kvendra/sessions/`, and runs the initial
//!    allowlist sync so the next `mcp serve` starts hot.

use crate::auth::discovery::auth_base_from_env;
use crate::auth::oidc::{client_id_from_env, login_workspace};
use crate::config::kvendra_home;
use crate::error::KvendraResult;
use crate::session::SessionState;
use chrono::Utc;
use clap::Args;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Switch to workspace mode and start an OIDC PKCE flow against the
    /// IdP (KVENDRA_AUTH_URL, default https://auth.kvendra.cloud).
    #[arg(long)]
    pub workspace: Option<String>,
}

pub async fn run(args: LoginArgs) -> KvendraResult<()> {
    match args.workspace {
        None => standalone_hint(),
        Some(ws_id) => workspace_login(&ws_id).await,
    }
}

fn standalone_hint() -> KvendraResult<()> {
    eprintln!(
        "Standalone login is the existing `kvendra unlock` subcommand.\n\
         For workspace mode, run `kvendra login --workspace <id>`."
    );
    Ok(())
}

async fn workspace_login(workspace_id: &str) -> KvendraResult<()> {
    let home = kvendra_home()?;
    let auth_base = auth_base_from_env()?;
    let client_id = client_id_from_env();

    eprintln!("Starting workspace login for '{workspace_id}'...");
    let token_set = login_workspace(workspace_id, &auth_base, &client_id).await?;
    eprintln!("Authorization code exchanged successfully.");

    // Decode the id_token (or access_token) payload — we only need
    // `email`, `sub`, and the issuer. Parsing is best-effort; the server
    // owns the canonical claims.
    let claims = decode_jwt_payload(&token_set.id_token)
        .or_else(|| decode_jwt_payload(&token_set.access_token))
        .unwrap_or_default();

    let now = Utc::now();
    let session = SessionState::from_token_set(
        workspace_id,
        &claims.tenant_id_hint().unwrap_or_default(),
        &claims.sub.unwrap_or_default(),
        &claims.email.unwrap_or_else(|| "unknown".into()),
        &claims.iss.unwrap_or_else(|| auth_base.to_string()),
        &client_id,
        &token_set,
        None,
        now,
    );
    session.persist_atomic(&home)?;
    eprintln!(
        "Session token persisted at ~/.kvendra/sessions/{}.token (mode 0600).",
        SessionState::workspace_id_safe(workspace_id)
    );

    // Initial allowlist sync (best-effort).
    initial_allowlist_sync(&home, workspace_id, &token_set.access_token).await;

    eprintln!("Login successful. Next `kvendra mcp serve` will run in workspace mode.");
    Ok(())
}

async fn initial_allowlist_sync(home: &Path, workspace_id: &str, jwt: &str) {
    match crate::workspace::allowlist_sync::sync_once(home, workspace_id, jwt, true).await {
        Ok(report) => {
            eprintln!(
                "Allowlist sync: {} fetched, {} unchanged, {} failed.",
                report.fetched, report.not_modified, report.failed
            );
        }
        Err(e) => {
            tracing::warn!(
                target: "kvendra::login",
                workspace = %workspace_id,
                error = %e,
                "initial allowlist sync failed (non-fatal)"
            );
            eprintln!(
                "Warning: allowlist sync failed ({e}). The server will retry on `mcp serve`."
            );
        }
    }
}

/// Minimal JWT claims subset we read at login time. Untrusted — used only
/// for UX display.
#[derive(Debug, Default, Deserialize)]
struct JwtClaims {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub iss: Option<String>,
    /// Custom claim namespaced under `kvendra:tenant_id`. Present when the
    /// IdP emits the canonical workspace claims (see GLO-013/014).
    #[serde(default, rename = "kvendra:tenant_id")]
    pub kvendra_tenant_id: Option<String>,
}

impl JwtClaims {
    fn tenant_id_hint(&self) -> Option<String> {
        self.kvendra_tenant_id.clone()
    }
}

/// Decode the `payload` segment of a compact JWT (`header.payload.sig`).
/// Returns `None` on any parse error. We intentionally do NOT verify the
/// signature here — the IdP did that already, and the broker re-validates
/// on every API call. We just want the email + sub for UX.
fn decode_jwt_payload(jwt: &str) -> Option<JwtClaims> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
    let mut parts = jwt.split('.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    let raw = B64URL.decode(payload_b64).ok()?;
    serde_json::from_slice::<JwtClaims>(&raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};

    fn make_jwt(payload: serde_json::Value) -> String {
        let header = B64URL.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let body = B64URL.encode(payload.to_string().as_bytes());
        let sig = B64URL.encode(b"sig");
        format!("{header}.{body}.{sig}")
    }

    #[test]
    fn decodes_email_and_sub() {
        let jwt = make_jwt(serde_json::json!({
            "email": "bob@acme.com",
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "iss": "https://auth.kvendra.cloud",
        }));
        let claims = decode_jwt_payload(&jwt).unwrap();
        assert_eq!(claims.email.as_deref(), Some("bob@acme.com"));
        assert_eq!(
            claims.sub.as_deref(),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
        assert_eq!(claims.iss.as_deref(), Some("https://auth.kvendra.cloud"));
    }

    #[test]
    fn returns_none_on_garbage() {
        // A single bare token has no dots → returns None.
        assert!(decode_jwt_payload("totally-broken").is_none());
        // Two parts with invalid base64 in the payload also returns None.
        assert!(decode_jwt_payload("aaa.!!!.ccc").is_none());
    }
}
