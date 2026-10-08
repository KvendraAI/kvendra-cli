//! `kvendra login [--workspace <id> | --pro]` — REQ-KVD-CLI-004 AC-RESOLVER-5
//! + REQ-KVD-CLI-005 AC-BACKUP-7.
//!
//! Three modes:
//!  - **standalone** (no flags): legacy vault unlock alias.
//!  - **workspace**: full OIDC PKCE flow against the IdP, persists a
//!    session token under `~/.kvendra/sessions/`, and runs the initial
//!    allowlist sync.
//!  - **pro** (M2.5 D8): OIDC PKCE flow without workspace_id; persists the
//!    raw JWT bearer to `~/.kvendra/sessions/pro.token` (mode 0600) for use
//!    by `kvendra backup {push,pull,list,restore,prune}`.

use crate::auth::discovery::{auth_base_from_env, discovery_url_from_env};
use crate::auth::oidc::{TokenSet, client_id_from_env, login_workspace};
use crate::auth::pro_refresh::{
    PRO_LOCK_ID, pro_access_path, pro_client_id_path, pro_id_token_path, pro_refresh_token_path,
    write_secret_atomic,
};
use crate::config::kvendra_home;
use crate::error::{KvendraError, KvendraResult};
use crate::session::SessionState;
use chrono::Utc;
use clap::Args;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Switch to workspace mode and start an OIDC PKCE flow against the
    /// IdP (KVENDRA_AUTH_URL, default https://auth.kvendra.cloud).
    #[arg(long, conflicts_with = "pro")]
    pub workspace: Option<String>,

    /// Authenticate as a Pro tier user (no workspace) for `kvendra backup`.
    /// Persists the bearer JWT to `~/.kvendra/sessions/pro.token` (mode 0600).
    #[arg(long, conflicts_with = "workspace")]
    pub pro: bool,
}

pub async fn run(args: LoginArgs) -> KvendraResult<()> {
    match (args.workspace, args.pro) {
        (None, false) => standalone_hint(),
        (Some(ws_id), false) => workspace_login(&ws_id).await,
        (None, true) => pro_login().await,
        (Some(_), true) => Err(KvendraError::InvalidArgs(
            "--workspace and --pro are mutually exclusive".into(),
        )),
    }
}

fn standalone_hint() -> KvendraResult<()> {
    eprintln!(
        "Standalone login is the existing `kvendra unlock` subcommand.\n\
         For workspace mode, run `kvendra login --workspace <id>`.\n\
         For Pro tier (cloud backup), run `kvendra login --pro`."
    );
    Ok(())
}

async fn workspace_login(workspace_id: &str) -> KvendraResult<()> {
    let home = kvendra_home()?;
    let discovery_url = discovery_url_from_env()?;
    let auth_base = auth_base_from_env()?;
    let client_id = client_id_from_env();

    eprintln!("Starting workspace login for '{workspace_id}'...");
    let token_set = login_workspace(workspace_id, &discovery_url, &client_id).await?;
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

/// `kvendra login --pro` — REQ-KVD-CLI-005 AC-BACKUP-7.
///
/// Pro tier does not bind to a workspace. The OIDC PKCE flow uses the
/// canonical IdP (KVENDRA_AUTH_URL) but persists only the raw `access_token`
/// at `~/.kvendra/sessions/pro.token` (plain text, mode 0600). `kvendra
/// backup` reads that file directly via [`backup::load_pro_jwt`].
///
/// The `refresh_token` is persisted at `~/.kvendra/sessions/pro.refresh_token`
/// (mode 0600); `kvendra backup` and `kvendra notifs` refresh the access and
/// id tokens before each call via [`crate::auth::pro_refresh`].
async fn pro_login() -> KvendraResult<()> {
    let home = kvendra_home()?;
    let discovery_url = discovery_url_from_env()?;
    let client_id = client_id_from_env();

    eprintln!("Starting Pro tier login (cloud backup)...");
    // We reuse `login_workspace` because the PKCE flow itself is
    // workspace-agnostic — the workspace_id param is currently unused inside
    // `login_workspace` (verified in oidc.rs:93). Passing "pro" as a label
    // makes the loopback success page slightly clearer in logs.
    let token_set = login_workspace("pro", &discovery_url, &client_id).await?;
    eprintln!("Authorization code exchanged successfully.");

    let path = persist_pro_tokens(&home, &client_id, &token_set)?;
    eprintln!(
        "Pro session JWT persisted at {} (mode 0600).",
        path.display()
    );

    // Persist also the id_token for UX display (email + profile claims).
    // OIDC by-design: `access_token` is opaque to clients and carries no
    // user claims; `id_token` carries `email`, `name`, `sub`, etc. Backup
    // endpoints continue to use `pro.token` (access_token) as the bearer.
    // Fix for ISSUE-KVD-CLI-940018 — `session info` rendered `email: None`
    // because it decoded the access_token instead of the id_token.

    // Structured log for UX-quality observability (ISSUE-KVD-CLI-9AE300).
    // Claims are untrusted at this point — the IdP signed them and the broker
    // re-validates on every API call; we use them only to surface flag, email,
    // issuer and expires_at to operators tailing the trace. Use the id_token
    // because access_token has no `email` claim (OIDC by-design).
    let claims = decode_jwt_payload(&token_set.id_token).unwrap_or_default();
    let expires_at = claims
        .exp
        .and_then(|ts| chrono::DateTime::<Utc>::from_timestamp(ts, 0))
        .map(|d| d.to_rfc3339())
        .unwrap_or_else(|| "unknown".into());
    tracing::info!(
        target: "kvendra::login",
        flag = "pro_login_succeeded",
        email = claims.email.as_deref().unwrap_or("unknown"),
        issuer = claims.iss.as_deref().unwrap_or("unknown"),
        expires_at = %expires_at,
        "Pro tier login completed"
    );
    Ok(())
}

/// Persist the Pro session files (`pro.client_id`, `pro.refresh_token`,
/// `pro.token`, `pro.id_token`) atomically with mode 0600, under the same
/// `pro` lock as the refresh path. Returns the access-token path. A
/// response without `refresh_token` removes any stale one so the refresh
/// path never pairs it with the new tokens.
fn persist_pro_tokens(
    home: &Path,
    client_id: &str,
    token_set: &TokenSet,
) -> KvendraResult<PathBuf> {
    let _guard = SessionState::acquire_lock(home, PRO_LOCK_ID)?;
    write_secret_atomic(&pro_client_id_path(home), client_id.as_bytes())?;
    let refresh_path = pro_refresh_token_path(home);
    if token_set.refresh_token.is_empty() {
        let _ = std::fs::remove_file(&refresh_path);
    } else {
        write_secret_atomic(&refresh_path, token_set.refresh_token.as_bytes())?;
    }
    let path = pro_access_path(home);
    write_secret_atomic(&path, token_set.access_token.as_bytes())?;
    write_secret_atomic(&pro_id_token_path(home), token_set.id_token.as_bytes())?;
    Ok(path)
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
pub(crate) struct JwtClaims {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub iss: Option<String>,
    /// Standard `exp` (Unix epoch seconds). Used by `session info` to render
    /// "expires in N minutes" for the Pro tier section.
    #[serde(default)]
    pub exp: Option<i64>,
    /// Custom claim namespaced under `kvendra:tenant_id`. Present when the
    /// IdP emits the canonical workspace claims (see GLO-013/014).
    #[serde(default, rename = "kvendra:tenant_id")]
    pub kvendra_tenant_id: Option<String>,
}

impl JwtClaims {
    pub(crate) fn tenant_id_hint(&self) -> Option<String> {
        self.kvendra_tenant_id.clone()
    }
}

/// Decode the `payload` segment of a compact JWT (`header.payload.sig`).
/// Returns `None` on any parse error. We intentionally do NOT verify the
/// signature here — the IdP did that already, and the broker re-validates
/// on every API call. We just want the email + sub for UX.
pub(crate) fn decode_jwt_payload(jwt: &str) -> Option<JwtClaims> {
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

    /// Regression for BUG-A (ISSUE-KVD-CLI-170F9D) — `exp` is now decoded so
    /// that `session info` and the `pro_login` tracing emit can surface the
    /// JWT expiry to operators. Format: RFC3339 from Unix epoch seconds.
    #[test]
    fn decodes_exp_claim_and_formats_rfc3339() {
        // Use a known epoch: 2024-01-15T00:00:00Z = 1705276800.
        let exp_ts: i64 = 1_705_276_800;
        let jwt = make_jwt(serde_json::json!({
            "email": "pro@kvendra.cloud",
            "iss":   "https://auth.kvendra.cloud",
            "exp":   exp_ts,
        }));
        let claims = decode_jwt_payload(&jwt).unwrap();
        assert_eq!(claims.exp, Some(exp_ts));
        let formatted = claims
            .exp
            .and_then(|ts| chrono::DateTime::<Utc>::from_timestamp(ts, 0))
            .map(|d| d.to_rfc3339())
            .unwrap();
        // RFC3339 from chrono ends in `+00:00` for UTC.
        assert_eq!(
            formatted, "2024-01-15T00:00:00+00:00",
            "unexpected rfc3339: {formatted}"
        );
    }

    #[test]
    fn returns_none_on_garbage() {
        // A single bare token has no dots → returns None.
        assert!(decode_jwt_payload("totally-broken").is_none());
        // Two parts with invalid base64 in the payload also returns None.
        assert!(decode_jwt_payload("aaa.!!!.ccc").is_none());
    }

    #[test]
    fn persist_pro_tokens_writes_session_files_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let ts = TokenSet {
            access_token: "at".into(),
            id_token: "idt".into(),
            refresh_token: "rt".into(),
            expires_in: 3600,
            token_type: "Bearer".into(),
        };
        let p = persist_pro_tokens(dir.path(), "cid-v2", &ts).unwrap();
        assert_eq!(p, pro_access_path(dir.path()));
        for (path, want) in [
            (pro_access_path(dir.path()), "at"),
            (pro_id_token_path(dir.path()), "idt"),
            (pro_refresh_token_path(dir.path()), "rt"),
            (pro_client_id_path(dir.path()), "cid-v2"),
        ] {
            assert_eq!(std::fs::read_to_string(&path).unwrap(), want);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "{}", path.display());
            }
        }
    }

    #[test]
    fn login_args_pro_and_workspace_conflict() {
        use clap::Parser;
        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            args: LoginArgs,
        }
        let r = Cli::try_parse_from(["kvendra", "--workspace", "acme/frontend", "--pro"]);
        assert!(r.is_err(), "expected --workspace + --pro to conflict");
    }
}
