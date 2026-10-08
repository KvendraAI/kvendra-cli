//! Proactive refresh of the Pro tier tokens (`kvendra login --pro`).
//!
//! Same algorithm as the workspace refresh in [`crate::auth::refresh`], over
//! the raw Pro files under `~/.kvendra/sessions/`:
//!  - `pro.token`         access_token (bearer for backup / notifs)
//!  - `pro.id_token`      id_token (`X-Id-Token` + UX claims)
//!  - `pro.refresh_token` refresh_token (never logged)
//!  - `pro.client_id`     OIDC client used at login (refresh uses the same)
//!
//! If the earliest `exp` of the access/id tokens is more than the refresh
//! lead away, nothing happens. Otherwise the cross-process flock is taken,
//! the files are re-read (a peer may have refreshed), and the refresh_token
//! is exchanged at the IdP. A rotated refresh_token is persisted first, then
//! the access and id tokens. If the IdP rejects the refresh_token
//! ([`is_invalid_grant`]) only `pro.refresh_token` is removed; the access and
//! id tokens stay until they expire. Any other failure is transient.

use crate::auth::discovery::{discover, discovery_url_from_env};
use crate::auth::oidc::{client_id_from_env, exchange_refresh_token, is_invalid_grant};
use crate::auth::refresh::{RefreshOutcome, refresh_lead};
use crate::cli::login::decode_jwt_payload;
use crate::config::set_file_mode_secure;
use crate::error::{KvendraError, KvendraResult};
use crate::session::SessionState;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use std::io::Write;
use std::path::{Path, PathBuf};
use url::Url;

/// Lock id used with [`SessionState::acquire_lock`] (`sessions/pro.token.lock`).
pub const PRO_LOCK_ID: &str = "pro";

/// Error message returned when the Pro session can no longer be renewed.
pub const PRO_SESSION_EXPIRED_MSG: &str = "ProSessionExpired: the Pro session has expired or was revoked — run `kvendra login --pro` again";

pub fn pro_access_path(home: &Path) -> PathBuf {
    home.join("sessions").join("pro.token")
}

pub fn pro_id_token_path(home: &Path) -> PathBuf {
    home.join("sessions").join("pro.id_token")
}

pub fn pro_refresh_token_path(home: &Path) -> PathBuf {
    home.join("sessions").join("pro.refresh_token")
}

pub fn pro_client_id_path(home: &Path) -> PathBuf {
    home.join("sessions").join("pro.client_id")
}

fn session_store_err(what: &str) -> impl Fn(std::io::Error) -> KvendraError + '_ {
    move |e| KvendraError::SessionStore(format!("{what}: {e}"))
}

/// Write a session secret atomically: a per-call random tmp file in the
/// same directory, created exclusively (`O_CREAT|O_EXCL`), without following
/// symlinks and with mode 0600 from creation; then `fsync`, `rename` and
/// `fsync` of the directory. The tmp file is removed on any error.
pub fn write_secret_atomic(path: &Path, contents: &[u8]) -> KvendraResult<()> {
    let dir = path
        .parent()
        .ok_or_else(|| KvendraError::SessionStore("secret path has no parent".into()))?;
    std::fs::create_dir_all(dir).map_err(session_store_err("mkdir sessions"))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("secret");
    let tmp_path = dir.join(format!(".{name}.tmp.{:016x}", rand::random::<u64>()));
    let result = write_tmp_and_rename(&tmp_path, path, contents);
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result?;
    set_file_mode_secure(path)?;
    #[cfg(unix)]
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(session_store_err("fsync sessions dir"))?;
    Ok(())
}

fn write_tmp_and_rename(tmp_path: &Path, path: &Path, contents: &[u8]) -> KvendraResult<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = opts.open(tmp_path).map_err(session_store_err("tmp open"))?;
    f.write_all(contents).map_err(session_store_err("write"))?;
    f.sync_all().map_err(session_store_err("fsync"))?;
    drop(f);
    std::fs::rename(tmp_path, path).map_err(session_store_err("rename"))
}

fn read_trimmed(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn jwt_exp(jwt: &str) -> Option<DateTime<Utc>> {
    decode_jwt_payload(jwt)
        .and_then(|c| c.exp)
        .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0))
}

/// Earliest `exp` among the persisted access and id tokens. `None` when
/// neither carries a decodable `exp`.
fn earliest_exp(home: &Path) -> Option<DateTime<Utc>> {
    [pro_access_path(home), pro_id_token_path(home)]
        .iter()
        .filter_map(|p| read_trimmed(p))
        .filter_map(|t| jwt_exp(&t))
        .min()
}

fn needs_refresh(home: &Path, now: DateTime<Utc>, lead: ChronoDuration) -> bool {
    match earliest_exp(home) {
        Some(exp) => exp - now <= lead,
        None => false,
    }
}

/// `true` when a refresh_token is persisted for the Pro session.
pub fn has_pro_refresh_token(home: &Path) -> bool {
    read_trimmed(&pro_refresh_token_path(home)).is_some()
}

/// Client id to refresh with: the one stored at login, or (sessions created
/// before it was stored) `KVENDRA_CLIENT_ID` / the default.
pub fn resolve_pro_client_id(home: &Path) -> String {
    read_trimmed(&pro_client_id_path(home)).unwrap_or_else(client_id_from_env)
}

/// Outcome when there is no refresh_token to use: an already expired token
/// is reported with the re-login message; otherwise the call goes on.
fn without_refresh_token(home: &Path) -> KvendraResult<RefreshOutcome> {
    match earliest_exp(home) {
        Some(exp) if exp <= Utc::now() => Err(KvendraError::Vault(PRO_SESSION_EXPIRED_MSG.into())),
        _ => Ok(RefreshOutcome::NotNeeded),
    }
}

/// Refresh the Pro tokens if they expire within the configured lead
/// (`KVENDRA_JWT_REFRESH_LEAD_SECONDS`, default 5 min). Sessions without
/// `pro.refresh_token` (older logins, or a rejected refresh_token) are not
/// refreshed; once their token has expired the re-login message is returned.
pub async fn ensure_fresh_pro_tokens(home: &Path) -> KvendraResult<RefreshOutcome> {
    if !needs_refresh(home, Utc::now(), refresh_lead()) {
        return Ok(RefreshOutcome::NotNeeded);
    }
    if !has_pro_refresh_token(home) {
        return without_refresh_token(home);
    }
    let discovery_url = discovery_url_from_env()?;
    let client_id = resolve_pro_client_id(home);
    refresh_pro_tokens_with(home, &discovery_url, &client_id, refresh_lead()).await
}

/// Called right before each Pro API call (backup, notifs). A rejected or
/// missing refresh_token with an expired token is fatal (actionable
/// re-login message); any other refresh failure (IdP unreachable, 5xx, ...)
/// is a warning and the call goes on with the current token.
pub async fn refresh_pro_before_call(home: &Path) -> KvendraResult<()> {
    match ensure_fresh_pro_tokens(home).await {
        Ok(_) => Ok(()),
        Err(KvendraError::Vault(m)) if m == PRO_SESSION_EXPIRED_MSG => Err(KvendraError::Vault(m)),
        Err(e) => {
            tracing::warn!(
                target: "kvendra::auth",
                error = %e,
                "Pro token refresh failed; continuing with the current token"
            );
            eprintln!(
                "Warning: Pro token refresh failed ({e}); continuing with the current token."
            );
            Ok(())
        }
    }
}

async fn refresh_pro_tokens_with(
    home: &Path,
    discovery_url: &Url,
    client_id: &str,
    lead: ChronoDuration,
) -> KvendraResult<RefreshOutcome> {
    if !needs_refresh(home, Utc::now(), lead) {
        return Ok(RefreshOutcome::NotNeeded);
    }

    let _guard = SessionState::acquire_lock(home, PRO_LOCK_ID)?;

    // Re-read disk: a peer may have refreshed while we were waiting.
    if !needs_refresh(home, Utc::now(), lead) {
        return Ok(RefreshOutcome::SkippedRefreshedByPeer);
    }
    let Some(refresh_token) = read_trimmed(&pro_refresh_token_path(home)) else {
        return without_refresh_token(home);
    };

    let oidc = discover(discovery_url).await?;
    let new_tokens = match exchange_refresh_token(&oidc, client_id, &refresh_token).await {
        Ok(t) => t,
        Err(KvendraError::OidcFlow(msg)) if is_invalid_grant(&msg) => {
            let _ = std::fs::remove_file(pro_refresh_token_path(home));
            return Err(KvendraError::Vault(PRO_SESSION_EXPIRED_MSG.into()));
        }
        Err(e) => return Err(e),
    };

    if !new_tokens.refresh_token.is_empty() && new_tokens.refresh_token != refresh_token {
        write_secret_atomic(
            &pro_refresh_token_path(home),
            new_tokens.refresh_token.as_bytes(),
        )?;
    }
    write_secret_atomic(&pro_access_path(home), new_tokens.access_token.as_bytes())?;
    if !new_tokens.id_token.is_empty() {
        write_secret_atomic(&pro_id_token_path(home), new_tokens.id_token.as_bytes())?;
    }
    tracing::info!(
        target: "kvendra::auth",
        flag = "pro_tokens_refreshed",
        "Pro session tokens refreshed"
    );
    Ok(RefreshOutcome::Refreshed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    fn make_jwt(exp: i64, marker: &str) -> String {
        let header = B64URL.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let body = B64URL.encode(
            serde_json::json!({ "exp": exp, "iss": "https://idp.test", "m": marker })
                .to_string()
                .as_bytes(),
        );
        format!("{header}.{body}.{}", B64URL.encode(b"sig"))
    }

    fn seed(home: &Path, exp: i64, refresh: Option<&str>) {
        write_secret_atomic(&pro_access_path(home), make_jwt(exp, "old-at").as_bytes()).unwrap();
        write_secret_atomic(&pro_id_token_path(home), make_jwt(exp, "old-id").as_bytes()).unwrap();
        if let Some(rt) = refresh {
            write_secret_atomic(&pro_refresh_token_path(home), rt.as_bytes()).unwrap();
        }
    }

    /// Simulated IdP: discovery document + token endpoint. Records the form
    /// bodies posted to `/token` and answers with `token_status`/`token_body`.
    struct MockIdp {
        discovery: Url,
        token_calls: Arc<AtomicUsize>,
        token_forms: Arc<Mutex<Vec<String>>>,
    }

    fn spawn_idp(token_status: u16, token_body: String) -> MockIdp {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");
        let token_calls = Arc::new(AtomicUsize::new(0));
        let token_forms = Arc::new(Mutex::new(Vec::new()));
        let (calls, forms, base_t) = (token_calls.clone(), token_forms.clone(), base.clone());
        std::thread::spawn(move || {
            for mut req in server.incoming_requests() {
                let url = req.url().to_string();
                let json =
                    tiny_http::Header::from_bytes("content-type", "application/json").unwrap();
                if url.ends_with("openid-configuration") {
                    let doc = serde_json::json!({
                        "issuer": "https://idp.test",
                        "authorization_endpoint": format!("{base_t}/authorize"),
                        "token_endpoint": format!("{base_t}/token"),
                    });
                    let _ = req.respond(
                        tiny_http::Response::from_string(doc.to_string()).with_header(json),
                    );
                } else if url.starts_with("/token") {
                    let mut body = String::new();
                    let _ = req.as_reader().read_to_string(&mut body);
                    forms.lock().unwrap().push(body);
                    calls.fetch_add(1, Ordering::SeqCst);
                    let _ = req.respond(
                        tiny_http::Response::from_string(token_body.clone())
                            .with_status_code(token_status)
                            .with_header(json),
                    );
                } else {
                    let _ = req.respond(tiny_http::Response::empty(404));
                }
            }
        });
        MockIdp {
            discovery: Url::parse(&format!("{base}/.well-known/openid-configuration")).unwrap(),
            token_calls,
            token_forms,
        }
    }

    fn lead() -> ChronoDuration {
        ChronoDuration::minutes(5)
    }

    #[tokio::test]
    async fn no_refresh_when_tokens_have_margin() {
        let dir = tempfile::tempdir().unwrap();
        let exp = (Utc::now() + ChronoDuration::minutes(30)).timestamp();
        seed(dir.path(), exp, Some("rt-1"));
        let idp = spawn_idp(200, "{}".into());
        let r = refresh_pro_tokens_with(dir.path(), &idp.discovery, "cid", lead())
            .await
            .unwrap();
        assert_eq!(r, RefreshOutcome::NotNeeded);
        assert_eq!(idp.token_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn refreshes_and_persists_both_tokens_when_expiring_soon() {
        let dir = tempfile::tempdir().unwrap();
        let exp = (Utc::now() + ChronoDuration::minutes(2)).timestamp();
        seed(dir.path(), exp, Some("rt-1"));
        let new_exp = (Utc::now() + ChronoDuration::hours(1)).timestamp();
        let (new_at, new_id) = (make_jwt(new_exp, "new-at"), make_jwt(new_exp, "new-id"));
        // Cognito does not rotate the refresh_token: field absent.
        let body = serde_json::json!({
            "access_token": new_at, "id_token": new_id,
            "expires_in": 3600, "token_type": "Bearer"
        })
        .to_string();
        let idp = spawn_idp(200, body);

        let r = refresh_pro_tokens_with(dir.path(), &idp.discovery, "cid-v2", lead())
            .await
            .unwrap();
        assert_eq!(r, RefreshOutcome::Refreshed);
        assert_eq!(idp.token_calls.load(Ordering::SeqCst), 1);
        let form = idp.token_forms.lock().unwrap()[0].clone();
        assert!(form.contains("grant_type=refresh_token"), "{form}");
        assert!(form.contains("client_id=cid-v2"), "{form}");
        assert!(form.contains("refresh_token=rt-1"), "{form}");

        assert_eq!(read_trimmed(&pro_access_path(dir.path())).unwrap(), new_at);
        assert_eq!(
            read_trimmed(&pro_id_token_path(dir.path())).unwrap(),
            new_id
        );
        assert_eq!(
            read_trimmed(&pro_refresh_token_path(dir.path())).unwrap(),
            "rt-1",
            "refresh_token kept when the IdP does not rotate it"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for p in [
                pro_access_path(dir.path()),
                pro_id_token_path(dir.path()),
                pro_refresh_token_path(dir.path()),
            ] {
                let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "{}", p.display());
            }
        }
    }

    #[tokio::test]
    async fn rotated_refresh_token_is_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let exp = (Utc::now() - ChronoDuration::minutes(1)).timestamp();
        seed(dir.path(), exp, Some("rt-1"));
        let new_exp = (Utc::now() + ChronoDuration::hours(1)).timestamp();
        let body = serde_json::json!({
            "access_token": make_jwt(new_exp, "a"), "id_token": make_jwt(new_exp, "i"),
            "refresh_token": "rt-2", "expires_in": 3600
        })
        .to_string();
        let idp = spawn_idp(200, body);
        refresh_pro_tokens_with(dir.path(), &idp.discovery, "cid", lead())
            .await
            .unwrap();
        assert_eq!(
            read_trimmed(&pro_refresh_token_path(dir.path())).unwrap(),
            "rt-2"
        );
    }

    #[tokio::test]
    async fn rejection_removes_only_refresh_token() {
        let dir = tempfile::tempdir().unwrap();
        let exp = (Utc::now() + ChronoDuration::minutes(1)).timestamp();
        seed(dir.path(), exp, Some("rt-revoked"));
        let before_at = read_trimmed(&pro_access_path(dir.path())).unwrap();
        let before_id = read_trimmed(&pro_id_token_path(dir.path())).unwrap();
        let idp = spawn_idp(400, r#"{"error":"invalid_grant"}"#.into());

        let err = refresh_pro_tokens_with(dir.path(), &idp.discovery, "cid", lead())
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("kvendra login --pro"), "{msg}");
        assert!(!msg.contains("rt-revoked"), "refresh_token leaked: {msg}");
        assert!(!has_pro_refresh_token(dir.path()));
        assert_eq!(
            read_trimmed(&pro_access_path(dir.path())).unwrap(),
            before_at
        );
        assert_eq!(
            read_trimmed(&pro_id_token_path(dir.path())).unwrap(),
            before_id
        );

        // Token still valid → later calls go on without refresh.
        assert_eq!(
            ensure_fresh_pro_tokens(dir.path()).await.unwrap(),
            RefreshOutcome::NotNeeded
        );
    }

    #[tokio::test]
    async fn transient_failures_keep_every_file() {
        for (status, body) in [
            (500, r#"{"error":"server_error"}"#),
            (429, r#"{"error":"invalid_grant"}"#),
            (400, "not json"),
            (400, r#"{"error":"invalid_request"}"#),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let exp = (Utc::now() + ChronoDuration::minutes(1)).timestamp();
            seed(dir.path(), exp, Some("rt-1"));
            let idp = spawn_idp(status, body.into());
            let err = refresh_pro_tokens_with(dir.path(), &idp.discovery, "cid", lead())
                .await
                .unwrap_err();
            assert!(
                !err.to_string().contains("ProSessionExpired"),
                "{status} {body} must be transient: {err}"
            );
            assert!(has_pro_refresh_token(dir.path()), "{status} {body}");
        }
    }

    #[tokio::test]
    async fn no_refresh_token_and_expired_asks_for_login() {
        let dir = tempfile::tempdir().unwrap();
        let exp = (Utc::now() - ChronoDuration::minutes(10)).timestamp();
        seed(dir.path(), exp, None);
        let err = ensure_fresh_pro_tokens(dir.path()).await.unwrap_err();
        assert!(err.to_string().contains("kvendra login --pro"), "{err}");
    }

    #[tokio::test]
    async fn no_refresh_token_but_still_valid_goes_on() {
        let dir = tempfile::tempdir().unwrap();
        let exp = (Utc::now() + ChronoDuration::minutes(3)).timestamp();
        seed(dir.path(), exp, None);
        let r = ensure_fresh_pro_tokens(dir.path()).await.unwrap();
        assert_eq!(r, RefreshOutcome::NotNeeded);
    }

    #[test]
    fn refresh_uses_client_id_stored_at_login() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(resolve_pro_client_id(dir.path()), client_id_from_env());
        write_secret_atomic(&pro_client_id_path(dir.path()), b"old-client\n").unwrap();
        assert_eq!(resolve_pro_client_id(dir.path()), "old-client");
    }

    #[test]
    fn atomic_write_leaves_no_tmp_and_replaces_symlink_without_following() {
        let dir = tempfile::tempdir().unwrap();
        let target = pro_access_path(dir.path());
        write_secret_atomic(&target, b"one").unwrap();
        write_secret_atomic(&target, b"two").unwrap();
        let names: Vec<String> = std::fs::read_dir(dir.path().join("sessions"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["pro.token".to_string()], "{names:?}");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "two");

        #[cfg(unix)]
        {
            let victim = dir.path().join("victim");
            std::fs::write(&victim, b"keep").unwrap();
            std::fs::remove_file(&target).unwrap();
            std::os::unix::fs::symlink(&victim, &target).unwrap();
            write_secret_atomic(&target, b"three").unwrap();
            assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
            assert!(
                !std::fs::symlink_metadata(&target)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "three");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn peer_refresh_detected_after_lock() {
        let dir = tempfile::tempdir().unwrap();
        let exp = (Utc::now() + ChronoDuration::minutes(1)).timestamp();
        seed(dir.path(), exp, Some("rt-1"));
        let idp = spawn_idp(500, "{}".into());

        // A "peer process" holds the flock while it refreshes.
        let guard = SessionState::acquire_lock(dir.path(), PRO_LOCK_ID).unwrap();
        let home = dir.path().to_path_buf();
        let discovery = idp.discovery.clone();
        let task =
            tokio::spawn(
                async move { refresh_pro_tokens_with(&home, &discovery, "cid", lead()).await },
            );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let fresh = (Utc::now() + ChronoDuration::hours(1)).timestamp();
        seed(dir.path(), fresh, Some("rt-1"));
        drop(guard);

        let r = task.await.unwrap().unwrap();
        assert_eq!(r, RefreshOutcome::SkippedRefreshedByPeer);
        assert_eq!(idp.token_calls.load(Ordering::SeqCst), 0);
    }
}
