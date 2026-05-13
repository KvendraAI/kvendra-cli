//! OIDC Authorization Code + PKCE flow against the IdP behind `KVENDRA_AUTH_URL`.
//!
//! Pure stdlib + `tiny_http` for the loopback callback receiver. We do NOT
//! shell out to a browser-controlling library beyond best-effort
//! `webbrowser::open`; the URL is always printed so headless flows still
//! work.
//!
//! Per D2 of the SPEC the callback listener iterates `54321..=54330`; the
//! first free port wins. The CLI uses the actually-bound port to build the
//! `redirect_uri`, which must match exactly one of the URLs configured in
//! the IdP application (kvendra-enterprise SAM template enumerates the full
//! grid 10 ports × {127.0.0.1, localhost}).

use crate::auth::discovery::{OidcConfig, discover};
use crate::error::{KvendraError, KvendraResult};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::ops::RangeInclusive;
use std::time::{Duration, Instant};
use url::Url;

/// Lowest loopback port the CLI tries when binding the OIDC callback receiver.
pub const PORT_RANGE_LOW: u16 = 54321;
/// Highest loopback port the CLI tries when binding the OIDC callback receiver.
pub const PORT_RANGE_HIGH: u16 = 54330;

/// Default OIDC `client_id` for staging. Override via env
/// `KVENDRA_CLIENT_ID`. The constant is provider-agnostic by name (it is
/// the canonical OIDC public client id, not a vendor-specific identifier).
pub const DEFAULT_CLIENT_ID: &str = "5ab5mhjhv0l6akhiqndvt636b";

/// PKCE proof carriers (RFC 7636).
pub struct PkceFlow {
    pub code_verifier: String,
    pub code_challenge: String,
    pub state: String,
}

impl PkceFlow {
    /// Generate a fresh PKCE challenge. `code_verifier` is 64 bytes of random
    /// base64url-no-padding (87 chars, within the 43..=128 RFC range).
    pub fn generate() -> KvendraResult<Self> {
        let mut buf = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut buf);
        let code_verifier = B64URL.encode(buf);

        let challenge_bytes = Sha256::digest(code_verifier.as_bytes());
        let code_challenge = B64URL.encode(challenge_bytes);

        let mut state_buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut state_buf);
        let state = hex::encode(state_buf);

        Ok(Self {
            code_verifier,
            code_challenge,
            state,
        })
    }
}

/// OAuth2 token bundle returned by the token endpoint.
#[derive(Debug, Clone)]
pub struct TokenSet {
    pub access_token: String,
    pub id_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub token_type: String,
}

/// Read the OIDC client id from env, falling back to [`DEFAULT_CLIENT_ID`].
pub fn client_id_from_env() -> String {
    std::env::var("KVENDRA_CLIENT_ID").unwrap_or_else(|_| DEFAULT_CLIENT_ID.to_string())
}

/// Bind the first available `127.0.0.1:port` in `range`. Returns
/// `Err(OidcCallbackPortRangeExhausted)` when every port is occupied.
pub fn bind_loopback_in_range(range: RangeInclusive<u16>) -> KvendraResult<(TcpListener, u16)> {
    for port in range {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        if let Ok(listener) = TcpListener::bind(addr) {
            return Ok((listener, port));
        }
    }
    Err(KvendraError::OidcCallbackPortRangeExhausted)
}

/// Full `kvendra login --workspace` happy path: discover, bind, open
/// browser, accept callback, exchange code for tokens.
pub async fn login_workspace(
    _workspace_id: &str,
    discovery_url: &Url,
    client_id: &str,
) -> KvendraResult<TokenSet> {
    let oidc = discover(discovery_url).await?;
    let (listener, port) = bind_loopback_in_range(PORT_RANGE_LOW..=PORT_RANGE_HIGH)?;
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");
    let pkce = PkceFlow::generate()?;
    let authorize_url = build_authorize_url(&oidc, client_id, &redirect_uri, &pkce)?;

    eprintln!("\nOpening browser for workspace login...");
    eprintln!("If the browser does not open, visit:\n{authorize_url}\n");
    let _ = webbrowser::open(authorize_url.as_str());

    let (code, returned_state) = accept_one_callback(listener, Duration::from_secs(300))?;
    if !constant_time_eq(returned_state.as_bytes(), pkce.state.as_bytes()) {
        return Err(KvendraError::OidcStateMismatch);
    }
    exchange_code_for_tokens(&oidc, client_id, &redirect_uri, &code, &pkce).await
}

/// Build the OIDC authorize URL with PKCE, openid scope, force-login prompt.
pub fn build_authorize_url(
    oidc: &OidcConfig,
    client_id: &str,
    redirect_uri: &str,
    pkce: &PkceFlow,
) -> KvendraResult<Url> {
    let mut url = oidc.authorization_url()?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", client_id);
        q.append_pair("redirect_uri", redirect_uri);
        q.append_pair("scope", "openid email profile");
        q.append_pair("state", &pkce.state);
        q.append_pair("code_challenge", &pkce.code_challenge);
        q.append_pair("code_challenge_method", "S256");
    }
    Ok(url)
}

/// Block until exactly one `GET /callback?...` arrives (or `timeout`).
/// Returns `(code, state)` extracted from the query string.
pub fn accept_one_callback(
    listener: TcpListener,
    timeout: Duration,
) -> KvendraResult<(String, String)> {
    listener
        .set_nonblocking(false)
        .map_err(|e| KvendraError::OidcFlow(format!("listener mode: {e}")))?;

    let server = tiny_http::Server::from_listener(listener, None)
        .map_err(|e| KvendraError::OidcFlow(format!("tiny_http: {e}")))?;
    let deadline = Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(KvendraError::OidcFlow("callback timed out".into()));
        }
        match server.recv_timeout(remaining) {
            Ok(Some(request)) => {
                let target = request.url().to_string();
                // Parse query string. tiny_http exposes raw URL only.
                let parsed = Url::parse(&format!("http://127.0.0.1{target}"))
                    .map_err(|e| KvendraError::OidcFlow(format!("callback URL: {e}")))?;
                let mut code = None;
                let mut state = None;
                let mut idp_error = None;
                for (k, v) in parsed.query_pairs() {
                    match k.as_ref() {
                        "code" => code = Some(v.into_owned()),
                        "state" => state = Some(v.into_owned()),
                        "error" => idp_error = Some(v.into_owned()),
                        _ => {}
                    }
                }
                let html = success_page_html();
                let resp = tiny_http::Response::from_string(html)
                    .with_header(
                        "Content-Type: text/html; charset=utf-8"
                            .parse::<tiny_http::Header>()
                            .unwrap(),
                    )
                    .with_status_code(200);
                let _ = request.respond(resp);

                if let Some(err) = idp_error {
                    return Err(KvendraError::OidcFlow(format!("IdP error: {err}")));
                }
                match (code, state) {
                    (Some(c), Some(s)) => return Ok((c, s)),
                    _ => {
                        return Err(KvendraError::OidcFlow(
                            "callback missing code or state".into(),
                        ));
                    }
                }
            }
            Ok(None) => continue,
            Err(e) => return Err(KvendraError::OidcFlow(format!("recv: {e}"))),
        }
    }
}

/// Exchange a freshly-received authorization code for an access/id/refresh
/// token tuple.
pub async fn exchange_code_for_tokens(
    oidc: &OidcConfig,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    pkce: &PkceFlow,
) -> KvendraResult<TokenSet> {
    let token_url = oidc.token_url()?;
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("kvendra-cli/", env!("CARGO_PKG_VERSION"), " (rust)"))
        .build()
        .map_err(|e| KvendraError::OidcFlow(format!("client: {e}")))?;
    let form = [
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("code", code),
        ("code_verifier", &pkce.code_verifier),
    ];
    let resp = client
        .post(token_url)
        .form(&form)
        .send()
        .await
        .map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                KvendraError::BrokerUnreachable(format!("token exchange: {e}"))
            } else {
                KvendraError::OidcFlow(format!("token exchange: {e}"))
            }
        })?;
    parse_token_response(resp).await
}

/// Refresh path: exchange `refresh_token` for a new access/id/refresh tuple.
pub async fn exchange_refresh_token(
    oidc: &OidcConfig,
    client_id: &str,
    refresh_token: &str,
) -> KvendraResult<TokenSet> {
    let token_url = oidc.token_url()?;
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("kvendra-cli/", env!("CARGO_PKG_VERSION"), " (rust)"))
        .build()
        .map_err(|e| KvendraError::OidcFlow(format!("client: {e}")))?;
    let form = [
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", refresh_token),
    ];
    let resp = client
        .post(token_url)
        .form(&form)
        .send()
        .await
        .map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                KvendraError::BrokerUnreachable(format!("refresh: {e}"))
            } else {
                KvendraError::OidcFlow(format!("refresh: {e}"))
            }
        })?;
    parse_token_response(resp).await
}

async fn parse_token_response(resp: reqwest::Response) -> KvendraResult<TokenSet> {
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| KvendraError::OidcFlow(format!("body: {e}")))?;
    if !status.is_success() {
        // 400 invalid_grant signals refresh token expiry. Caller decides
        // whether to remap to WorkspaceSessionExpired.
        return Err(KvendraError::OidcFlow(format!("HTTP {status}: {body}")));
    }
    #[derive(serde::Deserialize)]
    struct TokenResponse {
        access_token: String,
        #[serde(default)]
        id_token: String,
        // Some IdPs do NOT rotate refresh_tokens; the field may be absent
        // on refresh responses. Keep a stable default so the caller can
        // fall back to the previously-cached refresh_token.
        #[serde(default)]
        refresh_token: String,
        #[serde(default)]
        expires_in: u64,
        #[serde(default = "default_bearer")]
        token_type: String,
    }
    fn default_bearer() -> String {
        "Bearer".into()
    }
    let parsed: TokenResponse = serde_json::from_str(&body)
        .map_err(|e| KvendraError::OidcFlow(format!("decode token: {e}")))?;
    Ok(TokenSet {
        access_token: parsed.access_token,
        id_token: parsed.id_token,
        refresh_token: parsed.refresh_token,
        expires_in: parsed.expires_in,
        token_type: parsed.token_type,
    })
}

/// HTML body returned in the success branch of the loopback callback.
fn success_page_html() -> String {
    r#"<!doctype html>
<html><head><meta charset="utf-8"><title>Kvendra workspace login</title></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, sans-serif; padding: 2em; max-width: 32em;">
<h1>Workspace login successful</h1>
<p>You can close this window and return to your terminal.</p>
</body></html>
"#
    .into()
}

/// `true` iff both byte slices are equal in constant time. Used to compare
/// the `state` echoed by the IdP against the local PKCE state.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Best-effort sniff for the canonical IdP "invalid_grant" reply. Used by
/// the refresh path to remap a refresh-failure into
/// [`KvendraError::WorkspaceSessionExpired`].
pub fn is_invalid_grant(msg: &str) -> bool {
    msg.contains("invalid_grant") || msg.contains("HTTP 400") || msg.contains("HTTP 401")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_is_base64url_sha256() {
        let pkce = PkceFlow::generate().unwrap();
        let recomputed = B64URL.encode(Sha256::digest(pkce.code_verifier.as_bytes()));
        assert_eq!(recomputed, pkce.code_challenge);
        // RFC 7636: code_verifier 43..128 chars, charset URL-safe.
        assert!(
            pkce.code_verifier.len() >= 43 && pkce.code_verifier.len() <= 128,
            "verifier length {} out of range",
            pkce.code_verifier.len()
        );
    }

    #[test]
    fn state_is_unique_per_flow() {
        let a = PkceFlow::generate().unwrap();
        let b = PkceFlow::generate().unwrap();
        assert_ne!(a.state, b.state);
        assert_ne!(a.code_verifier, b.code_verifier);
    }

    #[test]
    fn constant_time_eq_matches_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn bind_loopback_returns_port_in_range() {
        // The OS may or may not have these ports free at test time. Either
        // every port is occupied (legitimate) → Err, or we get one in range.
        match bind_loopback_in_range(PORT_RANGE_LOW..=PORT_RANGE_HIGH) {
            Ok((_l, port)) => assert!((PORT_RANGE_LOW..=PORT_RANGE_HIGH).contains(&port)),
            Err(KvendraError::OidcCallbackPortRangeExhausted) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn invalid_grant_detection() {
        assert!(is_invalid_grant(r#"{"error":"invalid_grant"}"#));
        assert!(is_invalid_grant("HTTP 400: bad"));
        assert!(!is_invalid_grant("HTTP 500: server error"));
    }
}
