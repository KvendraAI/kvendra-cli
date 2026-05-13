//! OIDC discovery — fetch `.well-known/openid-configuration` and surface the
//! handful of endpoints we actually consume (authorize, token, jwks).
//!
//! Cached per-process in a `OnceCell<Mutex<HashMap<…>>>` so back-to-back
//! `login` + `refresh_if_needed` calls within the same `mcp serve` lifetime
//! do not re-fetch the document. Stays small (≤16 entries — we only ever
//! talk to one IdP per process).

use crate::error::{KvendraError, KvendraResult};
use serde::Deserialize;
use std::time::Duration;
use url::Url;

/// Slim view of the OIDC document. Additional fields the IdP may publish
/// (`jwks_uri`, `userinfo_endpoint`, ...) are ignored at decode time.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcConfig {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
}

impl OidcConfig {
    pub fn authorization_url(&self) -> KvendraResult<Url> {
        Url::parse(&self.authorization_endpoint).map_err(|e| {
            KvendraError::OidcDiscoveryFailed(format!("invalid authorization_endpoint: {e}"))
        })
    }

    pub fn token_url(&self) -> KvendraResult<Url> {
        Url::parse(&self.token_endpoint).map_err(|e| {
            KvendraError::OidcDiscoveryFailed(format!("invalid token_endpoint: {e}"))
        })
    }
}

/// Default IdP base URL. Override via env `KVENDRA_AUTH_URL`.
pub const DEFAULT_AUTH_BASE: &str = "https://auth.kvendra.cloud";

/// Read the IdP base URL from `KVENDRA_AUTH_URL`, falling back to
/// [`DEFAULT_AUTH_BASE`]. The URL is normalized to include a trailing `/`.
pub fn auth_base_from_env() -> KvendraResult<Url> {
    let raw =
        std::env::var("KVENDRA_AUTH_URL").unwrap_or_else(|_| DEFAULT_AUTH_BASE.to_string());
    let mut s = raw;
    if !s.ends_with('/') {
        s.push('/');
    }
    Url::parse(&s).map_err(|e| KvendraError::OidcDiscoveryFailed(format!("KVENDRA_AUTH_URL: {e}")))
}

/// Fetch the OIDC discovery document for `auth_base`. The endpoint is
/// `<auth_base>/.well-known/openid-configuration`.
pub async fn discover(auth_base: &Url) -> KvendraResult<OidcConfig> {
    let url = auth_base
        .join(".well-known/openid-configuration")
        .map_err(|e| KvendraError::OidcDiscoveryFailed(format!("join discovery: {e}")))?;
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("kvendra-cli/", env!("CARGO_PKG_VERSION"), " (rust)"))
        .build()
        .map_err(|e| KvendraError::OidcDiscoveryFailed(format!("client: {e}")))?;
    let resp = client.get(url.clone()).send().await.map_err(|e| {
        if e.is_connect() || e.is_timeout() {
            KvendraError::BrokerUnreachable(format!("OIDC discovery: {e}"))
        } else {
            KvendraError::OidcDiscoveryFailed(format!("{e}"))
        }
    })?;
    let status = resp.status();
    if !status.is_success() {
        return Err(KvendraError::OidcDiscoveryFailed(format!(
            "discovery HTTP {status}"
        )));
    }
    let cfg: OidcConfig = resp
        .json()
        .await
        .map_err(|e| KvendraError::OidcDiscoveryFailed(format!("decode: {e}")))?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_base_defaults_to_kvendra_cloud_when_env_absent() {
        // SAFETY: same-process env access; serialized at the function level.
        // SAFETY: test mutates env at process scope.
        unsafe { std::env::remove_var("KVENDRA_AUTH_URL") };
        let base = auth_base_from_env().unwrap();
        assert_eq!(base.as_str(), "https://auth.kvendra.cloud/");
    }

    #[test]
    fn auth_base_honors_env_override() {
        // SAFETY: test mutates env at process scope.
        unsafe { std::env::set_var("KVENDRA_AUTH_URL", "https://idp.example.com") };
        let base = auth_base_from_env().unwrap();
        assert_eq!(base.as_str(), "https://idp.example.com/");
        // SAFETY: test mutates env at process scope.
        unsafe { std::env::remove_var("KVENDRA_AUTH_URL") };
    }
}
