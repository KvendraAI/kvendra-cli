//! Thin HTTP client around the broker REST surface.

use crate::error::{KvendraError, KvendraResult};
use crate::protocol::v1::{
    CreateProfileRequest, MeResponse, MemberListResponse, ProfileListResponse, ProfileRedacted,
    TemplateListResponse, WorkspaceListResponse,
};
use std::time::Duration;
use url::Url;

/// Default broker base URL. Override via `KVENDRA_BROKER_URL`.
pub const DEFAULT_BROKER_BASE: &str = "https://api.kvendra.cloud";

/// Read the broker base URL from env, normalize trailing `/`.
pub fn broker_base_from_env() -> KvendraResult<Url> {
    let raw = std::env::var("KVENDRA_BROKER_URL")
        .unwrap_or_else(|_| DEFAULT_BROKER_BASE.to_string());
    let mut s = raw;
    if !s.ends_with('/') {
        s.push('/');
    }
    Url::parse(&s).map_err(|e| KvendraError::Http(format!("KVENDRA_BROKER_URL: {e}")))
}

/// Workspace-scoped HTTP client. Builds a single `reqwest::Client` and
/// reuses it across calls — connection pooling matters when the allowlist
/// sync task fans out to multiple templates.
pub struct WorkspaceClient {
    base: Url,
    jwt: String,
    http: reqwest::Client,
}

impl WorkspaceClient {
    /// Build a new client. `jwt` is the cached `access_token` from the
    /// session state.
    pub fn new(jwt: String) -> KvendraResult<Self> {
        let base = broker_base_from_env()?;
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("kvendra-cli/", env!("CARGO_PKG_VERSION"), " (rust)"))
            .build()
            .map_err(|e| KvendraError::Http(format!("client: {e}")))?;
        Ok(Self { base, jwt, http })
    }

    fn url(&self, suffix: &str) -> KvendraResult<Url> {
        self.base
            .join(suffix)
            .map_err(|e| KvendraError::Http(format!("join '{suffix}': {e}")))
    }

    fn map_status_error<T>(status: reqwest::StatusCode, body: String) -> KvendraResult<T> {
        match status.as_u16() {
            401 => Err(KvendraError::WorkspaceMembershipRevoked),
            403 => Err(KvendraError::InsufficientPrivilege("workspace".into())),
            404 => Err(KvendraError::ProfileNotFound),
            _ => Err(KvendraError::Http(format!("HTTP {status}: {body}"))),
        }
    }

    /// `GET /v1/me`. Tolerates IF-002 v1.1.0 (no `active_workspaces`).
    pub async fn me(&self) -> KvendraResult<MeResponse> {
        let url = self.url("v1/me")?;
        let resp = self
            .http
            .get(url)
            .bearer_auth(&self.jwt)
            .send()
            .await
            .map_err(map_reqwest)?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Self::map_status_error(status, body);
        }
        let parsed: MeResponse = resp
            .json()
            .await
            .map_err(|e| KvendraError::Http(format!("decode me: {e}")))?;
        Ok(parsed)
    }

    /// `GET /v1/workspaces`.
    pub async fn list_workspaces(&self) -> KvendraResult<WorkspaceListResponse> {
        let url = self.url("v1/workspaces")?;
        let resp = self
            .http
            .get(url)
            .bearer_auth(&self.jwt)
            .send()
            .await
            .map_err(map_reqwest)?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Self::map_status_error(status, body);
        }
        let parsed: WorkspaceListResponse = resp
            .json()
            .await
            .map_err(|e| KvendraError::Http(format!("decode workspaces: {e}")))?;
        Ok(parsed)
    }

    /// `GET /v1/workspaces/{id}/members`.
    pub async fn list_members(&self, workspace_id: &str) -> KvendraResult<MemberListResponse> {
        let url = self.url(&format!(
            "v1/workspaces/{}/members",
            urlencoding::encode(workspace_id)
        ))?;
        let resp = self
            .http
            .get(url)
            .bearer_auth(&self.jwt)
            .send()
            .await
            .map_err(map_reqwest)?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Self::map_status_error(status, body);
        }
        let parsed: MemberListResponse = resp
            .json()
            .await
            .map_err(|e| KvendraError::Http(format!("decode members: {e}")))?;
        Ok(parsed)
    }

    /// `GET /v1/workspaces/{id}/profiles`.
    pub async fn list_profiles(&self, workspace_id: &str) -> KvendraResult<ProfileListResponse> {
        let url = self.url(&format!(
            "v1/workspaces/{}/profiles",
            urlencoding::encode(workspace_id)
        ))?;
        let resp = self
            .http
            .get(url)
            .bearer_auth(&self.jwt)
            .send()
            .await
            .map_err(map_reqwest)?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Self::map_status_error(status, body);
        }
        let parsed: ProfileListResponse = resp
            .json()
            .await
            .map_err(|e| KvendraError::Http(format!("decode profiles: {e}")))?;
        Ok(parsed)
    }

    /// `GET /v1/workspaces/{id}/templates`. Optional `If-None-Match` header
    /// surfaces the conditional-GET path used by the allowlist sync task.
    /// Returns `Ok(None)` on `304 Not Modified`, `Ok(Some((body, etag)))`
    /// on `200`.
    #[allow(clippy::type_complexity)]
    pub async fn list_templates(
        &self,
        workspace_id: &str,
        if_none_match: Option<&str>,
    ) -> KvendraResult<Option<(TemplateListResponse, Option<String>)>> {
        let url = self.url(&format!(
            "v1/workspaces/{}/templates",
            urlencoding::encode(workspace_id)
        ))?;
        let mut req = self.http.get(url).bearer_auth(&self.jwt);
        if let Some(etag) = if_none_match {
            req = req.header("If-None-Match", etag);
        }
        let resp = req.send().await.map_err(map_reqwest)?;
        let status = resp.status();
        if status.as_u16() == 304 {
            return Ok(None);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Self::map_status_error(status, body);
        }
        let etag = resp
            .headers()
            .get("ETag")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());
        let parsed: TemplateListResponse = resp
            .json()
            .await
            .map_err(|e| KvendraError::Http(format!("decode templates: {e}")))?;
        Ok(Some((parsed, etag)))
    }

    /// `POST /v1/workspaces/{id}/profiles` — admin path for adding a new
    /// workspace secret.
    pub async fn create_profile(
        &self,
        workspace_id: &str,
        req: &CreateProfileRequest,
    ) -> KvendraResult<ProfileRedacted> {
        let url = self.url(&format!(
            "v1/workspaces/{}/profiles",
            urlencoding::encode(workspace_id)
        ))?;
        let resp = self
            .http
            .post(url)
            .bearer_auth(&self.jwt)
            .json(req)
            .send()
            .await
            .map_err(map_reqwest)?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Self::map_status_error(status, body);
        }
        let parsed: ProfileRedacted = resp
            .json()
            .await
            .map_err(|e| KvendraError::Http(format!("decode create_profile: {e}")))?;
        Ok(parsed)
    }
}

fn map_reqwest(e: reqwest::Error) -> KvendraError {
    if e.is_connect() || e.is_timeout() {
        KvendraError::BrokerUnreachable(format!("{e}"))
    } else {
        KvendraError::Http(format!("{e}"))
    }
}
