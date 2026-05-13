//! `RemoteBrokerResolver` — POSTs `tokens:issue` to the cloud broker.
//!
//! Cloud-agnostic by construction — no provider-specific identifiers leak
//! through the wire types. The base URL is configurable via
//! `KVENDRA_BROKER_URL`. // allowed: this doc comment documents the
//! abstraction itself; the listed vendor names exist only in this prose.

use crate::error::{KvendraError, KvendraResult};
use crate::protocol::v1::{IssueTokenRequest, IssueTokenResponse};
use crate::secret_resolver::{CallCtx, EphemeralSecret, ScopeMeta, SecretResolver};
use crate::session::SessionState;
use crate::vault::SecretPlaintext;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use url::Url;

/// Default broker base URL. Override via env `KVENDRA_BROKER_URL`.
pub const DEFAULT_BROKER_BASE: &str = "https://api.kvendra.cloud";

/// Resolver that fetches an ephemeral token from the workspace broker on
/// each `tools/call`. Concurrency-safe: the [`SessionState`] is shared via
/// `Arc<RwLock<…>>` with the proactive refresh task.
pub struct RemoteBrokerResolver {
    base_url: Url,
    session: Arc<RwLock<SessionState>>,
    http: reqwest::Client,
}

impl RemoteBrokerResolver {
    /// Build a new resolver wired to the broker behind `KVENDRA_BROKER_URL`.
    pub fn new(session: Arc<RwLock<SessionState>>) -> KvendraResult<Self> {
        let raw = std::env::var("KVENDRA_BROKER_URL")
            .unwrap_or_else(|_| DEFAULT_BROKER_BASE.to_string());
        let mut s = raw;
        if !s.ends_with('/') {
            s.push('/');
        }
        let base_url = Url::parse(&s).map_err(|e| {
            KvendraError::Http(format!("invalid KVENDRA_BROKER_URL: {e}"))
        })?;

        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            // SLA-KVD-ENTERPRISE-001 p99 < 100ms; 3s gives 30x headroom for
            // cold-starts and jitter without degrading UX.
            .timeout(Duration::from_secs(3))
            .user_agent(concat!("kvendra-cli/", env!("CARGO_PKG_VERSION"), " (rust)"))
            .build()
            .map_err(|e| KvendraError::Http(format!("client: {e}")))?;

        Ok(Self {
            base_url,
            session,
            http,
        })
    }
}

#[async_trait]
impl SecretResolver for RemoteBrokerResolver {
    async fn resolve(&self, profile_id: &str, ctx: &CallCtx) -> KvendraResult<EphemeralSecret> {
        let jwt = {
            let snap = self.session.read().await;
            snap.jwt.clone()
        };

        let body = IssueTokenRequest {
            primitive: ctx.primitive.clone(),
            op: ctx.op.clone(),
            args_hash: ctx.args_hash_hex.clone(),
            requested_at: ctx.requested_at.to_rfc3339(),
        };
        let url = self
            .base_url
            .join(&format!("v1/profiles/{profile_id}/tokens:issue"))
            .map_err(|e| KvendraError::Http(format!("join: {e}")))?;

        let resp = self
            .http
            .post(url)
            .bearer_auth(jwt)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                if e.is_connect() || e.is_timeout() {
                    KvendraError::BrokerUnreachable(format!("tokens:issue: {e}"))
                } else {
                    KvendraError::Http(format!("tokens:issue: {e}"))
                }
            })?;

        let status = resp.status().as_u16();
        match status {
            200 => {
                let parsed: IssueTokenResponse = resp
                    .json()
                    .await
                    .map_err(|e| KvendraError::Http(format!("decode tokens:issue: {e}")))?;
                let expires_at: DateTime<Utc> = parsed.expires_at.parse().map_err(|e| {
                    KvendraError::Http(format!("expires_at parse: {e}"))
                })?;
                Ok(EphemeralSecret {
                    token: SecretPlaintext::new(parsed.token.into_bytes()),
                    expires_at,
                    audit_id: Some(parsed.audit_id),
                    scope: ScopeMeta::from(parsed.scope),
                })
            }
            401 => Err(KvendraError::WorkspaceMembershipRevoked),
            403 => Err(KvendraError::InsufficientPrivilege(profile_id.into())),
            404 => Err(KvendraError::ProfileNotFound),
            410 => Err(KvendraError::ProfileExpired),
            429 => {
                let retry = resp
                    .headers()
                    .get("Retry-After")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                Err(KvendraError::RateLimited(retry))
            }
            other => {
                let body_text = resp.text().await.unwrap_or_default();
                Err(KvendraError::Http(format!(
                    "broker {other}: {body_text}"
                )))
            }
        }
    }

    fn mode_label(&self) -> String {
        // Cheap blocking read on the shared snapshot — `mode_label` is only
        // called by `session info` and audit-flag construction, not on the
        // hot path.
        let snap = futures_lite_block_on(self.session.read());
        format!("workspace:{}", snap.workspace_id)
    }
}

/// Tiny helper that synchronously awaits a `tokio::sync::RwLockReadGuard`
/// future. Used by [`SecretResolver::mode_label`] (non-async). Safe because
/// `RwLock::read` never blocks indefinitely — the lock guard is acquired
/// instantly when no writer is active.
fn futures_lite_block_on<F: std::future::Future>(fut: F) -> F::Output {
    let rt = tokio::runtime::Handle::try_current();
    match rt {
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(fut)),
        Err(_) => {
            // Fallback when called from a non-tokio context (only happens
            // in unit tests outside #[tokio::test]).
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build tokio runtime");
            rt.block_on(fut)
        }
    }
}
