//! Proactive JWT refresh — REQ-KVD-CLI-008.
//!
//! Algorithm per SPEC D5:
//!  - If `jwt_expires_at - now > 5min`: NotNeeded.
//!  - Else: take cross-process flock, re-read the on-disk file (another
//!    process may have refreshed), and only call the IdP if the freshly
//!    read state is still close to expiry.
//!  - `invalid_grant` → delete the session file, return
//!    [`KvendraError::WorkspaceSessionExpired`].

use crate::auth::discovery::{discover, discovery_url_from_env};
use crate::auth::oidc::{client_id_from_env, exchange_refresh_token, is_invalid_grant};
use crate::error::{KvendraError, KvendraResult};
use crate::session::SessionState;
use chrono::{Duration as ChronoDuration, Utc};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Outcome of a refresh attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// JWT had >5 minutes of life remaining — no exchange performed.
    NotNeeded,
    /// IdP successfully issued a new token set; on-disk state updated.
    Refreshed,
    /// Another process refreshed while we were waiting for the flock.
    SkippedRefreshedByPeer,
}

/// Default lead time before expiry at which we proactively refresh.
pub const DEFAULT_REFRESH_LEAD: ChronoDuration = ChronoDuration::minutes(5);

/// Read the configured lead time from `KVENDRA_JWT_REFRESH_LEAD_SECONDS`,
/// falling back to [`DEFAULT_REFRESH_LEAD`]. Required by SPEC §V17 for
/// E2E tests against shortened TTLs.
fn refresh_lead() -> ChronoDuration {
    std::env::var("KVENDRA_JWT_REFRESH_LEAD_SECONDS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .map(ChronoDuration::seconds)
        .unwrap_or(DEFAULT_REFRESH_LEAD)
}

/// Refresh the cached session if it is within [`refresh_lead`] of expiry.
pub async fn refresh_if_needed(
    home: &Path,
    session: &Arc<RwLock<SessionState>>,
) -> KvendraResult<RefreshOutcome> {
    let now = Utc::now();
    let lead = refresh_lead();
    let snapshot = session.read().await.clone();
    if snapshot.jwt_expires_at - now > lead {
        return Ok(RefreshOutcome::NotNeeded);
    }

    // Cross-process flock — guarantees only one process talks to the IdP
    // for a given workspace at a time.
    let _guard = SessionState::acquire_lock(home, &snapshot.workspace_id)?;

    // Re-read disk: a peer may have refreshed while we were waiting.
    if let Some(fresh) = SessionState::load(home, &snapshot.workspace_id)?
        && fresh.jwt_expires_at - now > lead
    {
        *session.write().await = fresh;
        return Ok(RefreshOutcome::SkippedRefreshedByPeer);
    }

    let discovery_url = discovery_url_from_env()?;
    let oidc = discover(&discovery_url).await?;
    let client_id = client_id_from_env();

    let new_tokens = match exchange_refresh_token(&oidc, &client_id, &snapshot.refresh_token).await
    {
        Ok(t) => t,
        Err(KvendraError::OidcFlow(msg)) if is_invalid_grant(&msg) => {
            let _ = SessionState::delete(home, &snapshot.workspace_id);
            return Err(KvendraError::WorkspaceSessionExpired);
        }
        Err(e) => return Err(e),
    };

    let new_state = SessionState::from_token_set(
        &snapshot.workspace_id,
        &snapshot.tenant_id,
        &snapshot.member_id,
        &snapshot.member_email,
        &snapshot.issuer,
        &snapshot.audience,
        &new_tokens,
        Some(&snapshot.refresh_token),
        now,
    );
    new_state.persist_atomic(home)?;
    *session.write().await = new_state;
    Ok(RefreshOutcome::Refreshed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::oidc::TokenSet;

    fn fresh_state(now: chrono::DateTime<Utc>) -> SessionState {
        SessionState::from_token_set(
            "acme-corp/frontend",
            "acme-corp",
            "member-id",
            "bob@acme.com",
            "https://auth.kvendra.cloud",
            "audience-id",
            &TokenSet {
                access_token: "jwt".into(),
                id_token: "id".into(),
                refresh_token: "rt".into(),
                expires_in: 1800,
                token_type: "Bearer".into(),
            },
            None,
            now,
        )
    }

    #[tokio::test]
    async fn refresh_skips_when_token_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let state = fresh_state(now);
        state.persist_atomic(dir.path()).unwrap();
        let shared = Arc::new(RwLock::new(state));
        // Token fresh (~30min remaining) → NotNeeded short-circuits before
        // talking to the IdP.
        let r = refresh_if_needed(dir.path(), &shared).await.unwrap();
        assert_eq!(r, RefreshOutcome::NotNeeded);
    }
}
