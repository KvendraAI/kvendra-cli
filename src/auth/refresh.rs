//! Proactive JWT refresh — REQ-KVD-CLI-008.
//!
//! Algorithm per SPEC D5:
//!  - If `jwt_expires_at - now > 5min`: NotNeeded.
//!  - Else: take cross-process flock, re-read the on-disk file (another
//!    process may have refreshed), and only call the IdP if the freshly
//!    read state is still close to expiry.
//!  - `invalid_grant` → delete the session file, return
//!    [`KvendraError::WorkspaceSessionExpired`].

use crate::auth::discovery::{auth_base_from_env, discover};
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

/// Lead time before expiry at which we proactively refresh.
pub const REFRESH_LEAD: ChronoDuration = ChronoDuration::minutes(5);

/// Refresh the cached session if it is within [`REFRESH_LEAD`] of expiry.
pub async fn refresh_if_needed(
    home: &Path,
    session: &Arc<RwLock<SessionState>>,
) -> KvendraResult<RefreshOutcome> {
    let now = Utc::now();
    let snapshot = session.read().await.clone();
    if snapshot.jwt_expires_at - now > REFRESH_LEAD {
        return Ok(RefreshOutcome::NotNeeded);
    }

    // Cross-process flock — guarantees only one process talks to the IdP
    // for a given workspace at a time.
    let _guard = SessionState::acquire_lock(home, &snapshot.workspace_id)?;

    // Re-read disk: a peer may have refreshed while we were waiting.
    if let Some(fresh) = SessionState::load(home, &snapshot.workspace_id)? {
        if fresh.jwt_expires_at - now > REFRESH_LEAD {
            *session.write().await = fresh;
            return Ok(RefreshOutcome::SkippedRefreshedByPeer);
        }
    }

    let auth_base = auth_base_from_env()?;
    let oidc = discover(&auth_base).await?;
    let client_id = client_id_from_env();

    let new_tokens =
        match exchange_refresh_token(&oidc, &client_id, &snapshot.refresh_token).await {
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
