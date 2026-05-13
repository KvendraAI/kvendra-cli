//! `LocalVaultResolver` — wraps the existing zero-knowledge vault.

use crate::error::KvendraResult;
use crate::secret_resolver::{CallCtx, EphemeralSecret, ScopeMeta, SecretResolver};
use crate::vault::Vault;
use async_trait::async_trait;
use chrono::{Duration as ChronoDuration, Utc};

/// Resolver that delegates to [`Vault::get_secret`]. Used in standalone
/// (Free) mode. Equivalence with pre-Sprint 4 behaviour is intentional:
/// `expires_at` is set far in the future, `audit_id == None`.
pub struct LocalVaultResolver {
    vault: Vault,
}

impl LocalVaultResolver {
    pub fn new(vault: Vault) -> Self {
        Self { vault }
    }
}

#[async_trait]
impl SecretResolver for LocalVaultResolver {
    async fn resolve(&self, profile_id: &str, _ctx: &CallCtx) -> KvendraResult<EphemeralSecret> {
        let plaintext = self.vault.get_secret(profile_id)?;
        Ok(EphemeralSecret {
            token: plaintext,
            // Pre-Sprint 4 semantics — local secrets are evergreen until the
            // user rotates them. Pick 365 days arbitrarily so consumers that
            // check `expires_at` do not log a permanent expiry warning.
            expires_at: Utc::now() + ChronoDuration::days(365),
            audit_id: None,
            scope: ScopeMeta::local_full(),
        })
    }

    fn mode_label(&self) -> String {
        "local".into()
    }
}
