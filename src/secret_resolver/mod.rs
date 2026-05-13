//! SecretResolver trait + two impls — REQ-KVD-CLI-004.
//!
//! Cloud-agnostic abstraction over the source of a secret consumed by the
//! 8 primitives. The two implementations are:
//!
//!  - [`local::LocalVaultResolver`] — reads ciphertext from
//!    `~/.kvendra/secrets/<profile>.blob` via [`crate::vault::Vault`]. Steady
//!    state of the standalone (Free) tier. `audit_id == None` because the
//!    operation is purely local.
//!  - [`remote::RemoteBrokerResolver`] — POSTs to `/v1/profiles/{id}/tokens:issue`
//!    against the broker behind `KVENDRA_BROKER_URL`. Workspace mode for the
//!    Team/Enterprise tier; the broker stamps the response with an `audit_id`
//!    correlatable with the central audit log.

pub mod local;
pub mod remote;

use crate::error::KvendraResult;
use crate::vault::SecretPlaintext;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Per-call context passed by the MCP server to the resolver. Cloud-agnostic
/// by construction: no provider identifier or credential metadata.
#[derive(Debug, Clone, Serialize)]
pub struct CallCtx {
    pub primitive: String,
    pub op: String,
    pub args_hash_hex: String,
    pub requested_at: DateTime<Utc>,
}

/// Output of `SecretResolver::resolve`. The plaintext is wrapped in
/// [`SecretPlaintext`] (`ZeroizeOnDrop`).
pub struct EphemeralSecret {
    pub token: SecretPlaintext,
    pub expires_at: DateTime<Utc>,
    /// ULID of the central audit row. `Some` only when the secret was issued
    /// by the remote broker; the local resolver always returns `None`.
    pub audit_id: Option<String>,
    pub scope: ScopeMeta,
}

/// Scope envelope returned alongside an [`EphemeralSecret`]. `constraints`
/// is opaque on purpose — the broker may return arbitrary JSON tied to the
/// template policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeMeta {
    pub primitive: String,
    pub op: String,
    #[serde(default)]
    pub constraints: serde_json::Value,
}

impl ScopeMeta {
    /// Catch-all scope used by `LocalVaultResolver` (the local plaintext is
    /// not further restricted — the allowlist YAML provides that boundary).
    pub fn local_full() -> Self {
        Self {
            primitive: String::new(),
            op: String::new(),
            constraints: serde_json::Value::Object(serde_json::Map::new()),
        }
    }
}

impl From<crate::protocol::v1::ScopeMetaWire> for ScopeMeta {
    fn from(w: crate::protocol::v1::ScopeMetaWire) -> Self {
        Self {
            primitive: w.primitive,
            op: w.op,
            constraints: w.constraints,
        }
    }
}

/// Trait implemented by the two resolvers. `Send + Sync` so the dispatcher
/// can hold an `Arc<dyn SecretResolver>`.
#[async_trait]
pub trait SecretResolver: Send + Sync {
    async fn resolve(&self, profile_id: &str, ctx: &CallCtx) -> KvendraResult<EphemeralSecret>;

    /// Returns `"local"` or `"workspace:<id>"` — surfaced by `session info`
    /// and added to the local audit row as a flag.
    fn mode_label(&self) -> String;
}
