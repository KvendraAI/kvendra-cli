//! Session persistence — two orthogonal paths under `~/.kvendra/sessions/`:
//!
//! - **Workspace JWT** (`store`, Sprint 4) — `<workspace_id_safe>.token`.
//!   Per ADR-KVD-ENTERPRISE-002 the refresh_token lives in plaintext on
//!   disk; the trust boundary explicitly accepts that a compromised laptop
//!   yields a short-lived JWT. Mitigations: file mode 0600, atomic write,
//!   advisory flock for cross-process refresh, server-side revocation +
//!   ≤30d refresh TTL.
//!
//! - **Local master session** (`local`, REQ-KVD-CLI-011 / ADR-KVD-029) —
//!   `active.blob` + `active.blob.hmac`. Stores the Argon2id-derived vault
//!   key encrypted with the machine-bound wrap key
//!   `kvendra/session-wrap/v1` + HMAC sidecar + TTL. Allows the subprocess
//!   `kvendra mcp serve` to unlock the vault without re-prompting the
//!   master password each time a client like Claude Code or Cursor spawns
//!   it.
//!
//! `workspace_id` contains `/` per GLO-013 (e.g. `acme-corp/frontend`); on
//! disk we translate it to a filesystem-safe slug by replacing `/` with
//! `__`. The original string survives inside the JSON for verification.

pub mod local;
pub mod store;
pub mod ttl;
pub mod wrap_key;

pub use store::{SessionState, list_active_sessions};
