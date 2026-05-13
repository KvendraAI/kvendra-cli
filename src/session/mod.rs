//! Workspace session persistence — JSON token file at
//! `~/.kvendra/sessions/<workspace_id_safe>.token` (mode 0600).
//!
//! Per ADR-KVD-ENTERPRISE-002 the refresh_token lives in plaintext on disk;
//! the trust boundary explicitly accepts that a compromised laptop yields a
//! short-lived JWT. Mitigations: file mode 0600, atomic write, advisory
//! flock for cross-process refresh, server-side revocation + ≤30d refresh
//! TTL.
//!
//! `workspace_id` contains `/` per GLO-013 (e.g. `acme-corp/frontend`); on
//! disk we translate it to a filesystem-safe slug by replacing `/` with
//! `__`. The original string survives inside the JSON for verification.

pub mod store;

pub use store::{SessionState, list_active_sessions};
