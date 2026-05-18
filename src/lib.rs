//! Kvendra — developer harness CLI.
//!
//! Library crate exposing the building blocks used by the `kvendra` binary:
//! - [`vault`] — zero-knowledge local secret storage (Argon2id + AES-256-GCM).
//! - [`audit`] — SQLite-backed HMAC-chained audit log.
//! - [`allowlist`] — YAML DSL parser and runtime enforcer.
//! - [`mcp`] — thin JSON-RPC 2.0 MCP server transport (per ADR-KVD-006).
//! - [`primitives`] — capability primitives (git, github, shell, ...).
//! - [`detection`] — regex pattern detection layer (placeholder Pase B).
//! - [`config`] — `~/.kvendra/config.toml` loader.
//! - [`error`] — unified `KvendraError` type.

pub mod allowlist;
pub mod approval;
pub mod audit;
pub mod auth;
pub mod backup;
pub mod captured_env;
pub mod cli;
pub mod config;
pub mod detection;
pub mod error;
pub mod keychain_acl;
pub mod mcp;
pub mod primitives;
pub mod protocol;
pub mod secret_resolver;
pub mod session;
pub mod tui;
pub mod vault;
pub mod workspace;

pub use error::{KvendraError, KvendraResult};

/// Test-only env-var lock shared by every unit test that mutates
/// `KVENDRA_HOME` / `KVENDRA_PASSWORD`. Process-wide env vars cannot be
/// scoped per-test, so cargo's parallel test runner needs serialization.
/// Uses `tokio::sync::Mutex` so the guard can be held across `.await`
/// points in async tests without tripping `clippy::await_holding_lock`.
#[cfg(test)]
pub(crate) fn test_env_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}
