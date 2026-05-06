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
pub mod audit;
pub mod cli;
pub mod config;
pub mod detection;
pub mod error;
pub mod mcp;
pub mod primitives;
pub mod tui;
pub mod vault;

pub use error::{KvendraError, KvendraResult};
