//! Workspace client — admin / member operations against the broker
//! (REQ-KVD-CLI-004, REQ-KVD-CLI-009).
//!
//! All wire types live in [`crate::protocol::v1`]. The base URL is read from
//! `KVENDRA_BROKER_URL` (default `https://api.kvendra.cloud`).

pub mod allowlist_sync;
pub mod client;
pub mod metadata_sync;

pub use client::{WorkspaceClient, broker_base_from_env};
