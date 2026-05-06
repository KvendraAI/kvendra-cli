//! MCP — thin JSON-RPC 2.0 server over stdio (ADR-KVD-006).
//!
//! Modules:
//! - [`protocol`] — request/response/error types.
//! - [`transport`] — line-delimited JSON-RPC reader/writer over stdio.
//! - [`server`] — dispatcher with audit hooks (records `started` BEFORE
//!   executing the primitive, then updates with the result — AC-AUDIT-1).

pub mod protocol;
pub mod server;
pub mod transport;
