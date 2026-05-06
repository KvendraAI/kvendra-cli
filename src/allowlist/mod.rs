//! Allowlist DSL — YAML per-profile capability constraint.
//!
//! Per ADR-KVD-008 we use `serde_yml`. Defaults are restrictive (REQ-KVD-002
//! AC-ALLOW-1): empty methods or wildcard endpoints without `accept_broad_scope`
//! are rejected.

pub mod dsl;
pub mod enforcer;
pub mod validator;

pub use dsl::{Allowlist, Operation, OperationConstraints, PrimitiveAllow, ProfileSpec};
pub use enforcer::check;
pub use validator::validate;
