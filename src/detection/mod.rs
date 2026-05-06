//! Detection layer — Pase B placeholder.
//!
//! REQ-KVD-002 Bloque 7 ships in Pase B. The skeleton lives here so that
//! sanitization helpers in primitive responses have a target to call.

pub mod patterns;

/// Severity decision for a detected token (placeholder).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Warn,
    Block,
}
