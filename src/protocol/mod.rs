//! Wire protocol types for talking to the Kvendra Enterprise broker.
//!
//! Scaffolding sprint (M0b absorbed into M1 — REQ-KVD-ENTERPRISE-006). The
//! sub-modules will be (re)generated from the closed-source OpenAPI 3.1
//! document via `scripts/codegen.sh`. Until M1 Sprint 4 wires the
//! `RemoteBrokerResolver` (REQ-KVD-CLI-004) the module is intentionally a
//! placeholder: it must compile, but it carries no real types yet.

pub mod v1;
