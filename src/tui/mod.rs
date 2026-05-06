//! TUI — Pase B placeholder.
//!
//! `kvendra dashboard` and `kvendra audit --watch` live UIs ship in Pase B.
//! This module exists so the feature flag `tui` compiles cleanly when
//! `ratatui` and `crossterm` are pulled in.

pub mod audit_watch;
pub mod dashboard;
