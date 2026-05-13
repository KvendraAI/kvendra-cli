//! Initial audit-log bootstrap — `vault_created` row written by `kvendra init`.
//!
//! Per ISSUE-KVD-CLI-003: previously the audit DB was created lazily on
//! the first `mcp serve` / `secret add`, so a forensic question like
//! "when was this vault created?" had to fall back to filesystem mtimes
//! (mutable). After init we now persist a single HMAC-chained row that
//! anchors the chain.

use crate::audit::{AuditEvent, AuditWriter, Severity, Status};
use crate::config::set_file_mode_secure;
use crate::error::KvendraResult;
use std::path::Path;
use time::OffsetDateTime;

/// Spawn the audit writer, tighten the SQLite file perms to 0600, and
/// emit a single `kvendra.system / vault_created` event referencing the
/// binary version. The writer is shut down before returning so the
/// `.db` / `.db-wal` files are flushed before `kvendra init` exits.
pub async fn write_vault_created_event(
    audit_db: &Path,
    hmac_key: Vec<u8>,
    version: &str,
) -> KvendraResult<()> {
    let writer = AuditWriter::spawn(audit_db.to_path_buf(), hmac_key)?;
    set_file_mode_secure(audit_db)?;
    let args_hash = super::reader::args_hash_hex(&serde_json::json!({ "version": version }));
    let event = AuditEvent {
        ts_unix_ms: OffsetDateTime::now_utc().unix_timestamp_nanos() as i64 / 1_000_000,
        profile_id: "kvendra.system".into(),
        primitive: "kvendra.system".into(),
        action: "vault_created".into(),
        args_hash_hex: args_hash,
        status: Status::Ok,
        severity: Severity::Info,
        flags: String::new(),
        remote_audit_id: None,
    };
    writer.record(event).await?;
    writer.shutdown().await;
    Ok(())
}
