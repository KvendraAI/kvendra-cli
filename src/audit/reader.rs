//! Audit reader — query / export / verify HMAC chain.

use crate::audit::hmac::{compute_hmac_v1, compute_hmac_v2};
use crate::audit::schema::init;
use crate::error::{KvendraError, KvendraResult};
use rusqlite::Connection;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct StoredEvent {
    pub id: i64,
    pub ts_unix_ms: i64,
    pub profile_id: String,
    pub primitive: String,
    pub action: String,
    pub args_hash_hex: String,
    pub status: String,
    pub severity: String,
    pub flags: String,
    pub prev_hmac_hex: String,
    pub hmac_hex: String,
    /// ULID of the remote audit counterpart. `None` for local-mode rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_audit_id: Option<String>,
    /// HMAC layout version (1 = legacy, 2 = post-v2 migration). Defaults to
    /// 1 for rows that pre-date the schema migration.
    pub hmac_version: i64,
}

pub fn open_readonly(db_path: &Path) -> KvendraResult<Connection> {
    let conn = Connection::open(db_path)?;
    init(&conn)?;
    Ok(conn)
}

pub fn list_all(conn: &Connection) -> KvendraResult<Vec<StoredEvent>> {
    // We `SELECT` the v2 columns explicitly because they may have been added
    // by the migration step earlier in the process — older binaries opening
    // the same file would have already had `apply_pending` upgrade the
    // schema for them too.
    let mut stmt = conn.prepare(
        "SELECT id, ts_unix_ms, profile_id, primitive, action, args_hash_hex,
         status, severity, flags, prev_hmac_hex, hmac_hex,
         remote_audit_id, hmac_version
         FROM audit_events ORDER BY id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(StoredEvent {
            id: row.get(0)?,
            ts_unix_ms: row.get(1)?,
            profile_id: row.get(2)?,
            primitive: row.get(3)?,
            action: row.get(4)?,
            args_hash_hex: row.get(5)?,
            status: row.get(6)?,
            severity: row.get(7)?,
            flags: row.get(8)?,
            prev_hmac_hex: row.get(9)?,
            hmac_hex: row.get(10)?,
            remote_audit_id: row.get(11)?,
            hmac_version: row.get(12)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Walk the chain from id ASC, recompute each row's HMAC under the layout
/// version recorded in that row, and fail at the first mismatch
/// (REQ-KVD-002 AC-AUDIT-2 extended for REQ-KVD-CLI-010 hmac_version).
pub fn verify_chain(conn: &Connection, hmac_key: &[u8]) -> KvendraResult<()> {
    let events = list_all(conn)?;
    let mut prev = String::new();
    for ev in events {
        if ev.prev_hmac_hex != prev {
            return Err(KvendraError::AuditChainBroken(ev.id));
        }
        let recomputed = if ev.hmac_version >= 2 {
            compute_hmac_v2(
                hmac_key,
                ev.id,
                ev.ts_unix_ms,
                &ev.profile_id,
                &ev.primitive,
                &ev.action,
                &ev.args_hash_hex,
                &ev.status,
                &ev.severity,
                &ev.flags,
                &ev.prev_hmac_hex,
                ev.remote_audit_id.as_deref(),
            )
        } else {
            compute_hmac_v1(
                hmac_key,
                ev.id,
                ev.ts_unix_ms,
                &ev.profile_id,
                &ev.primitive,
                &ev.action,
                &ev.args_hash_hex,
                &ev.status,
                &ev.severity,
                &ev.flags,
                &ev.prev_hmac_hex,
            )
        };
        if recomputed != ev.hmac_hex {
            return Err(KvendraError::AuditChainBroken(ev.id));
        }
        prev = ev.hmac_hex;
    }
    Ok(())
}

/// Compute SHA-256 of a JSON value, hex-encoded — used as `args_hash`.
pub fn args_hash_hex(args: &serde_json::Value) -> String {
    use sha2::{Digest, Sha256};
    let s = serde_json::to_string(args).unwrap_or_default();
    let digest = Sha256::digest(s.as_bytes());
    hex::encode(digest)
}
