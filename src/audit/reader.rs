//! Audit reader — query / export / verify HMAC chain.

use crate::audit::hmac::compute_hmac;
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
}

pub fn open_readonly(db_path: &Path) -> KvendraResult<Connection> {
    let conn = Connection::open(db_path)?;
    init(&conn)?;
    Ok(conn)
}

pub fn list_all(conn: &Connection) -> KvendraResult<Vec<StoredEvent>> {
    let mut stmt = conn.prepare(
        "SELECT id, ts_unix_ms, profile_id, primitive, action, args_hash_hex,
         status, severity, flags, prev_hmac_hex, hmac_hex
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
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Walk the chain from id ASC, recompute each row's HMAC, fail at the first
/// mismatch (REQ-KVD-002 AC-AUDIT-2).
pub fn verify_chain(conn: &Connection, hmac_key: &[u8]) -> KvendraResult<()> {
    let events = list_all(conn)?;
    let mut prev = String::new();
    for ev in events {
        if ev.prev_hmac_hex != prev {
            return Err(KvendraError::AuditChainBroken(ev.id));
        }
        let recomputed = compute_hmac(
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
        );
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
