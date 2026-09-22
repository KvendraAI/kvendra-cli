//! Audit reader — query / export / verify HMAC chain.

use crate::audit::hmac::{CURRENT_HMAC_LAYOUT, RowFields, compute_for_layout};
use crate::audit::layout_commit::{CommittedRow, is_legacy_layout, legacy_layout_digest};
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
    /// HMAC layout version (1 = legacy, 2 = remote_audit_id, 3 = error
    /// diagnostics, 4 = injective encoding). Defaults to 1 for rows that
    /// pre-date the schema migration; selects which layout `verify_chain`
    /// recomputes.
    pub hmac_version: i64,
    /// Closed-vocabulary diagnostic code for `status:error` rows
    /// (ISSUE-KVD-CLI-6C43AA). `None` for ok/started rows and pre-v3 rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Sanitized human-readable failure detail. `None` for non-error rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

pub fn open_readonly(db_path: &Path) -> KvendraResult<Connection> {
    let conn = Connection::open(db_path)?;
    init(&conn)?;
    Ok(conn)
}

pub fn list_all(conn: &Connection) -> KvendraResult<Vec<StoredEvent>> {
    list_from(conn, i64::MIN)
}

/// Every row with `id >= from_id`, id ASC (the tail of the chain starting at
/// `from_id`).
pub fn list_from(conn: &Connection, from_id: i64) -> KvendraResult<Vec<StoredEvent>> {
    // We `SELECT` the v2 columns explicitly because they may have been added
    // by the migration step earlier in the process — older binaries opening
    // the same file would have already had `apply_pending` upgrade the
    // schema for them too.
    let mut stmt = conn.prepare(
        "SELECT id, ts_unix_ms, profile_id, primitive, action, args_hash_hex,
         status, severity, flags, prev_hmac_hex, hmac_hex,
         remote_audit_id, hmac_version, error_code, error_message
         FROM audit_events WHERE id >= ?1 ORDER BY id ASC",
    )?;
    let rows = stmt.query_map([from_id], |row| {
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
            error_code: row.get(13)?,
            error_message: row.get(14)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

impl StoredEvent {
    /// The MAC-bound columns of this row.
    pub fn hmac_fields(&self) -> RowFields<'_> {
        RowFields {
            id: self.id,
            ts_unix_ms: self.ts_unix_ms,
            profile_id: &self.profile_id,
            primitive: &self.primitive,
            action: &self.action,
            args_hash_hex: &self.args_hash_hex,
            status: &self.status,
            severity: &self.severity,
            flags: &self.flags,
            prev_hmac_hex: &self.prev_hmac_hex,
            remote_audit_id: self.remote_audit_id.as_deref(),
            error_code: self.error_code.as_deref(),
            error_message: self.error_message.as_deref(),
        }
    }
}

impl StoredEvent {
    /// Whether this row's stored tag matches its columns under its own layout
    /// (the per-row half of [`verify_chain_report`]; prev-links not checked).
    pub fn mac_verifies(&self, hmac_key: &[u8]) -> KvendraResult<bool> {
        let recomputed = compute_for_layout(hmac_key, self.hmac_version, &self.hmac_fields())
            .map_err(|e| KvendraError::AuditLayoutViolation {
                row: self.id,
                reason: e.to_string(),
            })?;
        Ok(recomputed == self.hmac_hex)
    }
}

/// Outcome of a successful [`verify_chain_report`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainReport {
    /// Rows verified.
    pub rows: usize,
    /// Rows under a legacy layout (v1/v2/v3).
    pub legacy_rows: usize,
    /// Layout commitment rows (`kvendra audit commit-layout`), each checked
    /// against the digest of every legacy row.
    pub commitment_rows: usize,
}

impl ChainReport {
    /// Legacy rows pinned by a verified layout commitment (all or none: a
    /// commitment always covers every legacy row).
    pub fn committed_legacy_rows(&self) -> usize {
        if self.commitment_rows > 0 {
            self.legacy_rows
        } else {
            0
        }
    }

    /// Legacy rows whose unbound columns (v1 `remote_audit_id`, v1/v2 error
    /// diagnostics, NULL-vs-empty) are not yet pinned by a commitment.
    pub fn uncommitted_legacy_rows(&self) -> usize {
        self.legacy_rows - self.committed_legacy_rows()
    }
}

/// Walk the chain from id ASC, recompute each row's HMAC under the layout
/// version recorded in that row, and fail at the first mismatch
/// (REQ-KVD-002 AC-AUDIT-2 extended for REQ-KVD-CLI-010 hmac_version).
///
/// ISSUE-KVD-CLI-F4ED93: the layout is dispatched exhaustively
/// ([`compute_for_layout`]) — an unknown layout or a non-canonical legacy row
/// is an [`KvendraError::AuditLayoutViolation`], never silently absorbed. Once
/// a row of the current layout appears, no legacy-layout row may follow it:
/// the post-fix writer only ever emits the current layout.
pub fn verify_chain(conn: &Connection, hmac_key: &[u8]) -> KvendraResult<()> {
    verify_chain_report(conn, hmac_key).map(|_| ())
}

/// [`verify_chain`], plus: every layout commitment row must carry the digest
/// of all legacy rows before it (which, since legacy-after-v4 is refused, is
/// every legacy row in the log) — else [`KvendraError::AuditLayoutViolation`]
/// at the commitment row.
pub fn verify_chain_report(conn: &Connection, hmac_key: &[u8]) -> KvendraResult<ChainReport> {
    let events = list_all(conn)?;
    let mut prev = String::new();
    let mut seen_current_layout = false;
    let mut legacy: Vec<CommittedRow<'_>> = Vec::new();
    let mut commitment_rows = 0usize;
    for ev in &events {
        if ev.prev_hmac_hex != prev {
            return Err(KvendraError::AuditChainBroken(ev.id));
        }
        if seen_current_layout && ev.hmac_version < CURRENT_HMAC_LAYOUT {
            return Err(KvendraError::AuditLayoutViolation {
                row: ev.id,
                reason: format!(
                    "legacy layout v{} after a layout v{CURRENT_HMAC_LAYOUT} row",
                    ev.hmac_version
                ),
            });
        }
        if !ev.mac_verifies(hmac_key)? {
            return Err(KvendraError::AuditChainBroken(ev.id));
        }
        if ev.is_layout_commitment() {
            if legacy_layout_digest(&legacy) != ev.args_hash_hex {
                return Err(KvendraError::AuditLayoutViolation {
                    row: ev.id,
                    reason: format!(
                        "legacy layout commitment mismatch: the {} legacy row(s) it pins were \
                         altered (incl. columns outside their legacy MAC)",
                        legacy.len()
                    ),
                });
            }
            commitment_rows += 1;
        }
        if is_legacy_layout(ev.hmac_version) {
            legacy.push(ev.committed_row());
        }
        if ev.hmac_version == CURRENT_HMAC_LAYOUT {
            seen_current_layout = true;
        }
        prev.clone_from(&ev.hmac_hex);
    }
    Ok(ChainReport {
        rows: events.len(),
        legacy_rows: legacy.len(),
        commitment_rows,
    })
}

/// Compute SHA-256 of a JSON value, hex-encoded — used as `args_hash`.
pub fn args_hash_hex(args: &serde_json::Value) -> String {
    use sha2::{Digest, Sha256};
    let s = serde_json::to_string(args).unwrap_or_default();
    let digest = Sha256::digest(s.as_bytes());
    hex::encode(digest)
}
