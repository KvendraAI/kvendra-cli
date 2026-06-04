//! Audit writer — single-task owner of the SQLite Connection.
//!
//! Per ADR-KVD-007 we keep the SQLite handle on a dedicated blocking task
//! and feed it via `tokio::sync::mpsc`. This serializes writes, removes
//! contention, and lets async callers `await` enqueue without blocking the
//! reactor.
//!
//! Post-v3 migration every new row writes with `hmac_version = 3` and the
//! HMAC includes `remote_audit_id` plus `error_code` / `error_message` (each
//! NULL canonicalized to the empty string). The `update_event_status` path
//! re-hashes under v3 as well to keep the row's HMAC in sync with the
//! post-update status/severity and the error diagnostics it stamps.

use crate::audit::hmac::compute_hmac_v3;
use crate::audit::schema::init;
use crate::audit::{AuditEvent, Severity, Status};
use crate::error::{KvendraError, KvendraResult};
use rusqlite::Connection;
use std::path::PathBuf;
use tokio::sync::{mpsc, oneshot};

/// Async-safe handle to the audit writer.
#[derive(Clone)]
pub struct AuditWriter {
    tx: mpsc::Sender<WriterCmd>,
}

enum WriterCmd {
    Record {
        event: AuditEvent,
        ack: oneshot::Sender<KvendraResult<i64>>,
    },
    UpdateStatus {
        id: i64,
        status: Status,
        severity: Severity,
        error_code: Option<String>,
        error_message: Option<String>,
        ack: oneshot::Sender<KvendraResult<()>>,
    },
    Shutdown,
}

impl AuditWriter {
    /// Spawn the writer task with a fresh connection.
    pub fn spawn(db_path: PathBuf, hmac_key: Vec<u8>) -> KvendraResult<Self> {
        let (tx, mut rx) = mpsc::channel::<WriterCmd>(256);
        let conn = Connection::open(&db_path)?;
        init(&conn)?;

        std::thread::spawn(move || {
            // Owner thread: holds Connection (not Send). Pulls commands off
            // an mpsc Receiver via blocking_recv.
            let conn = conn;
            while let Some(cmd) = rx.blocking_recv() {
                match cmd {
                    WriterCmd::Record { event, ack } => {
                        let r = record_event(&conn, &hmac_key, &event);
                        let _ = ack.send(r);
                    }
                    WriterCmd::UpdateStatus {
                        id,
                        status,
                        severity,
                        error_code,
                        error_message,
                        ack,
                    } => {
                        let r = update_event_status(
                            &conn,
                            &hmac_key,
                            id,
                            status,
                            severity,
                            error_code.as_deref(),
                            error_message.as_deref(),
                        );
                        let _ = ack.send(r);
                    }
                    WriterCmd::Shutdown => break,
                }
            }
        });

        Ok(Self { tx })
    }

    /// Record a new audit event and return its row id.
    pub async fn record(&self, event: AuditEvent) -> KvendraResult<i64> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(WriterCmd::Record { event, ack: tx })
            .await
            .map_err(|_| KvendraError::Audit("writer channel closed".into()))?;
        rx.await
            .map_err(|_| KvendraError::Audit("writer ack dropped".into()))?
    }

    /// Update an existing event's status (after primitive execution).
    ///
    /// On the error path the caller passes the classified `error_code` and the
    /// already-sanitized `error_message`; both are persisted and bound to the
    /// v3 HMAC. `ok` updates pass `None`/`None`.
    pub async fn update_status(
        &self,
        id: i64,
        status: Status,
        severity: Severity,
        error_code: Option<String>,
        error_message: Option<String>,
    ) -> KvendraResult<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(WriterCmd::UpdateStatus {
                id,
                status,
                severity,
                error_code,
                error_message,
                ack: tx,
            })
            .await
            .map_err(|_| KvendraError::Audit("writer channel closed".into()))?;
        rx.await
            .map_err(|_| KvendraError::Audit("writer ack dropped".into()))?
    }

    pub async fn shutdown(&self) {
        let _ = self.tx.send(WriterCmd::Shutdown).await;
    }
}

fn record_event(conn: &Connection, hmac_key: &[u8], event: &AuditEvent) -> KvendraResult<i64> {
    // Fetch previous hmac (or empty for first row).
    let prev: String = conn
        .query_row(
            "SELECT hmac_hex FROM audit_events ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap_or_default();

    // Insert with placeholder hmac to obtain the autoincrement id.
    conn.execute(
        "INSERT INTO audit_events (ts_unix_ms, profile_id, primitive, action, args_hash_hex,
         status, severity, flags, prev_hmac_hex, hmac_hex, remote_audit_id, hmac_version,
         error_code, error_message)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        rusqlite::params![
            event.ts_unix_ms,
            event.profile_id,
            event.primitive,
            event.action,
            event.args_hash_hex,
            event.status.as_str(),
            event.severity.as_str(),
            event.flags,
            prev,
            "",
            event.remote_audit_id,
            3_i64,
            event.error_code,
            event.error_message,
        ],
    )?;
    let id = conn.last_insert_rowid();

    let mac = compute_hmac_v3(
        hmac_key,
        id,
        event.ts_unix_ms,
        &event.profile_id,
        &event.primitive,
        &event.action,
        &event.args_hash_hex,
        event.status.as_str(),
        event.severity.as_str(),
        &event.flags,
        &prev,
        event.remote_audit_id.as_deref(),
        event.error_code.as_deref(),
        event.error_message.as_deref(),
    );

    conn.execute(
        "UPDATE audit_events SET hmac_hex = ?1 WHERE id = ?2",
        rusqlite::params![mac, id],
    )?;
    Ok(id)
}

/// The subset of `audit_events` columns `update_event_status` needs to
/// re-derive a row's HMAC after a status/error update.
struct RehashRow {
    ts_unix_ms: i64,
    profile_id: String,
    primitive: String,
    action: String,
    args_hash_hex: String,
    flags: String,
    prev_hmac: String,
    remote_audit_id: Option<String>,
    hmac_version: i64,
    error_code: Option<String>,
    error_message: Option<String>,
}

#[allow(clippy::too_many_arguments)]
fn update_event_status(
    conn: &Connection,
    hmac_key: &[u8],
    id: i64,
    status: Status,
    severity: Severity,
    error_code: Option<&str>,
    error_message: Option<&str>,
) -> KvendraResult<()> {
    // 1) Update status + severity + the error diagnostics. The error columns
    // are only set when the caller supplies them (error path) — an `ok`
    // update passes None/None and leaves them NULL.
    conn.execute(
        "UPDATE audit_events SET status = ?1, severity = ?2, error_code = ?3, error_message = ?4
         WHERE id = ?5",
        rusqlite::params![
            status.as_str(),
            severity.as_str(),
            error_code,
            error_message,
            id
        ],
    )?;

    // 2) Re-compute HMAC over the updated row and persist. We pull
    // `hmac_version`, `remote_audit_id` and the (now-updated) error columns so
    // the function can dispatch to the right HMAC layout. Without this the
    // chain breaks when `verify` recomputes the row's HMAC using post-update
    // values while the stored HMAC was signed over pre-update ones.
    let row = conn.query_row(
        "SELECT ts_unix_ms, profile_id, primitive, action, args_hash_hex, flags, prev_hmac_hex,
                remote_audit_id, hmac_version, error_code, error_message
         FROM audit_events WHERE id = ?1",
        [id],
        |r| {
            Ok(RehashRow {
                ts_unix_ms: r.get(0)?,
                profile_id: r.get(1)?,
                primitive: r.get(2)?,
                action: r.get(3)?,
                args_hash_hex: r.get(4)?,
                flags: r.get(5)?,
                prev_hmac: r.get(6)?,
                remote_audit_id: r.get(7)?,
                hmac_version: r.get(8)?,
                error_code: r.get(9)?,
                error_message: r.get(10)?,
            })
        },
    )?;

    let mac = if row.hmac_version >= 3 {
        compute_hmac_v3(
            hmac_key,
            id,
            row.ts_unix_ms,
            &row.profile_id,
            &row.primitive,
            &row.action,
            &row.args_hash_hex,
            status.as_str(),
            severity.as_str(),
            &row.flags,
            &row.prev_hmac,
            row.remote_audit_id.as_deref(),
            row.error_code.as_deref(),
            row.error_message.as_deref(),
        )
    } else if row.hmac_version == 2 {
        crate::audit::hmac::compute_hmac_v2(
            hmac_key,
            id,
            row.ts_unix_ms,
            &row.profile_id,
            &row.primitive,
            &row.action,
            &row.args_hash_hex,
            status.as_str(),
            severity.as_str(),
            &row.flags,
            &row.prev_hmac,
            row.remote_audit_id.as_deref(),
        )
    } else {
        crate::audit::hmac::compute_hmac_v1(
            hmac_key,
            id,
            row.ts_unix_ms,
            &row.profile_id,
            &row.primitive,
            &row.action,
            &row.args_hash_hex,
            status.as_str(),
            severity.as_str(),
            &row.flags,
            &row.prev_hmac,
        )
    };

    conn.execute(
        "UPDATE audit_events SET hmac_hex = ?1 WHERE id = ?2",
        rusqlite::params![mac, id],
    )?;

    Ok(())
}
