//! Audit writer — single-task owner of the SQLite Connection.
//!
//! Per ADR-KVD-007 we keep the SQLite handle on a dedicated blocking task
//! and feed it via `tokio::sync::mpsc`. This serializes writes, removes
//! contention, and lets async callers `await` enqueue without blocking the
//! reactor.

use crate::audit::hmac::compute_hmac;
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
                        ack,
                    } => {
                        let r = update_event_status(&conn, &hmac_key, id, status, severity);
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
    pub async fn update_status(
        &self,
        id: i64,
        status: Status,
        severity: Severity,
    ) -> KvendraResult<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(WriterCmd::UpdateStatus {
                id,
                status,
                severity,
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
         status, severity, flags, prev_hmac_hex, hmac_hex)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
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
        ],
    )?;
    let id = conn.last_insert_rowid();

    let mac = compute_hmac(
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
    );

    conn.execute(
        "UPDATE audit_events SET hmac_hex = ?1 WHERE id = ?2",
        rusqlite::params![mac, id],
    )?;
    Ok(id)
}

fn update_event_status(
    conn: &Connection,
    hmac_key: &[u8],
    id: i64,
    status: Status,
    severity: Severity,
) -> KvendraResult<()> {
    // 1) Update status + severity.
    conn.execute(
        "UPDATE audit_events SET status = ?1, severity = ?2 WHERE id = ?3",
        rusqlite::params![status.as_str(), severity.as_str(), id],
    )?;

    // 2) Re-compute HMAC over the updated row and persist.
    //
    // Without this, the chain breaks when `verify` recomputes the row's
    // HMAC using the post-update status/severity (e.g. "ok") while the
    // stored HMAC was signed over the pre-update values (e.g. "started").
    // Since the writer task is serial (mpsc + dedicated thread), the next
    // INSERT always observes the post-UPDATE HMAC as `prev_hmac`, so the
    // chain remains consistent.
    let (ts_unix_ms, profile_id, primitive, action, args_hash_hex, flags, prev_hmac): (
        i64,
        String,
        String,
        String,
        String,
        String,
        String,
    ) = conn.query_row(
        "SELECT ts_unix_ms, profile_id, primitive, action, args_hash_hex, flags, prev_hmac_hex
         FROM audit_events WHERE id = ?1",
        [id],
        |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        },
    )?;

    let mac = compute_hmac(
        hmac_key,
        id,
        ts_unix_ms,
        &profile_id,
        &primitive,
        &action,
        &args_hash_hex,
        status.as_str(),
        severity.as_str(),
        &flags,
        &prev_hmac,
    );

    conn.execute(
        "UPDATE audit_events SET hmac_hex = ?1 WHERE id = ?2",
        rusqlite::params![mac, id],
    )?;

    Ok(())
}
