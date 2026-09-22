//! Audit writer — single-task owner of the SQLite Connection.
//!
//! Per ADR-KVD-007 we keep the SQLite handle on a dedicated blocking task
//! and feed it via `tokio::sync::mpsc`. This serializes writes, removes
//! contention, and lets async callers `await` enqueue without blocking the
//! reactor.
//!
//! Every new row writes with `hmac_version = CURRENT_HMAC_LAYOUT` (4, the
//! injective encoding of ISSUE-KVD-CLI-F4ED93) over the same columns as v3:
//! `remote_audit_id` plus `error_code` / `error_message`. The
//! `update_event_status` path re-hashes under the row's own layout to keep
//! the row's HMAC in sync with the post-update status/severity and the error
//! diagnostics it stamps, and re-chains any rows appended after it.
//!
//! The mpsc task serialises writes within ONE process only. Several processes
//! (every `kvendra mcp` server, CLI writers, `kvendra audit commit-layout`)
//! share the same DB, so every write — the tip read, the INSERT and the tag
//! UPDATE — runs inside one `BEGIN IMMEDIATE` transaction
//! ([`with_immediate_txn`], SA4-F4).

use crate::audit::hmac::{CURRENT_HMAC_LAYOUT, compute_for_layout, compute_hmac_v4};
use crate::audit::layout_commit::is_legacy_layout;
use crate::audit::reader::{StoredEvent, list_from};
use crate::audit::schema::{BUSY_TIMEOUT, init};
use crate::audit::{AuditEvent, Severity, Status};
use crate::error::{KvendraError, KvendraResult};
use rusqlite::{Connection, ErrorCode, OptionalExtension};
use std::path::PathBuf;
use std::time::Duration;
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
    /// row HMAC. `ok` updates pass `None`/`None`.
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

/// Attempts at `BEGIN IMMEDIATE` before a contended write lock is reported as
/// an error. Each attempt already waits up to [`BUSY_TIMEOUT`] inside SQLite.
const WRITE_LOCK_ATTEMPTS: u32 = 3;

fn is_busy(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(f, _)
            if matches!(f.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}

fn begin_immediate(conn: &Connection) -> KvendraResult<()> {
    let mut attempt = 1;
    loop {
        match conn.execute_batch("BEGIN IMMEDIATE") {
            Ok(()) => return Ok(()),
            Err(e) if is_busy(&e) && attempt < WRITE_LOCK_ATTEMPTS => {
                attempt += 1;
                std::thread::sleep(Duration::from_millis(50 * u64::from(attempt)));
            }
            Err(e) if is_busy(&e) => {
                return Err(KvendraError::Audit(format!(
                    "audit log is locked by another writer: gave up after {WRITE_LOCK_ATTEMPTS} \
                     attempts of {}s each ({e}); nothing was written",
                    BUSY_TIMEOUT.as_secs()
                )));
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Run `f` as ONE write transaction taken with `BEGIN IMMEDIATE`, so every
/// read-then-write of the chain tip is atomic against every other writer —
/// other threads, other `kvendra mcp` processes, `kvendra audit
/// commit-layout` (SA4-F4). The write lock is acquired up front, so the
/// statements inside never hit SQLITE_BUSY / a stale WAL snapshot; a
/// contended lock waits [`BUSY_TIMEOUT`] per attempt and is retried
/// [`WRITE_LOCK_ATTEMPTS`] times, then surfaces as an error (the row is never
/// dropped silently — the caller gets the `Err`). Any error rolls the whole
/// transaction back, so no half-written row (placeholder `hmac_hex = ''`) is
/// ever visible.
///
/// If the connection is already inside a transaction, `f` runs inline in it:
/// the caller owns atomicity and MUST have opened it with `BEGIN IMMEDIATE`
/// (as [`crate::audit::layout_commit::commit_legacy_layout`] does).
pub(crate) fn with_immediate_txn<T>(
    conn: &Connection,
    f: impl FnOnce(&Connection) -> KvendraResult<T>,
) -> KvendraResult<T> {
    if !conn.is_autocommit() {
        return f(conn);
    }
    begin_immediate(conn)?;
    let r = f(conn).and_then(|v| conn.execute_batch("COMMIT").map(|()| v).map_err(Into::into));
    if r.is_err() && !conn.is_autocommit() {
        let _ = conn.execute_batch("ROLLBACK");
    }
    r
}

pub(crate) fn record_event(
    conn: &Connection,
    hmac_key: &[u8],
    event: &AuditEvent,
) -> KvendraResult<i64> {
    with_immediate_txn(conn, |conn| record_in_txn(conn, hmac_key, event))
}

fn record_in_txn(conn: &Connection, hmac_key: &[u8], event: &AuditEvent) -> KvendraResult<i64> {
    // Fetch previous hmac (or empty for first row).
    let prev: String = conn
        .query_row(
            "SELECT hmac_hex FROM audit_events ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or_default();

    // Insert with placeholder hmac to obtain the autoincrement id. Invisible
    // to every other connection: the transaction commits only after the real
    // tag is in place.
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
            CURRENT_HMAC_LAYOUT,
            event.error_code,
            event.error_message,
        ],
    )?;
    let id = conn.last_insert_rowid();

    let mac = compute_hmac_v4(
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

/// Stamp the final status / severity / error diagnostics on row `id` and
/// re-derive its HMAC (layouts v1–v4 are unchanged: status and diagnostics
/// stay inside the MAC).
///
/// The dispatcher records a `started` row, runs the primitive, then calls
/// this — so by then other rows may already have chained onto row `id`'s OLD
/// tag (a concurrent tool call in the same server, another `kvendra mcp`
/// process, a CLI writer). Re-hashing only row `id` then broke the successor's
/// prev-link: the pre-existing CHAIN_BROKEN on long-lived logs. Fix (one
/// `BEGIN IMMEDIATE` transaction, all or nothing):
///
///  1. Refuse to re-sign anything that does not verify NOW: row `id`'s current
///     tag must match its current columns, and every successor must link to
///     its predecessor's current tag and carry a valid layout-v4 MAC. The key
///     holder re-signs only authentic rows — a tampered row is reported
///     (`AuditChainBroken` / `AuditLayoutViolation`), never laundered.
///  2. Update row `id`, then re-chain each successor: new `prev_hmac_hex` =
///     predecessor's new tag, tag recomputed under its own (v4) layout.
///
/// A legacy-layout row (v1–v3) is only updatable while it is the chain tip:
/// re-chaining after it could invalidate a layout commitment's digest.
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
    with_immediate_txn(conn, |conn| {
        update_in_txn(
            conn,
            hmac_key,
            id,
            status,
            severity,
            error_code,
            error_message,
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn update_in_txn(
    conn: &Connection,
    hmac_key: &[u8],
    id: i64,
    status: Status,
    severity: Severity,
    error_code: Option<&str>,
    error_message: Option<&str>,
) -> KvendraResult<()> {
    let rows = list_from(conn, id)?;
    let Some((target, successors)) = rows.split_first().filter(|(t, _)| t.id == id) else {
        return Err(KvendraError::Audit(format!(
            "audit row {id} not found for status update"
        )));
    };

    // 1) Everything we are about to re-sign must verify as it stands.
    if !target.mac_verifies(hmac_key)? {
        return Err(KvendraError::AuditChainBroken(id));
    }
    if !successors.is_empty() && is_legacy_layout(target.hmac_version) {
        return Err(KvendraError::AuditLayoutViolation {
            row: id,
            reason: format!(
                "status update of a legacy layout v{} row that already has successors",
                target.hmac_version
            ),
        });
    }
    let mut expected_prev = target.hmac_hex.as_str();
    for s in successors {
        if s.prev_hmac_hex != expected_prev {
            return Err(KvendraError::AuditChainBroken(s.id));
        }
        if s.hmac_version != CURRENT_HMAC_LAYOUT {
            return Err(KvendraError::AuditLayoutViolation {
                row: s.id,
                reason: format!(
                    "legacy layout v{} after a layout v{CURRENT_HMAC_LAYOUT} row",
                    s.hmac_version
                ),
            });
        }
        if !s.mac_verifies(hmac_key)? {
            return Err(KvendraError::AuditChainBroken(s.id));
        }
        expected_prev = &s.hmac_hex;
    }

    // 2) Re-sign the target under its own layout, then re-chain successors.
    let mut updated: StoredEvent = target.clone();
    updated.status = status.as_str().to_string();
    updated.severity = severity.as_str().to_string();
    updated.error_code = error_code.map(str::to_string);
    updated.error_message = error_message.map(str::to_string);
    let mut tag = compute_for_layout(hmac_key, updated.hmac_version, &updated.hmac_fields())
        .map_err(|e| KvendraError::Audit(format!("re-hash of row {id}: {e}")))?;
    conn.execute(
        "UPDATE audit_events SET status = ?1, severity = ?2, error_code = ?3, error_message = ?4,
         hmac_hex = ?5 WHERE id = ?6",
        rusqlite::params![
            updated.status,
            updated.severity,
            updated.error_code,
            updated.error_message,
            tag,
            id
        ],
    )?;
    for s in successors {
        let mut next = s.clone();
        next.prev_hmac_hex = tag;
        tag = compute_for_layout(hmac_key, next.hmac_version, &next.hmac_fields())
            .map_err(|e| KvendraError::Audit(format!("re-chain of row {}: {e}", s.id)))?;
        conn.execute(
            "UPDATE audit_events SET prev_hmac_hex = ?1, hmac_hex = ?2 WHERE id = ?3",
            rusqlite::params![next.prev_hmac_hex, tag, s.id],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::reader::{list_all, verify_chain};
    use std::sync::{Arc, Barrier};

    const K: &[u8] = b"writer-concurrency-test-key";

    fn open(path: &std::path::Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        init(&conn).unwrap();
        conn
    }

    fn ev(tag: &str, i: usize) -> AuditEvent {
        AuditEvent {
            ts_unix_ms: 1_700_000_000_000 + i as i64,
            profile_id: format!("p-{tag}"),
            primitive: "kvendra.shell".into(),
            action: "exec".into(),
            args_hash_hex: format!("{i:064x}"),
            status: Status::Started,
            severity: Severity::Info,
            flags: String::new(),
            remote_audit_id: None,
            error_code: None,
            error_message: None,
        }
    }

    /// The dispatcher's `record(started)` → work → `update_status` shape.
    fn dispatch_like(conn: &Connection, tag: &str, i: usize) {
        let id = record_event(conn, K, &ev(tag, i)).unwrap();
        let (st, sev, code, msg) = if i.is_multiple_of(3) {
            (
                Status::Error,
                Severity::Warn,
                Some("ALLOWLIST_VIOLATION"),
                Some("m"),
            )
        } else {
            (Status::Ok, Severity::Info, None, None)
        };
        update_event_status(conn, K, id, st, sev, code, msg).unwrap();
    }

    /// Two independent connections (≈ two `kvendra mcp` processes) writing at
    /// once must never fork the chain — pre-fix: broken 5/5.
    #[test]
    fn two_concurrent_writers_keep_one_chain() {
        for run in 0..5 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("audit.db");
            drop(open(&path));
            let barrier = Arc::new(Barrier::new(2));
            let handles: Vec<_> = ["a", "b"]
                .into_iter()
                .map(|tag| {
                    let (path, barrier) = (path.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        let conn = open(&path);
                        barrier.wait();
                        for i in 0..40usize {
                            if i.is_multiple_of(2) {
                                record_event(&conn, K, &ev(tag, i)).unwrap();
                            } else {
                                dispatch_like(&conn, tag, i);
                            }
                        }
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap();
            }
            let conn = open(&path);
            assert_eq!(list_all(&conn).unwrap().len(), 80, "run {run}");
            let r = verify_chain(&conn, K);
            assert!(r.is_ok(), "run {run}: {r:?}");
        }
    }

    /// The pre-existing logic bug, single writer: row N+1 chains onto N's
    /// tag, THEN N's status update lands. Pre-fix: CHAIN_BROKEN(N+1).
    #[test]
    fn status_update_after_a_successor_rechains_it() {
        let dir = tempfile::tempdir().unwrap();
        let conn = open(&dir.path().join("audit.db"));
        let a = record_event(&conn, K, &ev("a", 1)).unwrap();
        let b = record_event(&conn, K, &ev("b", 2)).unwrap();
        let c = record_event(&conn, K, &ev("c", 3)).unwrap();
        update_event_status(
            &conn,
            K,
            a,
            Status::Error,
            Severity::Error,
            Some("PRIMITIVE_FAILED"),
            Some("boom"),
        )
        .unwrap();
        update_event_status(&conn, K, c, Status::Ok, Severity::Info, None, None).unwrap();
        update_event_status(&conn, K, b, Status::Ok, Severity::Info, None, None).unwrap();
        verify_chain(&conn, K).unwrap();
        let rows = list_all(&conn).unwrap();
        assert_eq!(rows[0].status, "error");
        assert_eq!(rows[0].error_message.as_deref(), Some("boom"));
        assert_eq!(
            (rows[1].status.as_str(), rows[2].status.as_str()),
            ("ok", "ok")
        );
    }

    /// Re-signing never launders a tamper: a forged target or a forged /
    /// unlinked successor makes the update fail and change nothing.
    #[test]
    fn status_update_refuses_to_resign_tampered_rows() {
        for sql in [
            // Forged target column (its MAC no longer verifies).
            "UPDATE audit_events SET action = 'forged' WHERE id = 1",
            // Forged successor column.
            "UPDATE audit_events SET action = 'forged' WHERE id = 3",
            // Successor that no longer links to its predecessor.
            "UPDATE audit_events SET prev_hmac_hex = 'stale' WHERE id = 2",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let conn = open(&dir.path().join("audit.db"));
            for i in 0..3 {
                record_event(&conn, K, &ev("x", i)).unwrap();
            }
            conn.execute(sql, []).unwrap();
            let before = list_all(&conn).unwrap();
            let r = update_event_status(&conn, K, 1, Status::Ok, Severity::Info, None, None);
            assert!(
                matches!(r, Err(KvendraError::AuditChainBroken(_))),
                "{sql}: {r:?}"
            );
            let after = list_all(&conn).unwrap();
            for (x, y) in before.iter().zip(&after) {
                assert_eq!(
                    (&x.status, &x.hmac_hex, &x.prev_hmac_hex),
                    (&y.status, &y.hmac_hex, &y.prev_hmac_hex),
                    "{sql}: a refused update must change nothing"
                );
            }
            assert!(conn.is_autocommit(), "{sql}: transaction left open");
        }
    }

    #[test]
    fn status_update_of_a_missing_row_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let conn = open(&dir.path().join("audit.db"));
        record_event(&conn, K, &ev("x", 0)).unwrap();
        assert!(update_event_status(&conn, K, 9, Status::Ok, Severity::Info, None, None).is_err());
        assert!(conn.is_autocommit());
    }

    /// A writer blocked by another connection's write transaction waits for
    /// it (busy_timeout) instead of failing, and chains after whatever the
    /// lock holder appended.
    #[test]
    fn contended_write_lock_waits_then_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let holder = open(&path);
        record_event(&holder, K, &ev("h", 0)).unwrap();
        holder.execute_batch("BEGIN IMMEDIATE").unwrap();
        let p2 = path.clone();
        let t = std::thread::spawn(move || {
            let conn = open(&p2);
            record_event(&conn, K, &ev("w", 1))
        });
        std::thread::sleep(Duration::from_millis(300));
        record_event(&holder, K, &ev("h", 2)).unwrap();
        holder.execute_batch("COMMIT").unwrap();
        assert_eq!(t.join().unwrap().unwrap(), 3);
        verify_chain(&holder, K).unwrap();
    }
}
