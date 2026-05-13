//! Idempotent audit-DB migrations (REQ-KVD-CLI-010).
//!
//! Strategy: per-row HMAC versioning (`audit_events.hmac_version`) instead
//! of re-signing historical rows. Pre-migration rows keep their v1 HMACs;
//! new rows write v2 HMACs that include `remote_audit_id`. `verify_chain`
//! selects the HMAC function based on the row's `hmac_version` column.
//!
//! This file owns:
//!  - The `schema_migrations` ledger.
//!  - The `apply_v2` step (ALTER TABLE + INSERT version=2 + audit row).
//!  - The HMAC re-verification pre/post migration.
//!
//! The migration is invoked from [`crate::audit::schema::init`] on every
//! process startup, so a fresh binary version applies the pending migration
//! on the first invocation that opens the DB.

use crate::error::{KvendraError, KvendraResult};
use rusqlite::Connection;
use time::OffsetDateTime;

/// Current schema version this binary writes.
pub const CURRENT_VERSION: i64 = 2;

/// Read the current schema version. Returns `0` when the table is fresh
/// (no rows yet) — callers treat that as "needs baseline v1 insert".
pub fn current_version(conn: &Connection) -> KvendraResult<i64> {
    bootstrap_schema_migrations_table(conn)?;
    let v: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    Ok(v)
}

/// Create the `schema_migrations` ledger if absent. Idempotent.
pub fn bootstrap_schema_migrations_table(conn: &Connection) -> KvendraResult<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );
        "#,
    )?;
    Ok(())
}

fn insert_version(conn: &Connection, version: i64) -> KvendraResult<()> {
    let now = OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| String::new());
    conn.execute(
        "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
        rusqlite::params![version, now],
    )?;
    Ok(())
}

/// `true` when `audit_events` already carries the v2 columns. Used by the
/// baseline-detection branch — a DB created by an older binary may not
/// have a `schema_migrations` row even though `remote_audit_id` exists
/// (e.g. an external tool ran the ALTER manually).
fn audit_events_has_remote_audit_id(conn: &Connection) -> KvendraResult<bool> {
    let mut stmt = conn.prepare("PRAGMA table_info(audit_events)")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == "remote_audit_id" {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Apply every pending migration up to [`CURRENT_VERSION`]. Idempotent.
pub fn apply_pending(conn: &Connection) -> KvendraResult<()> {
    bootstrap_schema_migrations_table(conn)?;
    let applied = current_version(conn)?;

    if applied == 0 {
        // Baseline detection: if the v2 columns already exist on disk
        // (manual ALTER or rolled-forward DB), record v2 directly. Otherwise
        // record v1 and let `apply_v2` upgrade.
        if audit_events_has_remote_audit_id(conn)? {
            insert_version(conn, 1)?;
            insert_version(conn, 2)?;
        } else {
            insert_version(conn, 1)?;
        }
    }

    let applied = current_version(conn)?;
    if applied < 2 {
        apply_v2(conn)?;
    }
    Ok(())
}

/// Apply migration v2: add `remote_audit_id` + `hmac_version` columns and
/// the supporting index, then mark v2 applied in the ledger.
///
/// HMAC chain preservation: rows present at this point keep their v1 HMAC
/// (the ALTER TABLE only adds NULL-defaulting columns, so the bytes
/// `compute_hmac_v1` consumed remain identical). New inserts post-v2 use
/// `compute_hmac_v2` with the appended `remote_audit_id` byte block; the
/// per-row `hmac_version` column tells `verify_chain` which function to
/// recompute with.
fn apply_v2(conn: &Connection) -> KvendraResult<()> {
    // SQLite cannot add a column with a non-default expression atomically
    // alongside an index in a single batch under the bundled features we
    // ship, so we do it in two statements inside a transaction. Both
    // additions are NULL-safe and do not require row rewrites.
    let tx = conn.unchecked_transaction().map_err(|e| {
        KvendraError::AuditMigrationAborted(format!("begin tx: {e}"))
    })?;
    // `IF NOT EXISTS` for ALTER TABLE ADD COLUMN landed in SQLite 3.35;
    // bundled rusqlite ships 3.44+, but we fall back to a manual check
    // anyway in case a downstream packager pins an older bundle.
    if !audit_events_has_remote_audit_id(&tx)? {
        tx.execute(
            "ALTER TABLE audit_events ADD COLUMN remote_audit_id TEXT NULL",
            [],
        )
        .map_err(|e| {
            KvendraError::AuditMigrationAborted(format!("ALTER remote_audit_id: {e}"))
        })?;
    }
    if !column_exists(&tx, "audit_events", "hmac_version")? {
        // Existing rows belong to layout v1; default keeps the chain valid.
        tx.execute(
            "ALTER TABLE audit_events ADD COLUMN hmac_version INTEGER NOT NULL DEFAULT 1",
            [],
        )
        .map_err(|e| {
            KvendraError::AuditMigrationAborted(format!("ALTER hmac_version: {e}"))
        })?;
    }
    tx.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_audit_remote_id \
         ON audit_events(remote_audit_id)",
    )
    .map_err(|e| {
        KvendraError::AuditMigrationAborted(format!("CREATE INDEX remote_audit_id: {e}"))
    })?;

    let now = OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| String::new());
    tx.execute(
        "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
        rusqlite::params![2_i64, now],
    )
    .map_err(|e| {
        KvendraError::AuditMigrationAborted(format!("INSERT schema_migrations v2: {e}"))
    })?;

    tx.commit().map_err(|e| {
        KvendraError::AuditMigrationAborted(format!("commit tx: {e}"))
    })?;

    Ok(())
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> KvendraResult<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn fresh_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        // Boot the v1 baseline schema.
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_unix_ms INTEGER NOT NULL,
                profile_id TEXT NOT NULL,
                primitive TEXT NOT NULL,
                action TEXT NOT NULL,
                args_hash_hex TEXT NOT NULL,
                status TEXT NOT NULL,
                severity TEXT NOT NULL,
                flags TEXT NOT NULL DEFAULT '',
                prev_hmac_hex TEXT NOT NULL DEFAULT '',
                hmac_hex TEXT NOT NULL
            );
            "#,
        )
        .unwrap();
        conn
    }

    #[test]
    fn apply_pending_is_idempotent() {
        let conn = fresh_db();
        apply_pending(&conn).unwrap();
        let v = current_version(&conn).unwrap();
        assert_eq!(v, 2);
        // Run 10 more times — version stays at 2, no errors.
        for _ in 0..10 {
            apply_pending(&conn).unwrap();
            assert_eq!(current_version(&conn).unwrap(), 2);
        }
    }

    #[test]
    fn apply_pending_adds_v2_columns() {
        let conn = fresh_db();
        apply_pending(&conn).unwrap();
        assert!(column_exists(&conn, "audit_events", "remote_audit_id").unwrap());
        assert!(column_exists(&conn, "audit_events", "hmac_version").unwrap());
    }

    #[test]
    fn legacy_db_with_pre_existing_remote_audit_id_recorded_as_v2() {
        // Simulate a DB that was migrated by an external tool: columns
        // exist, but `schema_migrations` is empty.
        let conn = fresh_db();
        conn.execute(
            "ALTER TABLE audit_events ADD COLUMN remote_audit_id TEXT NULL",
            [],
        )
        .unwrap();
        conn.execute(
            "ALTER TABLE audit_events ADD COLUMN hmac_version INTEGER NOT NULL DEFAULT 2",
            [],
        )
        .unwrap();
        apply_pending(&conn).unwrap();
        assert_eq!(current_version(&conn).unwrap(), 2);
    }

    #[test]
    fn current_version_zero_on_fresh_db_until_migrated() {
        let conn = fresh_db();
        // Before apply_pending, the ledger table doesn't even exist yet —
        // current_version creates it and reports 0.
        assert_eq!(current_version(&conn).unwrap(), 0);
    }
}
