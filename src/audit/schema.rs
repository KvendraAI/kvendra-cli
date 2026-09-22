//! SQLite schema + PRAGMAs + migrations for the audit log.

use crate::error::KvendraResult;
use rusqlite::Connection;
use std::time::Duration;

/// How long a connection waits on a contended audit-DB lock before SQLite
/// reports SQLITE_BUSY.
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Apply PRAGMAs, create base tables, and run any pending migrations.
///
/// Idempotent — safe to call on every process startup.
pub fn init(conn: &Connection) -> KvendraResult<()> {
    // Several processes share one audit DB (every `kvendra mcp` server, the
    // CLI's `commit-layout` / `unlock` / `config` writers). Writers serialise
    // on `BEGIN IMMEDIATE` (see `writer::with_immediate_txn`); this makes a
    // contended lock wait instead of failing with SQLITE_BUSY at once.
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;

    // v1 baseline tables. We keep the CREATE at the v1 shape so the migration
    // ladder (apply_pending) is exercised identically for both fresh and
    // upgraded DBs — `remote_audit_id`/`hmac_version` (v2) and
    // `error_code`/`error_message` (v3) are added by their migration steps.
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
        CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts_unix_ms);
        CREATE INDEX IF NOT EXISTS idx_audit_profile ON audit_events(profile_id);
        "#,
    )?;

    // Apply any pending migrations (v1 → v2 → ...). Best-effort: errors
    // bubble up so callers can decide whether to abort. Migrations are
    // idempotent.
    crate::audit::migrations::apply_pending(conn)?;
    Ok(())
}
