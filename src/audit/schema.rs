//! SQLite schema + PRAGMAs + migrations for the audit log.

use crate::error::KvendraResult;
use rusqlite::Connection;

/// Apply PRAGMAs and create tables if absent.
pub fn init(conn: &Connection) -> KvendraResult<()> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;

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
    Ok(())
}
