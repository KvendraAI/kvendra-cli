//! Pre-authentication rejection log (REQ-KVD-CLI-CFB449 AC-REC-7).
//!
//! A rejected `recover` / `passwd` happens before any vault key exists, so
//! there is no HMAC key to append to `audit.db` ("pre-unlock audit gap").
//! The rejection is appended to `audit.preauth.jsonl` (0600, at most
//! [`MAX_LINES`] lines, oldest dropped) with a closed vocabulary and NO
//! secret: no phrase, no password, nothing derived. The next process that
//! holds the vault key imports every line into the HMAC chain as a row
//! flagged `preauth_unauthenticated` and empties the file.
//!
//! The file is not authenticated: anyone who can write it can forge lines.
//! That is why imported rows carry the flag, and why only known `action` /
//! `reason` values and a numeric timestamp are accepted (anything else is
//! skipped, so the file cannot smuggle text into the chain).

use crate::audit::{
    AuditEvent, AuditWriter, FLAG_PREAUTH_UNAUTHENTICATED, PRIMITIVE_SYSTEM, Severity, Status,
    reader::args_hash_hex,
};
use crate::error::KvendraResult;
use crate::vault::fsutil;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// File name under the vault home.
pub const FILE_NAME: &str = "audit.preauth.jsonl";
/// Retention cap (lines), enforced on append AND on import.
pub const MAX_LINES: usize = 1000;
/// Size cap enforced on import: only the last `MAX_BYTES` of the file are
/// read (a well-formed line is < 200 bytes, so this covers `MAX_LINES`).
pub const MAX_BYTES: u64 = 256 * 1024;

/// Commands that log pre-auth rejections.
const ACTIONS: &[&str] = &["recover", "passwd"];

/// Closed set of rejection reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    PhraseInvalid,
    PhraseMismatch,
    Unavailable,
    MaterialCorrupt,
    PasswordInvalid,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::PhraseInvalid => "phrase_invalid",
            Reason::PhraseMismatch => "phrase_mismatch",
            Reason::Unavailable => "unavailable",
            Reason::MaterialCorrupt => "material_corrupt",
            Reason::PasswordInvalid => "password_invalid",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "phrase_invalid" => Reason::PhraseInvalid,
            "phrase_mismatch" => Reason::PhraseMismatch,
            "unavailable" => Reason::Unavailable,
            "material_corrupt" => Reason::MaterialCorrupt,
            "password_invalid" => Reason::PasswordInvalid,
            _ => return None,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Line {
    /// Random 128-bit id (hex). Makes the import idempotent: a line whose id
    /// is already in the chain is not imported again (crash mid-import).
    id: String,
    ts_unix_ms: i64,
    action: String,
    status: String,
    reason: String,
}

fn new_line_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// `args_hash` of an imported row: binds the reason and the line id.
fn row_args_hash(id: &str, reason: Reason) -> String {
    args_hash_hex(&serde_json::json!({ "preauth_id": id, "reason": reason.as_str() }))
}

pub fn path(home: &Path) -> PathBuf {
    home.join(FILE_NAME)
}

fn now_ms() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64 / 1_000_000
}

/// Append one rejection. Best effort: a failure here never changes the
/// outcome of the command (it is logged via tracing instead).
pub fn record_rejection(home: &Path, action: &'static str, reason: Reason) {
    tracing::warn!(
        target: "kvendra::audit",
        action,
        reason = reason.as_str(),
        "pre-auth rejection (recorded in audit.preauth.jsonl)"
    );
    if let Err(e) = append(home, action, reason) {
        tracing::warn!(target: "kvendra::audit", "audit.preauth.jsonl not written: {e}");
    }
}

fn append(home: &Path, action: &str, reason: Reason) -> KvendraResult<()> {
    let p = path(home);
    let existing = match std::fs::read_to_string(&p) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };
    let mut lines: Vec<&str> = existing.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() >= MAX_LINES {
        lines.drain(..lines.len() + 1 - MAX_LINES);
    }
    let new_line = serde_json::to_string(&Line {
        id: new_line_id(),
        ts_unix_ms: now_ms(),
        action: action.into(),
        status: "rejected".into(),
        reason: reason.as_str().into(),
    })?;
    let mut out = String::with_capacity(existing.len() + new_line.len() + 1);
    for l in lines {
        out.push_str(l);
        out.push('\n');
    }
    out.push_str(&new_line);
    out.push('\n');
    fsutil::write_atomic(&p, out.as_bytes())
}

/// Validated lines currently pending import: at most the last
/// [`MAX_BYTES`] of the file and the last [`MAX_LINES`] valid lines.
fn pending(home: &Path) -> KvendraResult<Vec<(String, i64, &'static str, Reason)>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = match std::fs::File::open(path(home)) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let len = f.metadata()?.len();
    let truncated = len > MAX_BYTES;
    if truncated {
        f.seek(SeekFrom::Start(len - MAX_BYTES))?;
    }
    let mut buf = Vec::with_capacity(len.min(MAX_BYTES) as usize);
    f.take(MAX_BYTES).read_to_end(&mut buf)?;
    let raw = String::from_utf8_lossy(&buf);
    let mut lines = raw.lines();
    if truncated {
        // The first line may be cut in the middle.
        lines.next();
    }
    let mut out = Vec::new();
    for l in lines {
        let Ok(line) = serde_json::from_str::<Line>(l) else {
            continue;
        };
        let Some(action) = ACTIONS.iter().find(|a| **a == line.action) else {
            continue;
        };
        let Some(reason) = Reason::parse(&line.reason) else {
            continue;
        };
        if line.status != "rejected" || line.ts_unix_ms <= 0 || !valid_id(&line.id) {
            continue;
        }
        out.push((line.id, line.ts_unix_ms, *action, reason));
    }
    if out.len() > MAX_LINES {
        out.drain(..out.len() - MAX_LINES);
    }
    Ok(out)
}

/// `args_hash` of every pre-auth row already in the chain.
fn imported_hashes(home: &Path) -> KvendraResult<std::collections::HashSet<String>> {
    let db = home.join("audit.db");
    if !db.exists() {
        return Ok(Default::default());
    }
    let conn = crate::audit::reader::open_readonly(&db)?;
    Ok(crate::audit::reader::list_all(&conn)?
        .into_iter()
        .filter(|r| r.flags.contains(FLAG_PREAUTH_UNAUTHENTICATED))
        .map(|r| r.args_hash_hex)
        .collect())
}

/// Import every pending line into the HMAC chain (flag
/// `preauth_unauthenticated`) and remove the file. Idempotent: a line
/// already imported (same id) by a run that crashed before removing the
/// file is skipped. Returns the number of rows written.
pub async fn flush_into_chain(home: &Path, hmac_key: Vec<u8>) -> KvendraResult<usize> {
    let p = path(home);
    if !p.exists() {
        return Ok(0);
    }
    let rows = pending(home)?;
    let done = imported_hashes(home)?;
    let todo: Vec<_> = rows
        .into_iter()
        .filter(|(id, _, _, reason)| !done.contains(&row_args_hash(id, *reason)))
        .collect();
    if !todo.is_empty() {
        let writer = AuditWriter::spawn(home.join("audit.db"), hmac_key)?;
        for (n, (id, ts, action, reason)) in todo.iter().enumerate() {
            if n > 0
                && let Err(e) = crate::fault::maybe_fail("preauth.mid_import")
            {
                writer.shutdown().await;
                return Err(e);
            }
            let event = AuditEvent {
                ts_unix_ms: *ts,
                profile_id: PRIMITIVE_SYSTEM.into(),
                primitive: PRIMITIVE_SYSTEM.into(),
                action: (*action).into(),
                args_hash_hex: row_args_hash(id, *reason),
                status: Status::Error,
                severity: Severity::Warn,
                flags: format!(
                    "{FLAG_PREAUTH_UNAUTHENTICATED},{action}_rejected_{}",
                    reason.as_str()
                ),
                remote_audit_id: None,
                error_code: None,
                error_message: None,
            };
            if let Err(e) = writer.record(event).await {
                writer.shutdown().await;
                return Err(e);
            }
        }
        writer.shutdown().await;
    }
    std::fs::remove_file(&p)?;
    Ok(todo.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_caps_at_max_lines_and_is_0600() {
        let dir = tempfile::tempdir().unwrap();
        for _ in 0..(MAX_LINES + 5) {
            append(dir.path(), "recover", Reason::PhraseMismatch).unwrap();
        }
        let raw = std::fs::read_to_string(path(dir.path())).unwrap();
        assert_eq!(raw.lines().count(), MAX_LINES);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path(dir.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn pending_skips_unknown_or_malformed_lines() {
        let dir = tempfile::tempdir().unwrap();
        append(dir.path(), "recover", Reason::PhraseInvalid).unwrap();
        let mut raw = std::fs::read_to_string(path(dir.path())).unwrap();
        raw.push_str("not json\n");
        raw.push_str(
            r#"{"id":"00000000000000000000000000000001","ts_unix_ms":1,"action":"recover","status":"rejected","reason":"free text here"}"#,
        );
        raw.push('\n');
        raw.push_str(
            r#"{"id":"00000000000000000000000000000002","ts_unix_ms":1,"action":"rm -rf","status":"rejected","reason":"unavailable"}"#,
        );
        raw.push('\n');
        std::fs::write(path(dir.path()), raw).unwrap();
        let p = pending(dir.path()).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].3, Reason::PhraseInvalid);
    }

    /// B5 — the line cap and the size cap also apply on import.
    #[test]
    fn pending_caps_lines_and_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let mut raw = String::new();
        for i in 0..1500u32 {
            raw.push_str(&format!(
                "{{\"id\":\"{:032x}\",\"ts_unix_ms\":{},\"action\":\"recover\",\"status\":\"rejected\",\"reason\":\"phrase_mismatch\"}}\n",
                i + 1,
                i + 1
            ));
        }
        std::fs::write(path(dir.path()), &raw).unwrap();
        let p = pending(dir.path()).unwrap();
        assert_eq!(p.len(), MAX_LINES);
        assert_eq!(p.last().unwrap().1, 1500, "keeps the newest lines");
        // A huge file: only the tail is read.
        let mut big = "x".repeat(4 * MAX_BYTES as usize);
        big.push('\n');
        big.push_str(&raw);
        std::fs::write(path(dir.path()), &big).unwrap();
        let p = pending(dir.path()).unwrap();
        assert!(!p.is_empty() && p.len() <= MAX_LINES);
    }

    /// B5 — a crash in the middle of an import never duplicates rows when
    /// the file is imported again.
    #[tokio::test]
    async fn import_is_idempotent_after_partial_import() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        for _ in 0..3 {
            append(home, "recover", Reason::PhraseMismatch).unwrap();
        }
        let saved = std::fs::read(path(home)).unwrap();
        let key = vec![7u8; 32];
        assert_eq!(flush_into_chain(home, key.clone()).await.unwrap(), 3);
        // Simulate "rows written, file not yet removed".
        std::fs::write(path(home), &saved).unwrap();
        assert_eq!(flush_into_chain(home, key.clone()).await.unwrap(), 0);
        let conn = crate::audit::reader::open_readonly(&home.join("audit.db")).unwrap();
        let rows = crate::audit::reader::list_all(&conn).unwrap();
        assert_eq!(rows.len(), 3);
        crate::audit::reader::verify_chain(&conn, &key).unwrap();
    }

    /// B5 — failure after the first row of an import: the retry imports the
    /// rest exactly once.
    #[cfg(feature = "test-hooks")]
    #[tokio::test(flavor = "current_thread")]
    async fn import_resumes_without_duplicates_after_mid_import_failure() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        for _ in 0..3 {
            append(home, "passwd", Reason::PasswordInvalid).unwrap();
        }
        let key = vec![9u8; 32];
        {
            let _armed = crate::fault::arm("preauth.mid_import");
            assert!(flush_into_chain(home, key.clone()).await.is_err());
        }
        assert!(path(home).exists(), "file kept until the import completes");
        assert_eq!(flush_into_chain(home, key.clone()).await.unwrap(), 2);
        let conn = crate::audit::reader::open_readonly(&home.join("audit.db")).unwrap();
        assert_eq!(crate::audit::reader::list_all(&conn).unwrap().len(), 3);
        crate::audit::reader::verify_chain(&conn, &key).unwrap();
    }
}
