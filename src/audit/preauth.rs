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
/// Retention cap.
pub const MAX_LINES: usize = 1000;

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
    ts_unix_ms: i64,
    action: String,
    status: String,
    reason: String,
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

/// Validated lines currently pending import.
fn pending(home: &Path) -> KvendraResult<Vec<(i64, &'static str, Reason)>> {
    let raw = match std::fs::read_to_string(path(home)) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    for l in raw.lines() {
        let Ok(line) = serde_json::from_str::<Line>(l) else {
            continue;
        };
        let Some(action) = ACTIONS.iter().find(|a| **a == line.action) else {
            continue;
        };
        let Some(reason) = Reason::parse(&line.reason) else {
            continue;
        };
        if line.status != "rejected" || line.ts_unix_ms <= 0 {
            continue;
        }
        out.push((line.ts_unix_ms, *action, reason));
    }
    Ok(out)
}

/// Import every pending line into the HMAC chain (flag
/// `preauth_unauthenticated`) and remove the file. Returns the number of
/// imported rows.
pub async fn flush_into_chain(home: &Path, hmac_key: Vec<u8>) -> KvendraResult<usize> {
    let p = path(home);
    if !p.exists() {
        return Ok(0);
    }
    let rows = pending(home)?;
    if !rows.is_empty() {
        let writer = AuditWriter::spawn(home.join("audit.db"), hmac_key)?;
        for (ts, action, reason) in &rows {
            let event = AuditEvent {
                ts_unix_ms: *ts,
                profile_id: PRIMITIVE_SYSTEM.into(),
                primitive: PRIMITIVE_SYSTEM.into(),
                action: (*action).into(),
                args_hash_hex: args_hash_hex(&serde_json::json!({ "reason": reason.as_str() })),
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
    Ok(rows.len())
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
            r#"{"ts_unix_ms":1,"action":"recover","status":"rejected","reason":"free text here"}"#,
        );
        raw.push('\n');
        raw.push_str(
            r#"{"ts_unix_ms":1,"action":"rm -rf","status":"rejected","reason":"unavailable"}"#,
        );
        raw.push('\n');
        std::fs::write(path(dir.path()), raw).unwrap();
        let p = pending(dir.path()).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].2, Reason::PhraseInvalid);
    }
}
