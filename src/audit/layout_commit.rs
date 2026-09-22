//! Legacy layout commitment — `kvendra audit commit-layout`
//! (ISSUE-KVD-CLI-F4ED93, SA4-F3).
//!
//! The frozen legacy layouts leave columns outside the row MAC: v1 binds
//! neither `remote_audit_id` nor `error_code` / `error_message`, v2 binds no
//! error diagnostics, and v1/v2/v3 canonicalize `NULL` to `''`. Those rows can
//! never be re-MACed without losing the ability to verify their original tags,
//! so instead the owner APPENDS one layout-v4 **commitment row** whose
//! `args_hash_hex` is a SHA-256 digest over an injective encoding of EVERY
//! column (MAC-bound or not, with `NULL` distinct from `''`, plus the row's
//! `hmac_version` and `hmac_hex`) of every legacy row in the log. The digest
//! is bound by the commitment row's own v4 MAC, so after the commit any edit
//! to a legacy row — including the columns its legacy MAC never covered — is
//! an [`KvendraError::AuditLayoutViolation`] at the commitment row.
//!
//! Properties:
//!  - **Additive only.** No existing row is rewritten; every legacy tag keeps
//!    verifying exactly as before. A commitment never masks a failure the
//!    per-row MAC / prev-link checks already report.
//!  - **Covers all legacy rows.** Legacy rows can only precede the first v4
//!    row (`verify_chain` refuses legacy-after-v4), and a commitment is itself
//!    v4, so the legacy set is closed the moment the first commitment lands.
//!  - **Idempotent.** Re-running is a no-op when a matching commitment exists,
//!    a no-op when there are no legacy rows (empty log or v4-only log), and a
//!    refusal (never a re-commit) when an existing commitment no longer
//!    matches — re-committing would launder the tamper.
//!  - **Only over a verifying chain (SA4-F5).** The whole chain is verified
//!    inside the commit transaction first; on ANY verification failure
//!    (prev-link break, bad MAC, layout violation, commitment mismatch) the
//!    commit is refused and nothing is appended. A commitment therefore never
//!    vouches for a log that was already broken or forged, and an
//!    unauthenticated row that merely looks like a commitment (bogus MAC,
//!    stripped flags) can neither short-circuit to "already committed" nor
//!    hide behind a fresh commitment.

use crate::audit::hmac::RowFields;
use crate::audit::reader::{StoredEvent, list_all, verify_chain_report};
use crate::audit::writer::with_immediate_txn;
use crate::audit::{AuditEvent, PRIMITIVE_SYSTEM, Severity, Status};
use crate::error::{KvendraError, KvendraResult};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

/// `action` of a commitment row.
pub const ACTION_AUDIT_LAYOUT_COMMITTED: &str = "audit_layout_committed";

/// `flags` of a commitment row (exact match — the dispatcher never emits it).
pub const FLAG_AUDIT_LAYOUT_COMMITTED: &str = "audit_layout_committed";

/// Layout of the commitment row itself.
pub const COMMITMENT_ROW_LAYOUT: i64 = 4;

const DIGEST_DOMAIN: &[u8] = b"kvendra.audit.legacy-layout-commitment\0";

/// Every column of one stored row, as the digest sees it.
#[derive(Debug, Clone, Copy)]
pub struct CommittedRow<'a> {
    pub fields: RowFields<'a>,
    pub hmac_version: i64,
    pub hmac_hex: &'a str,
}

/// True for the legacy layouts a commitment pins.
pub fn is_legacy_layout(hmac_version: i64) -> bool {
    (1..=3).contains(&hmac_version)
}

/// Whether a row is a layout commitment. Every identifying column is bound by
/// the row's v4 MAC; the flag is server-only vocabulary.
pub fn is_commitment_row(
    hmac_version: i64,
    profile_id: &str,
    primitive: &str,
    action: &str,
    flags: &str,
) -> bool {
    hmac_version == COMMITMENT_ROW_LAYOUT
        && profile_id == PRIMITIVE_SYSTEM
        && primitive == PRIMITIVE_SYSTEM
        && action == ACTION_AUDIT_LAYOUT_COMMITTED
        && flags == FLAG_AUDIT_LAYOUT_COMMITTED
}

fn put_str(h: &mut Sha256, s: &str) {
    h.update((s.len() as u64).to_be_bytes());
    h.update(s.as_bytes());
}

fn put_opt(h: &mut Sha256, o: Option<&str>) {
    match o {
        None => h.update([0u8]),
        Some(s) => {
            h.update([1u8]);
            put_str(h, s);
        }
    }
}

/// Hex SHA-256 over an injective encoding of `rows` (in the given order):
/// domain tag, row count, then for each row every column fixed-width or
/// length-prefixed, optionals tagged `0x00` / `0x01`.
pub fn legacy_layout_digest(rows: &[CommittedRow<'_>]) -> String {
    let mut h = Sha256::new();
    h.update(DIGEST_DOMAIN);
    h.update((rows.len() as u64).to_be_bytes());
    for r in rows {
        let f = &r.fields;
        h.update(f.id.to_be_bytes());
        h.update(f.ts_unix_ms.to_be_bytes());
        put_str(&mut h, f.profile_id);
        put_str(&mut h, f.primitive);
        put_str(&mut h, f.action);
        put_str(&mut h, f.args_hash_hex);
        put_str(&mut h, f.status);
        put_str(&mut h, f.severity);
        put_str(&mut h, f.flags);
        put_str(&mut h, f.prev_hmac_hex);
        put_opt(&mut h, f.remote_audit_id);
        put_opt(&mut h, f.error_code);
        put_opt(&mut h, f.error_message);
        h.update(r.hmac_version.to_be_bytes());
        put_str(&mut h, r.hmac_hex);
    }
    hex::encode(h.finalize())
}

impl StoredEvent {
    pub fn committed_row(&self) -> CommittedRow<'_> {
        CommittedRow {
            fields: self.hmac_fields(),
            hmac_version: self.hmac_version,
            hmac_hex: &self.hmac_hex,
        }
    }

    pub fn is_layout_commitment(&self) -> bool {
        is_commitment_row(
            self.hmac_version,
            &self.profile_id,
            &self.primitive,
            &self.action,
            &self.flags,
        )
    }
}

/// Digest over every legacy row of `events`, and how many there are.
pub fn digest_of_legacy_rows(events: &[StoredEvent]) -> (String, usize) {
    let rows: Vec<CommittedRow<'_>> = events
        .iter()
        .filter(|e| is_legacy_layout(e.hmac_version))
        .map(StoredEvent::committed_row)
        .collect();
    (legacy_layout_digest(&rows), rows.len())
}

/// Result of [`commit_legacy_layout`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOutcome {
    /// The log holds no legacy row (empty, or v4-only) — nothing appended.
    NothingToCommit,
    /// A matching commitment already exists — nothing appended.
    AlreadyCommitted { row: i64, legacy_rows: usize },
    /// A new commitment row was appended.
    Committed {
        row: i64,
        legacy_rows: usize,
        digest_hex: String,
    },
}

/// Append a commitment over every legacy row, unless one already matches.
///
/// Runs under `BEGIN IMMEDIATE` so the chain verification, the read of the
/// legacy set, the read of the chain tip and the append are one atomic step
/// against other writers (every audit writer takes the same lock, SA4-F4).
///
/// Fail-closed (SA4-F5): the WHOLE chain must verify
/// ([`verify_chain_report`]) inside that transaction before anything is
/// decided. Any failure — a broken prev-link, a bad row MAC (e.g. a forged or
/// flag-stripped commitment row), a layout violation, a commitment that no
/// longer matches the legacy rows — is returned unchanged and nothing is
/// appended. Consequently only a MAC-valid commitment whose digest matches
/// counts as [`CommitOutcome::AlreadyCommitted`].
pub fn commit_legacy_layout(
    conn: &Connection,
    hmac_key: &[u8],
    ts_unix_ms: i64,
) -> KvendraResult<CommitOutcome> {
    if !conn.is_autocommit() {
        return Err(KvendraError::Audit(
            "commit-layout must own its transaction (connection already in one)".into(),
        ));
    }
    with_immediate_txn(conn, |conn| commit_in_txn(conn, hmac_key, ts_unix_ms))
}

fn commit_in_txn(
    conn: &Connection,
    hmac_key: &[u8],
    ts_unix_ms: i64,
) -> KvendraResult<CommitOutcome> {
    // Every commitment row that survives this check has a valid v4 MAC and
    // carries the digest of the current legacy rows.
    verify_chain_report(conn, hmac_key)?;
    let events = list_all(conn)?;
    let (digest_hex, legacy_rows) = digest_of_legacy_rows(&events);
    if legacy_rows == 0 {
        return Ok(CommitOutcome::NothingToCommit);
    }
    let existing: Vec<&StoredEvent> = events.iter().filter(|e| e.is_layout_commitment()).collect();
    if let Some(bad) = existing.iter().find(|c| c.args_hash_hex != digest_hex) {
        return Err(KvendraError::AuditLayoutViolation {
            row: bad.id,
            reason: "legacy rows no longer match their layout commitment — refusing to \
                     re-commit"
                .into(),
        });
    }
    if let Some(c) = existing.first() {
        return Ok(CommitOutcome::AlreadyCommitted {
            row: c.id,
            legacy_rows,
        });
    }
    let event = AuditEvent {
        ts_unix_ms,
        profile_id: PRIMITIVE_SYSTEM.into(),
        primitive: PRIMITIVE_SYSTEM.into(),
        action: ACTION_AUDIT_LAYOUT_COMMITTED.into(),
        args_hash_hex: digest_hex.clone(),
        status: Status::Ok,
        severity: Severity::Info,
        flags: FLAG_AUDIT_LAYOUT_COMMITTED.into(),
        remote_audit_id: None,
        error_code: None,
        error_message: None,
    };
    let row = crate::audit::writer::record_event(conn, hmac_key, &event)?;
    Ok(CommitOutcome::Committed {
        row,
        legacy_rows,
        digest_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::hmac::{compute_hmac_v1, compute_hmac_v2, compute_hmac_v3};
    use crate::audit::reader::{verify_chain, verify_chain_report};
    use crate::audit::schema::init;

    const K: &[u8] = b"layout-commit-test-key";

    fn db() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let conn = Connection::open(dir.path().join("audit.db")).unwrap();
        init(&conn).unwrap();
        (dir, conn)
    }

    #[allow(clippy::too_many_arguments)]
    fn legacy(
        conn: &Connection,
        layout: i64,
        id: i64,
        remote: Option<&str>,
        code: Option<&str>,
        msg: Option<&str>,
        prev: &str,
    ) -> String {
        let (ts, p, prim, act, args, st, sev, fl) = (
            1_700_000_000_000 + id,
            "p",
            "kvendra.shell",
            "exec",
            "ab",
            "error",
            "warn",
            "",
        );
        let tag = match layout {
            1 => compute_hmac_v1(K, id, ts, p, prim, act, args, st, sev, fl, prev),
            2 => compute_hmac_v2(K, id, ts, p, prim, act, args, st, sev, fl, prev, remote),
            _ => compute_hmac_v3(
                K, id, ts, p, prim, act, args, st, sev, fl, prev, remote, code, msg,
            ),
        };
        conn.execute(
            "INSERT INTO audit_events (id, ts_unix_ms, profile_id, primitive, action,
             args_hash_hex, status, severity, flags, prev_hmac_hex, hmac_hex, remote_audit_id,
             hmac_version, error_code, error_message)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            rusqlite::params![
                id, ts, p, prim, act, args, st, sev, fl, prev, tag, remote, layout, code, msg
            ],
        )
        .unwrap();
        tag
    }

    /// v1 (remote/code/msg NULL) → v2 (remote NULL) → v3.
    fn legacy_chain(conn: &Connection) {
        let h1 = legacy(conn, 1, 1, None, None, None, "");
        let h2 = legacy(conn, 2, 2, None, None, None, &h1);
        legacy(
            conn,
            3,
            3,
            None,
            Some("ALLOWLIST_VIOLATION"),
            Some("m"),
            &h2,
        );
    }

    fn commit(conn: &Connection) -> KvendraResult<CommitOutcome> {
        commit_legacy_layout(conn, K, 1_800_000_000_000)
    }

    #[test]
    fn digest_distinguishes_null_from_empty_and_every_column() {
        let (_d, conn) = db();
        legacy_chain(&conn);
        let events = list_all(&conn).unwrap();
        let base = digest_of_legacy_rows(&events).0;
        let mut e = events.clone();
        e[0].remote_audit_id = Some(String::new());
        assert_ne!(base, digest_of_legacy_rows(&e).0);
        let mut e = events.clone();
        e[0].error_code = Some(String::new());
        assert_ne!(base, digest_of_legacy_rows(&e).0);
        let mut e = events.clone();
        e[1].error_message = Some("x".into());
        assert_ne!(base, digest_of_legacy_rows(&e).0);
        let mut e = events.clone();
        e[2].hmac_version = 2;
        assert_ne!(base, digest_of_legacy_rows(&e).0);
        // Moving bytes across a field boundary cannot alias.
        let mut a = events.clone();
        a[0].primitive = "kvendra.shellexec".into();
        a[0].action = String::new();
        assert_ne!(base, digest_of_legacy_rows(&a).0);
        // Row order / count are bound.
        let mut r = events.clone();
        r.swap(0, 1);
        assert_ne!(base, digest_of_legacy_rows(&r).0);
        assert_ne!(base, digest_of_legacy_rows(&events[..2]).0);
    }

    #[test]
    fn empty_and_v4_only_logs_have_nothing_to_commit() {
        let (_d, conn) = db();
        assert_eq!(commit(&conn).unwrap(), CommitOutcome::NothingToCommit);
        let ev = AuditEvent {
            ts_unix_ms: 1,
            profile_id: "p".into(),
            primitive: "kvendra.git".into(),
            action: "push".into(),
            args_hash_hex: "ab".into(),
            status: Status::Ok,
            severity: Severity::Info,
            flags: String::new(),
            remote_audit_id: None,
            error_code: None,
            error_message: None,
        };
        crate::audit::writer::record_event(&conn, K, &ev).unwrap();
        assert_eq!(commit(&conn).unwrap(), CommitOutcome::NothingToCommit);
        let rep = verify_chain_report(&conn, K).unwrap();
        assert_eq!((rep.rows, rep.legacy_rows, rep.commitment_rows), (1, 0, 0));
    }

    #[test]
    fn commit_is_idempotent_and_verifies() {
        let (_d, conn) = db();
        legacy_chain(&conn);
        let rep = verify_chain_report(&conn, K).unwrap();
        assert_eq!((rep.legacy_rows, rep.committed_legacy_rows()), (3, 0));
        let CommitOutcome::Committed {
            row, legacy_rows, ..
        } = commit(&conn).unwrap()
        else {
            panic!("expected a new commitment");
        };
        assert_eq!((row, legacy_rows), (4, 3));
        assert_eq!(
            commit(&conn).unwrap(),
            CommitOutcome::AlreadyCommitted {
                row: 4,
                legacy_rows: 3
            }
        );
        let rep = verify_chain_report(&conn, K).unwrap();
        assert_eq!(
            (rep.rows, rep.commitment_rows, rep.committed_legacy_rows()),
            (4, 1, 3)
        );
    }

    #[test]
    fn edits_outside_the_legacy_mac_are_caught_once_committed() {
        for sql in [
            // v1: diagnostics + remote id are outside the v1 MAC.
            "UPDATE audit_events SET error_code = 'FORGED' WHERE id = 1",
            "UPDATE audit_events SET error_message = 'forged' WHERE id = 1",
            "UPDATE audit_events SET remote_audit_id = 'forged' WHERE id = 1",
            // v2: diagnostics outside the v2 MAC; NULL↔'' canonicalized.
            "UPDATE audit_events SET error_code = 'FORGED' WHERE id = 2",
            "UPDATE audit_events SET remote_audit_id = '' WHERE id = 2",
            // v3: NULL↔'' canonicalized by the legacy MAC.
            "UPDATE audit_events SET remote_audit_id = '' WHERE id = 3",
        ] {
            let (_d, conn) = db();
            legacy_chain(&conn);
            conn.execute(sql, []).unwrap();
            assert!(verify_chain(&conn, K).is_ok(), "uncommitted gap: {sql}");
            let (_d, conn) = db();
            legacy_chain(&conn);
            commit(&conn).unwrap();
            conn.execute(sql, []).unwrap();
            let r = verify_chain(&conn, K);
            assert!(
                matches!(r, Err(KvendraError::AuditLayoutViolation { row: 4, .. })),
                "{sql}: {r:?}"
            );
            assert!(
                matches!(
                    commit(&conn),
                    Err(KvendraError::AuditLayoutViolation { row: 4, .. })
                ),
                "{sql}: re-commit must refuse, not launder"
            );
        }
    }

    #[test]
    fn tampered_commitment_row_fails_its_own_mac() {
        let (_d, conn) = db();
        legacy_chain(&conn);
        commit(&conn).unwrap();
        conn.execute("UPDATE audit_events SET action = 'x' WHERE id = 4", [])
            .unwrap();
        assert!(matches!(
            verify_chain(&conn, K),
            Err(KvendraError::AuditChainBroken(4))
        ));
    }

    fn export_of(events: &[StoredEvent]) -> crate::audit::export::bundle::ExportBundle {
        crate::audit::export::bundle::build_bundle(
            events,
            "t",
            crate::audit::export::bundle::ExportFilters {
                from: None,
                to: None,
                raw: None,
            },
            hex::encode(K),
        )
    }

    fn passes(b: &crate::audit::export::bundle::ExportBundle) -> bool {
        matches!(
            crate::audit::export::verify::verify_bundle(b).unwrap(),
            crate::audit::export::verify::VerifyOutcome::Pass { .. }
        )
    }

    /// Export verifier parity: a genesis-rooted export checks the commitment
    /// exactly like `verify_chain`; a mid-chain window checks its MAC only.
    #[test]
    fn export_verifier_checks_the_commitment() {
        let (_d, conn) = db();
        legacy_chain(&conn);
        commit(&conn).unwrap();
        let events = list_all(&conn).unwrap();
        let full = export_of(&events);
        assert!(passes(&full));

        for f in 0..3 {
            let mut b = full.clone();
            match f {
                0 => b.events[0].error_code = Some("FORGED".into()),
                1 => b.events[1].error_message = Some("forged".into()),
                _ => b.events[1].remote_audit_id = Some(String::new()),
            }
            match crate::audit::export::verify::verify_bundle(&b).unwrap() {
                crate::audit::export::verify::VerifyOutcome::Fail {
                    first_deviation_at,
                    reason,
                } => {
                    assert_eq!(first_deviation_at, 3, "case {f}: {reason}");
                    assert!(reason.contains("commitment"), "case {f}: {reason}");
                }
                other => panic!("case {f}: expected FAIL, got {other:?}"),
            }
        }

        // Mid-chain window (legacy prefix partly outside): not checkable, the
        // commitment row's own MAC still verifies.
        assert!(passes(&export_of(&events[1..])));
        let mut w = export_of(&events[1..]);
        w.events[0].error_code = Some("FORGED".into());
        assert!(
            passes(&w),
            "documented: partial windows cannot pin legacy rows"
        );
    }

    fn row_count(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM audit_events", [], |r| r.get(0))
            .unwrap()
    }

    /// SA4-F5: committing over an already-broken chain is refused (was:
    /// appended + exit 0) and appends nothing.
    #[test]
    fn commit_refuses_on_a_broken_chain() {
        let (_d, conn) = db();
        legacy_chain(&conn);
        // A pre-existing link break inside the legacy prefix.
        conn.execute(
            "UPDATE audit_events SET prev_hmac_hex = 'stale' WHERE id = 3",
            [],
        )
        .unwrap();
        assert!(matches!(
            verify_chain(&conn, K),
            Err(KvendraError::AuditChainBroken(3))
        ));
        assert!(matches!(
            commit(&conn),
            Err(KvendraError::AuditChainBroken(3))
        ));
        assert_eq!(row_count(&conn), 3, "a refused commit appends nothing");
        assert!(conn.is_autocommit());
    }

    /// SA4-F5: a fake tail row that merely LOOKS like a matching commitment
    /// (right columns + digest, bogus MAC) is not "already committed".
    #[test]
    fn fake_commitment_row_is_not_already_committed() {
        let (_d, conn) = db();
        legacy_chain(&conn);
        let events = list_all(&conn).unwrap();
        let (digest, _) = digest_of_legacy_rows(&events);
        conn.execute(
            "INSERT INTO audit_events (ts_unix_ms, profile_id, primitive, action, args_hash_hex,
             status, severity, flags, prev_hmac_hex, hmac_hex, remote_audit_id, hmac_version)
             VALUES (1, ?1, ?1, ?2, ?3, 'ok', 'info', ?4, ?5, 'deadbeef', NULL, 4)",
            rusqlite::params![
                PRIMITIVE_SYSTEM,
                ACTION_AUDIT_LAYOUT_COMMITTED,
                digest,
                FLAG_AUDIT_LAYOUT_COMMITTED,
                events[2].hmac_hex
            ],
        )
        .unwrap();
        assert!(matches!(
            commit(&conn),
            Err(KvendraError::AuditChainBroken(4))
        ));
        assert_eq!(row_count(&conn), 4);
    }

    /// SA4-F5: stripping the flag off the real commitment (so it no longer
    /// looks like one) must not lead to a second commitment over the now
    /// broken chain.
    #[test]
    fn stripped_commitment_flags_refuse_instead_of_recommitting() {
        let (_d, conn) = db();
        legacy_chain(&conn);
        commit(&conn).unwrap();
        conn.execute("UPDATE audit_events SET flags = '' WHERE id = 4", [])
            .unwrap();
        assert!(matches!(
            commit(&conn),
            Err(KvendraError::AuditChainBroken(4))
        ));
        assert_eq!(row_count(&conn), 4);
    }

    /// SA4-F4: `commit-layout` racing a live writer (separate connections ≈
    /// separate processes) never forks the chain and commits exactly once.
    /// Pre-fix: CHAIN_BROKEN 9/10.
    #[test]
    fn commit_racing_a_writer_keeps_one_chain() {
        use std::sync::{Arc, Barrier};
        for run in 0..10 {
            let (dir, conn) = db();
            legacy_chain(&conn);
            let path = dir.path().join("audit.db");
            let barrier = Arc::new(Barrier::new(3));
            let writer = {
                let (path, barrier) = (path.clone(), barrier.clone());
                std::thread::spawn(move || {
                    let conn = Connection::open(&path).unwrap();
                    init(&conn).unwrap();
                    barrier.wait();
                    for i in 0..30 {
                        let ev = AuditEvent {
                            ts_unix_ms: 1_900_000_000_000 + i,
                            profile_id: "p".into(),
                            primitive: "kvendra.shell".into(),
                            action: "exec".into(),
                            args_hash_hex: format!("{i:064x}"),
                            status: Status::Started,
                            severity: Severity::Info,
                            flags: String::new(),
                            remote_audit_id: None,
                            error_code: None,
                            error_message: None,
                        };
                        crate::audit::writer::record_event(&conn, K, &ev).unwrap();
                    }
                })
            };
            let committers: Vec<_> = (0..2)
                .map(|_| {
                    let (path, barrier) = (path.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        let conn = Connection::open(&path).unwrap();
                        init(&conn).unwrap();
                        barrier.wait();
                        commit(&conn).unwrap()
                    })
                })
                .collect();
            writer.join().unwrap();
            let outcomes: Vec<_> = committers.into_iter().map(|h| h.join().unwrap()).collect();
            assert_eq!(
                outcomes
                    .iter()
                    .filter(|o| matches!(o, CommitOutcome::Committed { .. }))
                    .count(),
                1,
                "run {run}: {outcomes:?}"
            );
            let rep = verify_chain_report(&conn, K);
            assert!(
                matches!(rep, Ok(r) if r.rows == 34 && r.commitment_rows == 1),
                "run {run}: {rep:?}"
            );
        }
    }
}
