//! Integration tests — `kvendra config recovery-codes regenerate`.
//!
//! REQ-KVD-CLI-003 / ISSUE-KVD-CLI-025. The double-barrier flow rotates the
//! 8 numeric one-time codes stored in `~/.kvendra/recovery_codes.json`. These
//! tests exercise the testable core (`regenerate_inner`) end-to-end:
//!
//! - F.1  happy_path_returns_8_unique_codes
//! - F.2  wrong_password_rejects_with_invalid_master_password
//! - F.3  acknowledge_mismatch_rejects_with_dedicated_error
//! - F.4  acknowledge_mismatch_emits_audit_row_with_canonical_flag
//! - F.5  happy_path_overwrites_recovery_codes_json_with_eight_slots
//! - F.6  recovery_codes_json_perms_are_0600_after_regenerate
//! - F.7  audit_row_severity_warn_status_ok_with_previous_used_count_flag
//! - F.8  previous_used_count_reflects_consumed_slots
//! - F.9  args_hash_does_not_contain_any_new_recovery_code
//! - F.10 vault_not_initialized_rejects_with_clear_error

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use kvendra::cli::config_recovery_codes::{REGENERATE_ACK, regenerate_inner};
use kvendra::config::{Config, ensure_layout};
use kvendra::error::KvendraError;
use kvendra::vault::Vault;
use kvendra::vault::kdf::{KdfParams, derive, random_salt};
use kvendra::vault::recovery::{RecoveryCodesFile, StoredCode, generate_codes};
use std::path::Path;
use tempfile::TempDir;

fn fast_params() -> KdfParams {
    KdfParams {
        m_cost_kib: 19_456,
        t_cost: 2,
        p_cost: 1,
        salt: vec![1u8; 16],
    }
}

/// Bootstrap a fresh `~/.kvendra/`-shaped tempdir with an unlocked vault and
/// a `recovery_codes.json` of 8 Argon2id-hashed codes — mirrors `kvendra init`.
fn bootstrap(home: &Path) -> (Vault, Vec<String>) {
    ensure_layout(home).unwrap();
    let v = Vault::new(home.to_path_buf());
    v.create_with_params(b"hunter2-test", fast_params()).unwrap();
    v.unlock(b"hunter2-test", 30).unwrap();

    let codes = generate_codes();
    let mut stored = RecoveryCodesFile::default();
    for code in &codes {
        let salt = random_salt();
        let params = KdfParams {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: salt.clone(),
        };
        let h = derive(code.as_bytes(), &params).unwrap();
        stored.codes.push(StoredCode {
            hash_b64: B64.encode(h.as_bytes()),
            salt_b64: B64.encode(&salt),
            used_at: None,
            used_for: None,
        });
    }
    std::fs::write(
        v.recovery_codes_path(),
        serde_json::to_string_pretty(&stored).unwrap(),
    )
    .unwrap();
    Config::default().save(home, &v).unwrap();
    (v, codes)
}

/// F.1 — happy path: returns 8 unique codes formatted XXXX-XXXX-XX.
#[tokio::test]
async fn happy_path_returns_8_unique_codes() {
    let tmp = TempDir::new().unwrap();
    let (_v, _codes) = bootstrap(tmp.path());

    let outcome = regenerate_inner(tmp.path(), b"hunter2-test", REGENERATE_ACK)
        .await
        .unwrap();

    assert_eq!(outcome.new_codes.len(), 8);
    let unique: std::collections::HashSet<_> = outcome.new_codes.iter().collect();
    assert_eq!(unique.len(), 8, "the 8 new codes must be unique");
    for c in &outcome.new_codes {
        assert_eq!(c.len(), 12, "expected XXXX-XXXX-XX format");
        assert_eq!(c.matches('-').count(), 2);
    }
}

/// F.2 — wrong password rejects BEFORE acknowledge is checked.
#[tokio::test]
async fn wrong_password_rejects_with_invalid_master_password() {
    let tmp = TempDir::new().unwrap();
    let (_v, _codes) = bootstrap(tmp.path());

    let r = regenerate_inner(tmp.path(), b"WRONG-PASSWORD", REGENERATE_ACK).await;

    assert!(
        matches!(r, Err(KvendraError::InvalidMasterPassword)),
        "expected InvalidMasterPassword, got {r:?}"
    );
}

/// F.3 — acknowledge mismatch rejects with the dedicated error variant.
#[tokio::test]
async fn acknowledge_mismatch_rejects_with_dedicated_error() {
    let tmp = TempDir::new().unwrap();
    let (_v, _codes) = bootstrap(tmp.path());

    let r = regenerate_inner(tmp.path(), b"hunter2-test", "regenerate").await;

    assert!(
        matches!(r, Err(KvendraError::RegenerateAcknowledgeMismatch)),
        "expected RegenerateAcknowledgeMismatch, got {r:?}"
    );
}

/// F.4 — acknowledge mismatch emits a dedicated audit row tagged with the
/// canonical flag string `recovery_codes_regenerate_aborted_acknowledge_mismatch`.
#[tokio::test]
async fn acknowledge_mismatch_emits_audit_row_with_canonical_flag() {
    let tmp = TempDir::new().unwrap();
    let (_v, _codes) = bootstrap(tmp.path());

    let _r = regenerate_inner(tmp.path(), b"hunter2-test", "nope").await;
    // Allow writer thread to flush.
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    let conn = rusqlite::Connection::open(tmp.path().join("audit.db")).unwrap();
    let (action, severity, status, flags, primitive): (String, String, String, String, String) =
        conn.query_row(
            "SELECT action, severity, status, flags, primitive FROM audit_events \
             WHERE action = 'recovery_codes_regenerate' ORDER BY id DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();

    assert_eq!(action, "recovery_codes_regenerate");
    assert_eq!(severity, "warn");
    assert_eq!(status, "error");
    assert_eq!(primitive, "kvendra.system");
    assert!(
        flags.contains("recovery_codes_regenerate_aborted_acknowledge_mismatch"),
        "flags must contain the canonical abort flag: {flags}"
    );
}

/// F.5 — happy path overwrites `recovery_codes.json` with exactly 8 fresh slots.
#[tokio::test]
async fn happy_path_overwrites_recovery_codes_json_with_eight_slots() {
    let tmp = TempDir::new().unwrap();
    let (_v, original_codes) = bootstrap(tmp.path());
    let path = tmp.path().join("recovery_codes.json");
    let original_raw = std::fs::read_to_string(&path).unwrap();

    let outcome = regenerate_inner(tmp.path(), b"hunter2-test", REGENERATE_ACK)
        .await
        .unwrap();

    let new_raw = std::fs::read_to_string(&path).unwrap();
    assert_ne!(
        original_raw, new_raw,
        "recovery_codes.json must be overwritten"
    );
    let parsed: RecoveryCodesFile = serde_json::from_str(&new_raw).unwrap();
    assert_eq!(parsed.codes.len(), 8);
    for s in &parsed.codes {
        assert!(s.used_at.is_none(), "fresh codes must be unconsumed");
        assert!(s.used_for.is_none());
    }
    // None of the original (plaintext) codes can match any of the new
    // hashed slots — the rotation must produce different material.
    let new_codes_set: std::collections::HashSet<_> = outcome.new_codes.iter().collect();
    let original_set: std::collections::HashSet<_> = original_codes.iter().collect();
    assert!(new_codes_set.is_disjoint(&original_set), "codes must rotate");
}

/// F.6 — recovery_codes.json perms are 0600 after the atomic rename.
#[cfg(unix)]
#[tokio::test]
async fn recovery_codes_json_perms_are_0600_after_regenerate() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().unwrap();
    let (_v, _codes) = bootstrap(tmp.path());

    let _outcome = regenerate_inner(tmp.path(), b"hunter2-test", REGENERATE_ACK)
        .await
        .unwrap();

    let meta = std::fs::metadata(tmp.path().join("recovery_codes.json")).unwrap();
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "expected 0600, got {:o}", mode);
}

/// F.7 — audit row on success has severity=warn, status=ok, primitive
/// `kvendra.system`, action `recovery_codes_regenerate`, and the
/// `previous_used_count_<N>` flag.
#[tokio::test]
async fn audit_row_severity_warn_status_ok_with_previous_used_count_flag() {
    let tmp = TempDir::new().unwrap();
    let (_v, _codes) = bootstrap(tmp.path());

    let _outcome = regenerate_inner(tmp.path(), b"hunter2-test", REGENERATE_ACK)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    let conn = rusqlite::Connection::open(tmp.path().join("audit.db")).unwrap();
    let (action, severity, status, flags, primitive): (String, String, String, String, String) =
        conn.query_row(
            "SELECT action, severity, status, flags, primitive FROM audit_events \
             WHERE action = 'recovery_codes_regenerate' AND status = 'ok' \
             ORDER BY id DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();

    assert_eq!(action, "recovery_codes_regenerate");
    assert_eq!(severity, "warn");
    assert_eq!(status, "ok");
    assert_eq!(primitive, "kvendra.system");
    assert!(
        flags.contains("recovery_codes_regenerated"),
        "flags must contain the canonical success flag: {flags}"
    );
    assert!(
        flags.contains("previous_used_count_0"),
        "flags must contain previous_used_count_0 for fresh vault: {flags}"
    );
}

/// F.8 — previous_used_count reflects the number of slots that carried
/// `used_at = Some(_)` in the file we just overwrote.
#[tokio::test]
async fn previous_used_count_reflects_consumed_slots() {
    let tmp = TempDir::new().unwrap();
    let (_v, _codes) = bootstrap(tmp.path());

    // Hand-mutate two slots to be "consumed" before we regenerate.
    let path = tmp.path().join("recovery_codes.json");
    let raw = std::fs::read_to_string(&path).unwrap();
    let mut file: RecoveryCodesFile = serde_json::from_str(&raw).unwrap();
    file.codes[0].used_at = Some("2026-05-08T10:00:00Z".into());
    file.codes[0].used_for = Some("home_rebound".into());
    file.codes[3].used_at = Some("2026-05-08T11:00:00Z".into());
    file.codes[3].used_for = Some("home_rebound".into());
    std::fs::write(&path, serde_json::to_string_pretty(&file).unwrap()).unwrap();

    let outcome = regenerate_inner(tmp.path(), b"hunter2-test", REGENERATE_ACK)
        .await
        .unwrap();
    assert_eq!(outcome.previous_used_count, 2);

    // And the audit row encodes `previous_used_count_2`.
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    let conn = rusqlite::Connection::open(tmp.path().join("audit.db")).unwrap();
    let flags: String = conn
        .query_row(
            "SELECT flags FROM audit_events \
             WHERE action = 'recovery_codes_regenerate' AND status = 'ok' \
             ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        flags.contains("previous_used_count_2"),
        "flags must encode previous_used_count_2: {flags}"
    );
}

/// F.9 — `args_hash_hex` does not contain any of the freshly-generated
/// recovery codes verbatim. Plaintext codes never appear in any audit field.
#[tokio::test]
async fn args_hash_does_not_contain_any_new_recovery_code() {
    let tmp = TempDir::new().unwrap();
    let (_v, _codes) = bootstrap(tmp.path());

    let outcome = regenerate_inner(tmp.path(), b"hunter2-test", REGENERATE_ACK)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    let conn = rusqlite::Connection::open(tmp.path().join("audit.db")).unwrap();
    let (args_hash, flags, action): (String, String, String) = conn
        .query_row(
            "SELECT args_hash_hex, flags, action FROM audit_events \
             WHERE action = 'recovery_codes_regenerate' AND status = 'ok' \
             ORDER BY id DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(action, "recovery_codes_regenerate");
    for code in &outcome.new_codes {
        assert!(
            !args_hash.contains(code),
            "args_hash leaked code {code}: {args_hash}"
        );
        assert!(
            !flags.contains(code),
            "flags leaked code {code}: {flags}"
        );
    }
}

/// F.10 — uninitialised vault rejects with a clear error message.
#[tokio::test]
async fn vault_not_initialized_rejects_with_clear_error() {
    let tmp = TempDir::new().unwrap();
    // No bootstrap — sentinel.blob does not exist.
    ensure_layout(tmp.path()).unwrap();

    let r = regenerate_inner(tmp.path(), b"any-password", REGENERATE_ACK).await;
    let msg = match r {
        Err(KvendraError::Vault(s)) => s,
        other => panic!("expected KvendraError::Vault(..), got {other:?}"),
    };
    assert!(
        msg.contains("vault not initialized"),
        "error must mention vault not initialised: {msg}"
    );
}
