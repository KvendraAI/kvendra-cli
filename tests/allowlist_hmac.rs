//! REQ-KVD-007 / ISSUE-KVD-CLI-018 — integration tests for the allowlist
//! HMAC verification flow + TOCTOU cache fix at the storage layer.
//!
//! Inline unit tests in `src/vault/mod.rs::tests` cover the
//! `compute_allowlist_hmac` semantics; tests in `src/mcp/server.rs::tests`
//! cover the `enforce_allowlist` runtime path. This file exercises the
//! pieces that the CLI flow stitches together: persisting the HMAC into
//! the on-disk profile meta, observing the field through public Vault
//! APIs, and validating that the audit chain remains intact when the
//! `allowlist_tampered_detected` flag is recorded.

use kvendra::audit::reader::{open_readonly, verify_chain};
use kvendra::audit::{AuditEvent, AuditWriter, Severity, Status};
use kvendra::vault::{Profile, Vault, kdf::KdfParams};
use tempfile::tempdir;

fn fast_params() -> KdfParams {
    KdfParams {
        m_cost_kib: 19_456,
        t_cost: 2,
        p_cost: 1,
        salt: vec![1u8; 16],
    }
}

const SAMPLE_YAML: &str = "profile_id: p\nsecret:\n  type: github_pat\nallowlist:\n  primitives:\n    - name: kvendra.shell\n      operations:\n        - run:\n            binaries: [\"echo\"]\n";

fn bootstrap(home: &std::path::Path) -> Vault {
    kvendra::config::ensure_layout(home).unwrap();
    let v = Vault::new(home.to_path_buf());
    v.create_with_params(b"hunter2-allowlist-hmac", fast_params())
        .unwrap();
    v.unlock(b"hunter2-allowlist-hmac", 30).unwrap();
    v.put_secret("p", b"sometoken-plaintext").unwrap();
    v.save_profile_meta(&Profile {
        profile_id: "p".into(),
        secret_type: "github_pat".into(),
        created_at: "2026-05-07T00:00:00Z".into(),
        expiration: None,
        unsafe_raw_token_enabled: false,
        quarantined: false,
        allowlist_hmac_hex: None,
    })
    .unwrap();
    v
}

/// REQ-KVD-007 AC-1 — after writing an allowlist YAML and computing the
/// HMAC under the unlocked sub-key, the value persists into the profile
/// meta file and round-trips through `load_profile_meta`. This is the
/// invariant `secret set-allowlist` exercises end-to-end.
#[test]
fn set_allowlist_persists_hmac_to_profile_meta() {
    let dir = tempdir().unwrap();
    let v = bootstrap(dir.path());
    std::fs::write(v.profile_allowlist_path("p"), SAMPLE_YAML).unwrap();

    let key = v.allowlist_hmac_key().unwrap();
    let hmac = kvendra::vault::compute_allowlist_hmac(&key, SAMPLE_YAML.as_bytes());
    let mut meta = v.load_profile_meta("p").unwrap();
    meta.allowlist_hmac_hex = Some(hmac.clone());
    v.save_profile_meta(&meta).unwrap();

    let after = v.load_profile_meta("p").unwrap();
    assert_eq!(after.allowlist_hmac_hex.as_deref(), Some(hmac.as_str()));
}

/// REQ-KVD-007 AC-7 (regression) — the secret blob on disk is the AES-256-GCM
/// ciphertext, not the plaintext. Adding a HMAC field to ProfileMeta must
/// not alter the blob's encrypted shape. The plaintext token must NEVER
/// appear in the on-disk blob bytes.
#[test]
fn secret_blob_remains_opaque_after_set_allowlist() {
    let dir = tempdir().unwrap();
    let v = bootstrap(dir.path());
    std::fs::write(v.profile_allowlist_path("p"), SAMPLE_YAML).unwrap();
    let key = v.allowlist_hmac_key().unwrap();
    let hmac = kvendra::vault::compute_allowlist_hmac(&key, SAMPLE_YAML.as_bytes());
    let mut meta = v.load_profile_meta("p").unwrap();
    meta.allowlist_hmac_hex = Some(hmac);
    v.save_profile_meta(&meta).unwrap();

    let blob = std::fs::read(v.profile_blob_path("p")).unwrap();
    assert!(
        !blob
            .windows(b"sometoken-plaintext".len())
            .any(|w| w == b"sometoken-plaintext"),
        "secret blob unexpectedly contains plaintext (AES-256-GCM regression)"
    );
}

/// REQ-KVD-007 AC-3 — when an attacker edits the YAML out-of-band, a
/// fresh-process audit chain is still verifiable: writing an
/// `allowlist_tampered_detected` row and updating the row's status to
/// `error` must not break the HMAC chain that `audit verify` relies on.
#[tokio::test]
async fn audit_chain_remains_intact_when_tampering_event_appended() {
    let dir = tempdir().unwrap();
    let v = bootstrap(dir.path());
    let hmac_key = v.audit_hmac_key().unwrap();
    let writer = AuditWriter::spawn(v.audit_db_path(), hmac_key.clone()).unwrap();

    let event = AuditEvent {
        ts_unix_ms: (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64,
        primitive: "kvendra.shell".into(),
        action: "run".into(),
        status: Status::Started,
        severity: Severity::Info,
        profile_id: "p".into(),
        args_hash_hex: kvendra::audit::reader::args_hash_hex(&serde_json::json!({})),
        flags: "allowlist_tampered_detected".into(),
    };
    let row_id = writer.record(event).await.unwrap();
    writer
        .update_status(row_id, Status::Error, Severity::Error)
        .await
        .unwrap();
    writer.shutdown().await;

    let conn = open_readonly(&v.audit_db_path()).unwrap();
    verify_chain(&conn, &hmac_key).expect("chain must remain intact post-tampering row");
    let flags: String = conn
        .query_row(
            "SELECT flags FROM audit_events WHERE id = ?1",
            [row_id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(flags.contains("allowlist_tampered_detected"));
}

/// REQ-KVD-007 — a profile written before this feature shipped (no
/// `allowlist_hmac_hex` in JSON) must round-trip cleanly through the
/// public Vault APIs. This locks in the `#[serde(default)]` backward-
/// compatibility for legacy profiles.
#[test]
fn legacy_profile_meta_without_hmac_field_loads() {
    let dir = tempdir().unwrap();
    let v = bootstrap(dir.path());
    // Overwrite the meta file with a JSON payload missing the new field —
    // simulating a profile persisted by an older binary.
    let legacy = r#"{
        "profile_id": "p",
        "secret_type": "github_pat",
        "created_at": "2026-04-01T00:00:00Z",
        "expiration": null,
        "unsafe_raw_token_enabled": false,
        "quarantined": false
    }"#;
    std::fs::write(v.profile_meta_path("p"), legacy).unwrap();

    let loaded = v.load_profile_meta("p").unwrap();
    assert_eq!(loaded.profile_id, "p");
    assert!(
        loaded.allowlist_hmac_hex.is_none(),
        "legacy profile must load with allowlist_hmac_hex = None"
    );
}
