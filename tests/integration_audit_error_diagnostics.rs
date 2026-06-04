//! Integration tests — audit `error_code` / `error_message` diagnostics
//! (ISSUE-KVD-CLI-6C43AA).
//!
//! When a primitive call fails, the dispatcher must now persist a closed
//! vocabulary `error_code` plus a SANITIZED `error_message` on the audit row,
//! committed to the v3 HMAC chain. These tests drive the real dispatcher and
//! inspect the resulting `audit.db`.
//!
//! Coverage:
//! - allowlist violation → error_code=ALLOWLIST_VIOLATION + non-empty message.
//! - `audit --json` (StoredEvent serialization) includes the two fields.
//! - the HMAC chain verifies with the new v3 rows present.

use kvendra::approval::{ApprovalCache, Transport};
use kvendra::audit::AuditWriter;
use kvendra::config::Config;
use kvendra::mcp::protocol::JsonRpcRequest;
use kvendra::mcp::server::{ServerContext, dispatch};
use kvendra::vault::kdf::KdfParams;
use kvendra::vault::{Profile, Vault};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Mutex;

fn fast_params() -> KdfParams {
    KdfParams {
        m_cost_kib: 19_456,
        t_cost: 2,
        p_cost: 1,
        salt: vec![1u8; 16],
    }
}

async fn bootstrap_ctx(yaml: &str, profile_id: &str) -> (TempDir, Arc<ServerContext>) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    kvendra::config::ensure_layout(home).unwrap();
    let v = Vault::new(home.to_path_buf());
    v.create_with_params(b"hunter2-error-diag", fast_params())
        .unwrap();
    v.unlock(b"hunter2-error-diag", 30).unwrap();
    v.put_secret(profile_id, b"sometoken").unwrap();
    v.save_profile_meta(&Profile {
        profile_id: profile_id.to_string(),
        secret_type: "github_pat".into(),
        created_at: "2026-05-07T00:00:00Z".into(),
        expiration: None,
        unsafe_raw_token_enabled: false,
        quarantined: false,
        allowlist_hmac_hex: None,
    })
    .unwrap();
    let allowlist_path = v.profile_allowlist_path(profile_id);
    std::fs::write(&allowlist_path, yaml).unwrap();
    let key = v.allowlist_hmac_key().unwrap();
    let hmac_hex = kvendra::vault::compute_allowlist_hmac(&key, yaml.as_bytes());
    let mut profile = v.load_profile_meta(profile_id).unwrap();
    profile.allowlist_hmac_hex = Some(hmac_hex);
    v.save_profile_meta(&profile).unwrap();

    let writer = AuditWriter::spawn(v.audit_db_path(), v.audit_hmac_key().unwrap()).unwrap();
    let mut config = Config::default();
    config.approval.mode = kvendra::approval::ApprovalMode::Silent;

    let ctx = Arc::new(ServerContext {
        vault: v,
        config,
        writer: std::sync::RwLock::new(Some(writer)),
        approval_cache: Arc::new(ApprovalCache::new()),
        approval_prompt_lock: Arc::new(Mutex::new(())),
        transport: Transport::Mcp,
        resolver: None,
        session: None,
        workspace_id: None,
    });
    (dir, ctx)
}

fn tools_call(
    profile: &str,
    primitive: &str,
    operation: &str,
    args: serde_json::Value,
) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: Some(serde_json::json!(1)),
        method: "tools/call".into(),
        params: Some(serde_json::json!({
            "name": primitive,
            "arguments": {
                "profile_id": profile,
                "operation": operation,
                "args": args,
            }
        })),
    }
}

const SHELL_ECHO_ONLY_YAML: &str = "profile_id: p\nsecret:\n  type: github_pat\nallowlist:\n  primitives:\n    - name: kvendra.shell\n      operations:\n        - run:\n            binaries: [\"echo\"]\n";

async fn drain(ctx: &Arc<ServerContext>) {
    if let Some(w) = ctx.audit_writer() {
        w.shutdown().await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(60)).await;
}

/// (b) An allowlist violation must stamp error_code=ALLOWLIST_VIOLATION and a
/// non-empty error_message that carries the rejection detail.
#[tokio::test]
async fn allowlist_violation_populates_error_code_and_message() {
    let (_dir, ctx) = bootstrap_ctx(SHELL_ECHO_ONLY_YAML, "p").await;
    // `cat` is not allowlisted → AllowlistViolation pre-dispatch.
    let req = tools_call(
        "p",
        "kvendra.shell",
        "run",
        serde_json::json!({ "bin": "cat", "argv": ["/etc/passwd"] }),
    );
    let _ = dispatch(req, ctx.clone()).await;
    drain(&ctx).await;

    let conn = rusqlite::Connection::open(ctx.vault.audit_db_path()).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT status, error_code, error_message FROM audit_events \
             WHERE status = 'error' ORDER BY id ASC",
        )
        .unwrap();
    let rows: Vec<(String, Option<String>, Option<String>)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .filter_map(Result::ok)
        .collect();

    assert!(
        rows.iter().any(
            |(_s, code, msg)| code.as_deref() == Some("ALLOWLIST_VIOLATION")
                && msg.as_deref().map(|m| !m.is_empty()).unwrap_or(false)
        ),
        "expected an error row with code ALLOWLIST_VIOLATION + message, got: {rows:?}"
    );
}

/// (d) `audit --json` serializes StoredEvent; the error fields must appear on
/// error rows (and be absent / null on ok rows).
#[tokio::test]
async fn audit_json_includes_error_fields() {
    let (_dir, ctx) = bootstrap_ctx(SHELL_ECHO_ONLY_YAML, "p").await;
    let req = tools_call(
        "p",
        "kvendra.shell",
        "run",
        serde_json::json!({ "bin": "cat", "argv": ["x"] }),
    );
    let _ = dispatch(req, ctx.clone()).await;
    drain(&ctx).await;

    let conn = kvendra::audit::reader::open_readonly(&ctx.vault.audit_db_path()).unwrap();
    let events = kvendra::audit::reader::list_all(&conn).unwrap();
    let json = serde_json::to_string(&events).unwrap();
    assert!(
        json.contains("\"error_code\":\"ALLOWLIST_VIOLATION\""),
        "audit --json output must surface error_code; got: {json}"
    );
    assert!(
        json.contains("\"error_message\""),
        "audit --json output must surface error_message; got: {json}"
    );
}

/// (e) The HMAC chain must verify with v3 error rows present — both a legacy
/// (v1, NULL error fields) row inserted manually AND new dispatcher rows.
#[tokio::test]
async fn hmac_chain_verifies_with_legacy_and_v3_error_rows() {
    let (_dir, ctx) = bootstrap_ctx(SHELL_ECHO_ONLY_YAML, "p").await;
    let key = ctx.vault.audit_hmac_key().unwrap();

    // Insert a legacy v1-shape row directly (NULL error columns, hmac_version
    // defaults to 1 via the migrated schema's column default) as the FIRST row
    // so the chain root is a v1 entry.
    {
        let conn = rusqlite::Connection::open(ctx.vault.audit_db_path()).unwrap();
        let h = kvendra::audit::hmac::compute_hmac_v1(
            &key,
            1,
            1_700_000_000_000,
            "p",
            "kvendra.shell",
            "run",
            "ab",
            "ok",
            "info",
            "",
            "",
        );
        conn.execute(
            "INSERT INTO audit_events (id, ts_unix_ms, profile_id, primitive, action,
             args_hash_hex, status, severity, flags, prev_hmac_hex, hmac_hex, hmac_version)
             VALUES (1, 1700000000000, 'p', 'kvendra.shell', 'run', 'ab', 'ok', 'info', '', '', ?1, 1)",
            [&h],
        )
        .unwrap();
    }

    // Now drive a real failing call (v3 error row) + a successful call (v3 ok).
    let bad = tools_call(
        "p",
        "kvendra.shell",
        "run",
        serde_json::json!({ "bin": "cat", "argv": ["x"] }),
    );
    let _ = dispatch(bad, ctx.clone()).await;
    let good = tools_call(
        "p",
        "kvendra.shell",
        "run",
        serde_json::json!({ "binary": "echo", "argv": ["hi"] }),
    );
    let _ = dispatch(good, ctx.clone()).await;
    drain(&ctx).await;

    let conn = kvendra::audit::reader::open_readonly(&ctx.vault.audit_db_path()).unwrap();
    let r = kvendra::audit::reader::verify_chain(&conn, &key);
    assert!(
        r.is_ok(),
        "HMAC chain must verify across a legacy v1 row and new v3 error rows, got: {r:?}"
    );
}
