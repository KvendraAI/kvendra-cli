//! Integration tests for ISSUE-KVD-CLI-2F07ED — `kvendra session info`
//! must coexist with a Pro-tier token (`~/.kvendra/sessions/pro.token`).
//!
//! The bug: `list_active_sessions` lists `pro.token` as if it were a
//! workspace session, and downstream `SessionState::load("pro")` fails to
//! decode the raw JWT as JSON. These tests exercise the full binary so
//! they catch the regression at the user-visible CLI layer.

use assert_cmd::Command;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use kvendra::session::SessionState;
use chrono::{Duration as ChronoDuration, Utc};
use tempfile::tempdir;

/// Synthesise a 3-segment JWT (header.payload.sig) like the one `pro_login`
/// persists raw to `pro.token`. The signature is bogus — `session info`
/// does not verify it.
fn make_jwt(payload: serde_json::Value) -> String {
    let header = B64URL.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let body = B64URL.encode(payload.to_string().as_bytes());
    let sig = B64URL.encode(b"sig");
    format!("{header}.{body}.{sig}")
}

fn write_pro_token(home: &std::path::Path) {
    let sessions = home.join("sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    let jwt = make_jwt(serde_json::json!({
        "email": "pro-user@kvendra.cloud",
        "sub":   "550e8400-e29b-41d4-a716-446655440000",
        "iss":   "https://auth.kvendra.cloud",
    }));
    std::fs::write(sessions.join("pro.token"), jwt.as_bytes()).unwrap();
}

fn write_workspace_token(home: &std::path::Path, workspace_id: &str) {
    use kvendra::auth::oidc::TokenSet;
    let token_set = TokenSet {
        access_token: make_jwt(serde_json::json!({"email": "bob@acme.com"})),
        id_token: make_jwt(serde_json::json!({
            "email": "bob@acme.com",
            "sub":   "550e8400-e29b-41d4-a716-446655440000",
            "iss":   "https://auth.kvendra.cloud",
        })),
        refresh_token: "rt-opaque".into(),
        expires_in: 3600,
        token_type: "Bearer".into(),
    };
    let now = Utc::now();
    let state = SessionState::from_token_set(
        workspace_id,
        "acme-corp",
        "550e8400-e29b-41d4-a716-446655440000",
        "bob@acme.com",
        "https://auth.kvendra.cloud",
        "client-id",
        &token_set,
        None,
        now,
    );
    // Override jwt_expires_at to make sure it is comfortably in the future
    // regardless of clock drift in CI.
    let mut state = state;
    state.jwt_expires_at = now + ChronoDuration::minutes(30);
    state.persist_atomic(home).unwrap();
}

#[test]
fn session_info_works_with_pro_token_present() {
    // BUG-A (ISSUE-KVD-CLI-170F9D): before the fix, this case reported
    // `mode == "local"` (Free tier) which was misleading. After the fix,
    // when only `pro.token` exists, `mode == "pro"` and a `pro` block is
    // emitted carrying the decoded email/issuer for UX.
    let home = tempdir().unwrap();
    write_pro_token(home.path());

    let assert = Command::cargo_bin("kvendra")
        .unwrap()
        .env("KVENDRA_HOME", home.path())
        .args(["session", "info", "--json"])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .expect("session info --json must emit valid JSON when only pro.token exists");
    assert_eq!(
        json.get("mode").and_then(|v| v.as_str()),
        Some("pro"),
        "with only pro.token present, mode must be 'pro' (BUG-A fix), got: {stdout}"
    );
    let pro = json.get("pro").expect("pro section must be present");
    assert_eq!(
        pro.get("active").and_then(|v| v.as_bool()),
        Some(true),
        "pro.active must be true, got: {stdout}"
    );
    assert_eq!(
        pro.get("email").and_then(|v| v.as_str()),
        Some("pro-user@kvendra.cloud"),
        "pro.email must be decoded from JWT, got: {stdout}"
    );
    assert_eq!(
        pro.get("issuer").and_then(|v| v.as_str()),
        Some("https://auth.kvendra.cloud"),
        "pro.issuer must be decoded from JWT, got: {stdout}"
    );
}

#[test]
fn session_info_pro_coexists_with_workspace_session() {
    // BUG-A coexistence: when both pro.token AND a workspace session are
    // present, mode stays "workspace" (workspace prevails) but the `pro`
    // block is still emitted so the operator sees both at once.
    let home = tempdir().unwrap();
    write_pro_token(home.path());
    let ws = "acme/frontend";
    write_workspace_token(home.path(), ws);

    let assert = Command::cargo_bin("kvendra")
        .unwrap()
        .env("KVENDRA_HOME", home.path())
        .args(["session", "info", "--json"])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .expect("session info --json must emit valid JSON when pro+workspace tokens coexist");
    assert_eq!(
        json.get("mode").and_then(|v| v.as_str()),
        Some("workspace"),
        "workspace prevails, got: {stdout}"
    );
    let pro = json
        .get("pro")
        .expect("pro section must be present alongside workspace");
    assert_eq!(
        pro.get("email").and_then(|v| v.as_str()),
        Some("pro-user@kvendra.cloud"),
        "pro section must still carry decoded JWT claims, got: {stdout}"
    );
}

#[test]
fn session_info_works_with_pro_token_and_workspace_token() {
    let home = tempdir().unwrap();
    write_pro_token(home.path());
    // Use a workspace_id that slug-sorts AFTER "pro" so `list_active_sessions`
    // (sorted alphabetically) yields ["pro", "zzz-tenant/frontend"]. With the
    // bug present, the multi-session branch picks sessions[0] == "pro" and
    // `SessionState::load("pro")` fails to decode the raw JWT — exposing the
    // bug. With the fix, "pro" is skipped, sessions==["zzz-tenant/frontend"],
    // and the workspace view is built correctly.
    let ws = "zzz-tenant/frontend";
    write_workspace_token(home.path(), ws);

    let assert = Command::cargo_bin("kvendra")
        .unwrap()
        .env("KVENDRA_HOME", home.path())
        .args(["session", "info", "--json"])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .expect("session info --json must emit valid JSON when pro+workspace tokens coexist");
    assert_eq!(
        json.get("mode").and_then(|v| v.as_str()),
        Some("workspace"),
        "with workspace token present, mode must be 'workspace' (pro.token ignored), got: {stdout}"
    );
    assert_eq!(
        json.get("workspace_id").and_then(|v| v.as_str()),
        Some(ws),
        "workspace_id must be reported, got: {stdout}"
    );
}
