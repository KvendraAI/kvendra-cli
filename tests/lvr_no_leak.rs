//! TEST-KVD-CLI-NEW-1 (AC-LVR-1) + TEST-KVD-CLI-NEW-2 (AC-LVR-2) —
//! REQ-KVD-11F906. No MCP response (result, error message, error data) ever
//! carries a value of `vars.blob`, across the 8 primitives, with references in
//! bounded and free positions, allowlist denials that echo the resolved
//! field, primitive failures, and a binary that prints its cwd.

mod lvr_common;

use lvr_common::*;
use serde_json::json;

const YAML: &str = r#"profile_id: p
secret:
  type: github_pat
allowlist:
  primitives:
    - name: kvendra.shell
      operations:
        - exec:
            binaries: ["pwd", "ls", "sh", "kvd-sentinel-missing-binary"]
            cwd_pattern: "^{WS}(/.*)?$"
            accept_destructive: true
    - name: kvendra.git
      operations:
        - commit:
            cwd_pattern: "^{WS}(/.*)?$"
            accept_destructive: true
    - name: kvendra.github
      operations:
        - read_repo:
            repos: ["github.com/kvd-sentinel-org/*"]
    - name: kvendra.http
      operations:
        - request:
            url_pattern_regex: ["^https://api\\.kvd-sentinel-allowed\\.example/"]
            methods: ["GET"]
    - name: kvendra.aws
      operations:
        - s3_cp:
            buckets: ["kvd-sentinel-bucket"]
            accept_destructive: true
    - name: kvendra.pypi
      operations:
        - upload:
            accept_destructive: true
    - name: kvendra.npm
      operations:
        - publish:
            packages: ["kvd-sentinel-pkg"]
            accept_destructive: true
    - name: kvendra.unsafe.raw_token
      unsafe_raw_token_allowed: false
"#;

fn assert_no_sentinel(f: &Fixture, resp: &serde_json::Value, case: &str) {
    let s = resp.to_string();
    for sentinel in f.sentinels() {
        assert!(
            !s.contains(&sentinel),
            "[{case}] local value leaked in the MCP response: {s}"
        );
    }
}

#[tokio::test]
async fn no_local_value_in_any_response_across_the_8_primitives() {
    let f = fixture(YAML).await;
    let cases: Vec<(&str, &str, &str, serde_json::Value)> = vec![
        // shell — bounded cwd, binary prints its cwd (output must be masked).
        (
            "shell pwd bounded",
            "kvendra.shell",
            "exec",
            json!({"binary": "pwd", "argv": [], "cwd": "{{lvr:ws}}"}),
        ),
        // shell — primitive failure (binary not found) with a bounded cwd.
        (
            "shell failure",
            "kvendra.shell",
            "exec",
            json!({"binary": "kvd-sentinel-missing-binary", "argv": [], "cwd": "{{lvr:ws}}"}),
        ),
        // shell — reference in a free position (argv without template).
        (
            "shell argv free",
            "kvendra.shell",
            "exec",
            json!({"binary": "ls", "argv": ["{{lvr:s}}"], "cwd": "{{lvr:ws}}"}),
        ),
        // git — free-text message with a reference (unbounded).
        (
            "git message ref",
            "kvendra.git",
            "commit",
            json!({"cwd": "{{lvr:ws}}", "message": "fix {{lvr:s}}"}),
        ),
        // git — free-text message with the LITERAL value (O8 guard).
        (
            "git message literal",
            "kvendra.git",
            "commit",
            json!({"cwd": "{{lvr:ws}}", "message": format!("touch {}", SENTINEL_STRING)}),
        ),
        // github — reference in `repo` (unbounded).
        (
            "github repo",
            "kvendra.github",
            "read_repo",
            json!({"repo": "kvd-sentinel-org/{{lvr:s}}"}),
        ),
        // http — url bounded but outside the pattern: the denial echoes it.
        (
            "http url denied",
            "kvendra.http",
            "request",
            json!({"url": "https://{{lvr:host}}/v1", "method": "GET"}),
        ),
        // http — body (never accepted, O5).
        (
            "http body",
            "kvendra.http",
            "request",
            json!({"url": "https://api.kvd-sentinel-allowed.example/x", "method": "GET", "body": "{{lvr:s}}"}),
        ),
        // aws — local src without local_roots: the denial echoes the path.
        (
            "aws src",
            "kvendra.aws",
            "s3_cp",
            json!({"src": "{{lvr:ws}}/f", "dst": "s3://kvd-sentinel-bucket/f"}),
        ),
        // pypi — dist without local_roots: the denial echoes the path.
        (
            "pypi dist",
            "kvendra.pypi",
            "upload",
            json!({"dist": "{{lvr:ws}}/dist"}),
        ),
        // npm — reference in `package` (unbounded).
        (
            "npm package",
            "kvendra.npm",
            "publish",
            json!({"package": "{{lvr:s}}", "cwd": "{{lvr:ws}}"}),
        ),
    ];
    for (case, prim, op, args) in cases {
        let resp = run(&f, call(prim, op, args)).await;
        assert_no_sentinel(&f, &resp, case);
    }
    // Escape hatch — reference in the free `reason`.
    let req = kvendra::mcp::protocol::JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: Some(json!(1)),
        method: "tools/call".into(),
        params: Some(json!({
            "name": "kvendra.unsafe.raw_token",
            "arguments": {"profile_id": "p", "reason": "debugging {{lvr:s}} for a while"}
        })),
    };
    let resp = run(&f, req).await;
    assert_no_sentinel(&f, &resp, "raw_token reason");
}

/// The positive path really executes and its output is re-symbolized (O4).
#[tokio::test]
async fn bounded_cwd_executes_and_output_is_resymbolized() {
    let f = fixture(YAML).await;
    let resp = run(
        &f,
        call(
            "kvendra.shell",
            "exec",
            json!({"binary": "pwd", "argv": [], "cwd": "{{lvr:ws}}"}),
        ),
    )
    .await;
    assert!(resp.get("result").is_some(), "pwd must execute: {resp}");
    assert!(
        resp.to_string().contains("{{lvr:ws}}"),
        "the cwd printed by pwd must come back as the reference: {resp}"
    );
    assert_no_sentinel(&f, &resp, "pwd");
    let rows = audit_rows(&f).await;
    assert!(
        rows.iter().any(|(fl, _, _)| fl == "lvr_output_masked"),
        "{rows:?}"
    );
}

/// TEST-KVD-CLI-NEW-2 (AC-LVR-2) — the allowlist is evaluated on the RESOLVED
/// value: `cwd_pattern` bounds `.../tmp-a`, the variable resolves to
/// `.../tmp-b` → `allowlist_denied`, and the message (which echoes the cwd)
/// is masked.
#[tokio::test]
async fn allowlist_evaluates_resolved_value_and_masks_the_denial() {
    let yaml = r#"profile_id: p
secret:
  type: github_pat
allowlist:
  primitives:
    - name: kvendra.shell
      operations:
        - exec:
            binaries: ["pwd"]
            cwd_pattern: "^{WS}/tmp-a$"
            accept_destructive: true
"#;
    let f = fixture(yaml).await;
    let b = f.ws.join("tmp-b");
    std::fs::create_dir_all(&b).unwrap();
    kvendra::vars::set_var(
        &f.ctx.vault,
        "other",
        kvendra::vars::VarType::Path,
        &b.to_string_lossy(),
        true,
    )
    .unwrap();
    let resp = run(
        &f,
        call(
            "kvendra.shell",
            "exec",
            json!({"binary": "pwd", "argv": [], "cwd": "{{lvr:other}}"}),
        ),
    )
    .await;
    let msg = resp
        .pointer("/error/message")
        .and_then(|m| m.as_str())
        .unwrap_or("");
    assert!(
        msg.contains("not allowed"),
        "expected allowlist denial: {resp}"
    );
    assert!(
        msg.contains("{{lvr:other}}"),
        "the echoed cwd must be masked: {resp}"
    );
    assert!(!resp.to_string().contains(&*b.to_string_lossy()), "{resp}");
    let rows = audit_rows(&f).await;
    assert!(
        rows.iter()
            .any(|(fl, _, _)| fl.contains("allowlist_denied")),
        "{rows:?}"
    );
    for (_, msg, _) in &rows {
        assert!(
            !msg.contains(&*b.to_string_lossy()),
            "audit error_message leaked: {msg}"
        );
    }
}
