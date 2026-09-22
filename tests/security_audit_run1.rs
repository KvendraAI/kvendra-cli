//! Adversarial security regression suite — Cloudflare-style internal audit
//! RUN-KVD-CLI-190069 (run 1), executed against v0.6.4 (`e41b652`).
//!
//! Same contract as `tests/security_audit_salva.rs`: every test is an ATTACK
//! (or the pure-function shape behind one) asserted against the SECURE
//! behaviour. The suite is therefore **red on `e41b652` and green after the
//! remediation** of the nine findings below — a test that passes identically
//! before and after the fix would be worthless.
//!
//!   SA1  ISSUE-KVD-CLI-DDFB49  HIGH  kvendra.github target-shape mismatch
//!                                    bypasses the repos/org allowlist scope
//!   SA2  ISSUE-KVD-CLI-9D5CF5  HIGH  the LOCAL filesystem operand of every
//!                                    brokered transfer is unconstrained
//!   SA3  ISSUE-KVD-CLI-705EF0  MED   KVENDRA_APPROVAL_MODE outranks the
//!                                    HMAC-signed approval policy
//!   SA4  ISSUE-KVD-CLI-F4ED93  MED   audit-chain HMAC input is non-injective
//!                                    and the layout version is unauthenticated
//!   SA5  ISSUE-KVD-CLI-3319F0  MED   broker-supplied `template_id` is joined
//!                                    into a filesystem path without validation
//!   SA6  ISSUE-KVD-CLI-BFACC4  MED   config-mutating subcommands launder an
//!                                    integrity-refused config into signed
//!                                    defaults
//!   SA7  ISSUE-KVD-CLI-9B3395  MED   the destructive catalog omits
//!                                    github.release / github.add_topics
//!   SA8  ISSUE-KVD-CLI-8F501A  MED   a low-entropy decoy hides every real
//!                                    token of the same provider from `detect`
//!   SA10 ISSUE-KVD-CLI-0F929A  MED   supply chain (Cargo.lock un-versioned,
//!                                    no `--locked`, deny.toml never executed)
//!                                    — verified by SHELL checks, not by a
//!                                    Rust test; see the TEST entity for the
//!                                    recorded RED output.
//!
//! In-crate `#[cfg(test)]` companions live where the API is private or where
//! the process environment has to be locked:
//!   - SA5 write-boundary  → `src/workspace/allowlist_sync.rs` (`sa5_*`)
//!   - SA6 config writers  → `src/cli/config_approval.rs`      (`sa6_*`)
//!
//! HARD RULES honoured by every test here: temp `KVENDRA_HOME` only (the
//! production vault `~/.kvendra/` is never read or written), no process-env
//! mutation from this binary (no lock available in `tests/`), and no
//! `dispatch()` that could resolve to `Ask`/`AskDestructive` on a destructive
//! op — that would reach the biometric / TTY approval backend and hang CI on
//! a modal dialog.

use kvendra::allowlist::catalog;
use kvendra::allowlist::dsl::ProfileSpec;
use kvendra::allowlist::enforcer::check;
use kvendra::allowlist::validate;
use kvendra::approval::policy;
use kvendra::approval::{ApprovalCache, ApprovalMode, Transport};
use kvendra::audit::AuditWriter;
use kvendra::audit::hmac::{compute_hmac_v2, compute_hmac_v3};
use kvendra::config::{Config, DetectionSeverity};
use kvendra::detection::{detect, sanitize_output};
use kvendra::mcp::protocol::JsonRpcRequest;
use kvendra::mcp::server::{ServerContext, dispatch};
use kvendra::vault::kdf::KdfParams;
use kvendra::vault::{Profile, Vault};
use kvendra::workspace::allowlist_sync::{cache_root, template_cache_path, template_etag_path};
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Mutex;

// ═════════════════════════════════════════════════════════════════════════
// Shared helpers (mirrors of tests/security_audit_salva.rs:43-137 — kept
// local because integration test binaries cannot share a module).
// ═════════════════════════════════════════════════════════════════════════

fn fast_params() -> KdfParams {
    KdfParams {
        m_cost_kib: 19_456,
        t_cost: 2,
        p_cost: 1,
        salt: vec![1u8; 16],
    }
}

fn spec_of(yaml: &str) -> ProfileSpec {
    ProfileSpec::from_yaml(yaml).unwrap()
}

/// Canonical MCP envelope `{profile_id, operation, args}` — the enforcer reads
/// the INNER `args` object (PAT-KVD-004 / H2).
fn env_args(operation: &str, args: Value) -> Value {
    json!({ "profile_id": "x", "operation": operation, "args": args })
}

/// Sandbox `ServerContext`. Approval mode is always `Silent` so `dispatch`
/// never reaches the biometric / TTY backend.
async fn bootstrap(
    profile_id: &str,
    allowlist_yaml: &str,
    detection_severity: DetectionSeverity,
) -> (TempDir, Arc<ServerContext>) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    kvendra::config::ensure_layout(home).unwrap();
    let v = Vault::new(home.to_path_buf());
    v.create_with_params(b"hunter2-run1-audit", fast_params())
        .unwrap();
    v.unlock(b"hunter2-run1-audit", 30).unwrap();
    v.put_secret(profile_id, b"ghp_notarealtokenjustplaceholder000000")
        .unwrap();
    v.save_profile_meta(&Profile {
        profile_id: profile_id.to_string(),
        secret_type: "github_pat".into(),
        created_at: "2026-09-18T00:00:00Z".into(),
        expiration: None,
        unsafe_raw_token_enabled: false,
        quarantined: false,
        allowlist_hmac_hex: None,
    })
    .unwrap();

    let allowlist_path = v.profile_allowlist_path(profile_id);
    std::fs::write(&allowlist_path, allowlist_yaml).unwrap();
    let key = v.allowlist_hmac_key().unwrap();
    let hmac_hex = kvendra::vault::compute_allowlist_hmac(&key, allowlist_yaml.as_bytes());
    let mut profile = v.load_profile_meta(profile_id).unwrap();
    profile.allowlist_hmac_hex = Some(hmac_hex);
    v.save_profile_meta(&profile).unwrap();

    let writer = AuditWriter::spawn(v.audit_db_path(), v.audit_hmac_key().unwrap()).unwrap();
    let mut config = Config::default();
    config.approval.mode = ApprovalMode::Silent;
    config.detection.severity = detection_severity;

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

async fn drain(ctx: &Arc<ServerContext>) {
    if let Some(w) = ctx.audit_writer() {
        w.shutdown().await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(60)).await;
}

/// `(primitive, flags, status)` for every audit row, oldest first.
async fn audit_rows(ctx: &Arc<ServerContext>) -> Vec<(String, String, String)> {
    drain(ctx).await;
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

const SHELL_ECHO_ONLY: &str = r#"
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

// ═════════════════════════════════════════════════════════════════════════
// SA1 — ISSUE-KVD-CLI-DDFB49 (HIGH)
// kvendra.github target-shape mismatch bypasses the repos / org scope.
//
// RED at e41b652: `check_args` derives the non-git target ONLY from `repo` /
// `url` (src/allowlist/enforcer.rs:422-431) and, when nothing is derivable,
// takes an EARLY `return Ok(())` (:443) that is fail-closed for git only.
// The primitive resolves the target from `repo` OR `owner`+`repo_name`/`name`
// and NEVER reads `url` (src/primitives/github.rs:63-86). Three divergences
// follow: omission, `url` decoy, and `extract_owner_from_repo` (:597-601)
// dropping the FIRST segment as if it were a host.
//
// Enforcer level ONLY — an allowed github call would hit api.github.com.
// ═════════════════════════════════════════════════════════════════════════

const GH_REPOS_SCOPE: &str = r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - list_issues:
            repos: ["KvendraAI/*"]
        - read_repo:
            repos: ["KvendraAI/*"]
"#;

const GH_ORG_SCOPE: &str = r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - update_repo:
            org: ["KvendraAI"]
            accept_destructive: true
        - read_repo:
            org: ["KvendraAI"]
"#;

/// Bypass 1 — OMISSION. The call carries the shape the primitive actually
/// parses (`owner` + `repo_name`) and no `repo`/`url` at all, so the enforcer
/// cannot derive a target and returns Ok. The primitive then happily targets
/// `AttackerAcct/out-of-scope-repo`.
#[test]
fn sa1_owner_repo_name_shape_must_not_bypass_the_repos_scope() {
    let s = spec_of(GH_REPOS_SCOPE);
    let args = env_args(
        "list_issues",
        json!({ "owner": "AttackerAcct", "repo_name": "out-of-scope-repo" }),
    );
    let r = check(&s, "kvendra.github", "list_issues", &args);
    assert!(
        r.is_err(),
        "a github call whose target is out of the `repos` scope must be DENIED \
         (fail-closed on shape mismatch); enforcer returned {r:?}"
    );
}

/// Bypass 2 — DECOY. `url` is in the allowlisted scope and satisfies the
/// enforcer; the primitive ignores `url` entirely and targets the
/// `owner`+`repo_name` pair instead.
#[test]
fn sa1_decoy_url_must_not_mask_the_real_target() {
    let s = spec_of(GH_REPOS_SCOPE);
    let args = env_args(
        "read_repo",
        json!({
            "url": "KvendraAI/kvendra-cli",
            "owner": "AttackerAcct",
            "repo_name": "private-repo"
        }),
    );
    let r = check(&s, "kvendra.github", "read_repo", &args);
    assert!(
        r.is_err(),
        "a github call carrying a `url` the primitive never reads plus a real \
         out-of-scope target must be DENIED (conflicting target fields); \
         enforcer returned {r:?}"
    );
}

/// Bypass 3 — ORG INVERSION. `extract_owner_from_repo` discards the first
/// segment as a host, so `AttackerAcct/KvendraAI` is read as owner
/// `KvendraAI` (allowed) while the primitive targets owner `AttackerAcct`.
#[test]
fn sa1_org_scope_must_compare_the_owner_not_the_repo_name() {
    let s = spec_of(GH_ORG_SCOPE);
    let args = env_args(
        "update_repo",
        json!({ "repo": "AttackerAcct/KvendraAI", "homepage": "https://evil.example" }),
    );
    let r = check(&s, "kvendra.github", "update_repo", &args);
    assert!(
        r.is_err(),
        "org scope must be evaluated against the OWNER half of `owner/name`; \
         enforcer returned {r:?}"
    );
}

/// Bypass 4 (surfaced by the analysis, folded into DDFB49) — the org block is
/// SILENTLY SKIPPED when no owner is visible (enforcer.rs:402
/// `if let Some(o) = owner.as_deref()`), so an org-only profile authorises a
/// call with no resolvable owner at all.
#[test]
fn sa1_org_scope_must_fail_closed_when_no_owner_resolves() {
    let s = spec_of(GH_ORG_SCOPE);
    let args = env_args("read_repo", json!({}));
    let r = check(&s, "kvendra.github", "read_repo", &args);
    assert!(
        r.is_err(),
        "an `org` constraint with no resolvable owner must DENY, never skip; \
         enforcer returned {r:?}"
    );
}

/// Bypass 3, FALSE-NEGATIVE face (surfaced while executing the plan — the
/// analysis expected this one to be a guard). Because
/// `extract_owner_from_repo` drops the first segment as a host, the
/// LEGITIMATE two-segment `owner/name` form — the shape the primitive parses
/// and the shape the KB recipe documents — resolves to owner `kvendra-cli`
/// and is DENIED today. One broken canonicalizer, both error directions.
#[test]
fn sa1_org_scope_must_allow_the_legitimate_owner_slash_name_form() {
    let org = spec_of(GH_ORG_SCOPE);
    let ok_org = env_args(
        "update_repo",
        json!({ "repo": "KvendraAI/kvendra-cli", "homepage": "https://kvendra.com" }),
    );
    let r = check(&org, "kvendra.github", "update_repo", &ok_org);
    assert!(
        r.is_ok(),
        "`repo: \"KvendraAI/kvendra-cli\"` under `org: [\"KvendraAI\"]` is the \
         documented happy path and must PASS — today the owner is read from \
         the wrong segment, so it is refused with the repo NAME as the org; \
         got {r:?}"
    );
}

/// GUARD (green before AND after) — the legitimate shapes must keep working,
/// so the fix cannot be "deny everything".
#[test]
fn sa1_guard_legitimate_github_targets_still_pass() {
    let s = spec_of(GH_REPOS_SCOPE);
    let ok = env_args("list_issues", json!({ "repo": "KvendraAI/kvendra-cli" }));
    assert!(
        check(&s, "kvendra.github", "list_issues", &ok).is_ok(),
        "a target inside the declared `repos` scope must pass"
    );

    let org = spec_of(GH_ORG_SCOPE);
    // Explicit `owner` field — the only org shape the enforcer reads correctly
    // today (mirrors `org_happy_owner_field`, src/allowlist/enforcer.rs:1648).
    let ok_org = env_args(
        "update_repo",
        json!({ "owner": "KvendraAI", "repo_name": "kvendra-cli", "homepage": "https://kvendra.com" }),
    );
    assert!(
        check(&org, "kvendra.github", "update_repo", &ok_org).is_ok(),
        "an explicit in-scope `owner` must pass"
    );
}

// GREEN-only (implementer): once `github_target` / `github_owner` are the one
// shared resolver used by BOTH the primitive and the enforcer, add —
//   * `check(GH_REPOS_SCOPE, read_repo, {owner:"KvendraAI", repo_name:"x/../../../user"})`
//     → Err (owner/repo halves charset-validated, blocks `..` path-segment
//     injection into the api.github.com URL);
//   * `check(GH_REPOS_SCOPE, read_repo, {repo:"github.com/KvendraAI/kvendra-cli"})`
//     → Ok (github `repos` patterns host-normalised — today this DENIES);
//   * `check(GH_REPOS_SCOPE, release, {owner:"KvendraAI", name:"v1.0.0", tag_name:"v1.0.0"})`
//     → Err (`name` is the release TITLE on `release`, never a repo alias);
//   * the error messages: "cannot determine the target repository" +
//     "fail-closed" on omission, and the REAL target named on the decoy/org
//     cases;
//   * a spec with `repos` + `env_vars_to_inject: ["FOO"]` called WITHOUT a
//     repo and with `env: {"BAR": "1"}` → Err, proving the early `return Ok(())`
//     no longer skips the constraints below it;
//   * a producer↔enforcer contract test driving the enforcer with the exact
//     payload `primitives::github` builds (PAT-KVD-CLI-1A99C5).
// None of these can be expressed today: the resolver does not exist, the
// host-normalisation and the `name`-on-release rule do not exist, and the
// messages are the ones the buggy branches emit.
//
// GREEN-only block (landed with the remediation): the shared resolver is
// `kvendra::primitives::github::resolve_target`.

const GH_RELEASE_SCOPE: &str = r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - release:
            repos: ["KvendraAI/*"]
            accept_destructive: true
"#;

#[test]
fn sa1_green_owner_and_repo_halves_are_charset_validated() {
    let s = spec_of(GH_REPOS_SCOPE);
    for payload in [
        json!({ "owner": "KvendraAI", "repo_name": "x/../../../user" }),
        json!({ "owner": "KvendraAI", "repo_name": ".." }),
        json!({ "repo": "KvendraAI/x/../../y" }),
        json!({ "repo": "KvendraAI/kvendra-cli?x=1" }),
    ] {
        let r = check(
            &s,
            "kvendra.github",
            "read_repo",
            &env_args("read_repo", payload.clone()),
        );
        assert!(r.is_err(), "{payload} must be refused; got {r:?}");
    }
}

#[test]
fn sa1_green_github_repos_patterns_are_host_normalised() {
    let s = spec_of(GH_REPOS_SCOPE);
    let args = env_args(
        "read_repo",
        json!({ "repo": "github.com/KvendraAI/kvendra-cli" }),
    );
    let r = check(&s, "kvendra.github", "read_repo", &args);
    assert!(
        r.is_ok(),
        "host-qualified in-scope repo must pass; got {r:?}"
    );
}

#[test]
fn sa1_green_name_is_not_a_repo_alias_on_release() {
    let s = spec_of(GH_RELEASE_SCOPE);
    let title_only = env_args(
        "release",
        json!({ "owner": "KvendraAI", "name": "v1.0.0", "tag_name": "v1.0.0" }),
    );
    let err = check(&s, "kvendra.github", "release", &title_only).unwrap_err();
    assert!(
        err.to_string()
            .contains("cannot determine the target repository"),
        "`name` is the release title, never the repo: {err}"
    );
    let ok = env_args(
        "release",
        json!({ "owner": "KvendraAI", "repo_name": "kvendra-cli", "name": "v1.0.0", "tag_name": "v1.0.0" }),
    );
    assert!(check(&s, "kvendra.github", "release", &ok).is_ok());
}

#[test]
fn sa1_green_error_messages_name_the_reason_and_the_real_target() {
    let repos = spec_of(GH_REPOS_SCOPE);
    let omission = check(
        &repos,
        "kvendra.github",
        "list_issues",
        &env_args("list_issues", json!({ "state": "open" })),
    )
    .unwrap_err()
    .to_string();
    assert!(
        omission.contains("cannot determine the target repository")
            && omission.contains("fail-closed"),
        "{omission}"
    );
    let decoy = check(
        &repos,
        "kvendra.github",
        "read_repo",
        &env_args(
            "read_repo",
            json!({ "url": "KvendraAI/kvendra-cli", "owner": "AttackerAcct", "repo_name": "private-repo" }),
        ),
    )
    .unwrap_err()
    .to_string();
    assert!(decoy.contains("AttackerAcct/private-repo"), "{decoy}");

    let org = spec_of(GH_ORG_SCOPE);
    let inv = check(
        &org,
        "kvendra.github",
        "update_repo",
        &env_args("update_repo", json!({ "repo": "AttackerAcct/KvendraAI" })),
    )
    .unwrap_err()
    .to_string();
    assert!(inv.contains("org 'AttackerAcct'"), "{inv}");
}

#[test]
fn sa1_green_missing_target_no_longer_skips_the_later_constraints() {
    let s = spec_of(
        r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - read_repo:
            repos: ["KvendraAI/*"]
            env_vars_to_inject: ["FOO"]
"#,
    );
    let no_repo = env_args("read_repo", json!({ "env": { "BAR": "1" } }));
    assert!(check(&s, "kvendra.github", "read_repo", &no_repo).is_err());
    // And with a resolvable target the env constraint below is reached.
    let with_repo = env_args(
        "read_repo",
        json!({ "repo": "KvendraAI/kvendra-cli", "env": { "BAR": "1" } }),
    );
    let err = check(&s, "kvendra.github", "read_repo", &with_repo).unwrap_err();
    assert!(err.to_string().contains("env var 'BAR'"), "{err}");
}

/// Producer↔enforcer contract (PAT-KVD-CLI-1A99C5): for every payload shape
/// the primitive accepts (and a few it refuses), the enforcer allows EXACTLY
/// when the target the primitive would call is inside the `repos` scope.
#[test]
fn sa1_green_producer_enforcer_contract_on_the_real_github_payloads() {
    use kvendra::primitives::github::resolve_target;
    let s = spec_of(GH_REPOS_SCOPE);
    for payload in [
        json!({ "repo": "KvendraAI/kvendra-cli" }),
        json!({ "repo": "github.com/KvendraAI/kvendra-cli" }),
        json!({ "repo": "AttackerAcct/kvendra-cli" }),
        json!({ "owner": "KvendraAI", "repo_name": "kvendra-cli" }),
        json!({ "owner": "KvendraAI", "name": "kvendra-cli" }),
        json!({ "owner": "AttackerAcct", "name": "kvendra-cli" }),
        json!({ "repo": "KvendraAI/kvendra-cli", "owner": "AttackerAcct", "repo_name": "x" }),
        json!({ "url": "KvendraAI/kvendra-cli", "owner": "AttackerAcct", "repo_name": "x" }),
        json!({ "url": "https://github.com/KvendraAI/kvendra-cli" }),
        json!({ "owner": "KvendraAI" }),
        json!({ "repo": "KvendraAI" }),
    ] {
        let primitive_hits_in_scope =
            resolve_target("read_repo", &payload).is_ok_and(|t| t.owner == "KvendraAI");
        let allowed = check(
            &s,
            "kvendra.github",
            "read_repo",
            &env_args("read_repo", payload.clone()),
        )
        .is_ok();
        assert_eq!(
            allowed, primitive_hits_in_scope,
            "enforcer and primitive disagree on {payload}"
        );
    }
}

/// GUARD — the real-world shapes of the owner's profiles keep working:
/// github ops scoped by `repos: ["KvendraAI/kvendra-cli"]`, and git
/// push/tag scoped by `repos` + `refs` / `tag_pattern` on a URL remote.
#[test]
fn sa1_guard_real_world_github_and_git_configs_still_pass() {
    let gh = spec_of(
        r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - release:
            repos: ["KvendraAI/kvendra-cli"]
            accept_destructive: true
        - add_topics:
            repos: ["KvendraAI/kvendra-cli"]
        - read_repo:
            repos: ["KvendraAI/kvendra-cli"]
"#,
    );
    for (op, payload) in [
        (
            "release",
            json!({ "repo": "KvendraAI/kvendra-cli", "tag_name": "v0.7.0", "name": "v0.7.0" }),
        ),
        (
            "add_topics",
            json!({ "repo": "KvendraAI/kvendra-cli", "topics": ["mcp"] }),
        ),
        (
            "read_repo",
            json!({ "repo": "github.com/KvendraAI/kvendra-cli" }),
        ),
    ] {
        let r = check(&gh, "kvendra.github", op, &env_args(op, payload.clone()));
        assert!(r.is_ok(), "{op} {payload} must pass; got {r:?}");
    }
    let r = check(
        &gh,
        "kvendra.github",
        "read_repo",
        &env_args("read_repo", json!({ "repo": "KvendraAI/other" })),
    );
    assert!(r.is_err());

    let git = spec_of(
        r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - push:
            repos: ["github.com/KvendraAI/*"]
            refs: ["refs/heads/main"]
            accept_destructive: true
        - tag:
            repos: ["github.com/KvendraAI/*"]
            tag_pattern: ["v[0-9]+\\.[0-9]+\\.[0-9]+"]
            accept_destructive: true
"#,
    );
    let push = env_args(
        "push",
        json!({ "remote": "git@github.com:KvendraAI/kvendra-cli.git", "ref": "refs/heads/main" }),
    );
    assert!(check(&git, "kvendra.git", "push", &push).is_ok());
    let tag = env_args(
        "tag",
        json!({ "remote": "https://github.com/KvendraAI/kvendra-cli.git", "name": "v0.7.0" }),
    );
    assert!(check(&git, "kvendra.git", "tag", &tag).is_ok());
    let bad_push = env_args(
        "push",
        json!({ "remote": "https://github.com/Evil/x.git", "ref": "refs/heads/main" }),
    );
    assert!(check(&git, "kvendra.git", "push", &bad_push).is_err());
}

// ═════════════════════════════════════════════════════════════════════════
// SA2 — ISSUE-KVD-CLI-9D5CF5 (HIGH)
// The LOCAL filesystem operand of a brokered transfer is unconstrained.
//
// RED at e41b652: the `buckets` block (enforcer.rs:208-232) only denies when
// `extract_bucket_from_s3_uri` returns Some, so a local path short-circuits
// the whole check; the DSL has no field for a local root (dsl.rs:143); the
// aws primitive only guards against leading dashes (aws.rs:122-143); and
// `s3_sync` is catalogued destructive ONLY with `--delete` (catalog.rs:111),
// so no approval prompt fires either.
// ═════════════════════════════════════════════════════════════════════════

const AWS_BUCKET_SCOPE: &str = r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.aws
      operations:
        - s3_sync:
            buckets: ["kvendra-com-prod"]
            accept_destructive: true
        - s3_cp:
            buckets: ["kvendra-com-prod"]
            accept_destructive: true
"#;

const GIT_CLONE_SCOPE: &str = r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - clone:
            repos: ["github.com/KvendraAI/*"]
"#;

/// Exfiltration direction: an arbitrary local tree is uploaded to an
/// allowlisted bucket. The bucket constraint is satisfied by `dst`; `src` is
/// never looked at.
#[test]
fn sa2_local_source_outside_any_declared_root_must_be_denied() {
    let s = spec_of(AWS_BUCKET_SCOPE);
    let args = env_args(
        "s3_sync",
        json!({ "src": "/etc", "dst": "s3://kvendra-com-prod/x" }),
    );
    let r = check(&s, "kvendra.aws", "s3_sync", &args);
    assert!(
        r.is_err(),
        "an s3_sync whose LOCAL source is outside every declared local root \
         must be DENIED (fail-closed: no `local_roots` declared at all here); \
         enforcer returned {r:?}"
    );
}

/// Overwrite direction: attacker-controlled bytes are written to an arbitrary
/// local path. Same blind spot, opposite arrow.
#[test]
fn sa2_local_destination_outside_any_declared_root_must_be_denied() {
    let s = spec_of(AWS_BUCKET_SCOPE);
    let args = env_args(
        "s3_cp",
        json!({ "src": "s3://kvendra-com-prod/payload", "dst": "/usr/local/bin/kvendra" }),
    );
    let r = check(&s, "kvendra.aws", "s3_cp", &args);
    assert!(
        r.is_err(),
        "an s3_cp whose LOCAL destination is outside every declared local root \
         must be DENIED; enforcer returned {r:?}"
    );
}

/// `git clone` writes a whole tree wherever `dst` points, under the owner's
/// credential. The `repos` constraint only ever looks at `url`.
#[test]
fn sa2_git_clone_destination_outside_any_declared_root_must_be_denied() {
    let s = spec_of(GIT_CLONE_SCOPE);
    let args = env_args(
        "clone",
        json!({
            "url": "https://github.com/KvendraAI/kvendra-cli",
            "dst": "/usr/local/lib/kvendra-payload"
        }),
    );
    let r = check(&s, "kvendra.git", "clone", &args);
    assert!(
        r.is_err(),
        "a git clone destination outside every declared local root must be \
         DENIED; enforcer returned {r:?}"
    );
}

/// Consent side of the same finding — without a prompt the owner never sees
/// the transfer at all. `s3_sync` must be destructive regardless of `--delete`
/// (it overwrites), and `git clone` must have a rule at all.
#[test]
fn sa2_s3_sync_must_be_destructive_without_the_delete_flag() {
    assert!(
        catalog::is_destructive("kvendra.aws", "s3_sync", &json!({})),
        "s3_sync writes to a destination whether or not `--delete` is set — it \
         must be unconditionally destructive so approval fires"
    );
}

#[test]
fn sa2_git_clone_must_be_destructive() {
    assert!(
        catalog::is_destructive("kvendra.git", "clone", &Value::Null),
        "git clone materialises an arbitrary tree on the local filesystem under \
         the owner's credential — it must be catalogued destructive \
         (PAT-KVD-CLI-86A922: treat every brokered subprocess as hostile)"
    );
}

/// GUARD (green before AND after) — the bucket constraint itself must keep
/// denying a foreign bucket; the new local-root rule must not shadow it.
#[test]
fn sa2_guard_foreign_bucket_is_still_denied_by_the_bucket_rule() {
    let s = spec_of(AWS_BUCKET_SCOPE);
    let args = env_args(
        "s3_sync",
        json!({ "src": "./build", "dst": "s3://attacker-bucket/x" }),
    );
    let err = check(&s, "kvendra.aws", "s3_sync", &args).unwrap_err();
    assert!(
        err.to_string().contains("attacker-bucket"),
        "the bucket rejection must still name the offending bucket, got: {err}"
    );
}

// GREEN-only (implementer): once the DSL grows `local_roots` (D2) add —
//   * roots `[<tmp>]` + `{src:"<tmp>/dist", dst:"s3://kvendra-com-prod/x"}` → Ok;
//   * roots `[<tmp>]` + `{src:"<tmp>/not-yet-built", …}` (leaf absent, parent
//     inside) → Ok;
//   * roots `[<tmp>]` + `<tmp>/../../etc` and `<tmp>-evil/x` → Err
//     (component-wise `Path::starts_with`, not a string prefix);
//   * `#[cfg(unix)]` symlink `<tmp>/link -> /etc` → Err (canonicalize);
//   * `S3://b/k` and `s3:///k` → Err (malformed remote, never treated local);
//   * git clone with `dst` ABSENT → Err (writes into the broker cwd);
//   * pypi.upload `{dist:"<tmp>/dist/pkg-1.0.tar.gz"}` → Ok, `{dist:"/etc"}` → Err;
//   * `validate_for_signing(spec_with_s3_sync_and_no_local_roots)` → Err naming
//     `local_roots`, while plain `validate(spec)` on the same YAML stays Ok
//     (the runtime validator must NOT brick whole profiles).
// All of them need the `local_roots` field and `validate_for_signing`, neither
// of which exists at e41b652 — the YAML would not even deserialize
// (`deny_unknown_fields`).
//
// GREEN-only block (landed with the remediation).

/// `<outer>/root` is the declared root; `<outer>/root-evil` is the
/// string-prefix trap sibling.
fn sa2_roots_fixture() -> (TempDir, String) {
    let outer = tempfile::tempdir().unwrap();
    let root = outer.path().join("root");
    std::fs::create_dir_all(root.join("dist")).unwrap();
    std::fs::create_dir_all(outer.path().join("root-evil")).unwrap();
    (outer, root.to_string_lossy().into_owned())
}

fn sa2_transfer_spec(root: &str) -> ProfileSpec {
    spec_of(&format!(
        r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.aws
      operations:
        - s3_sync:
            buckets: ["kvendra-com-prod"]
            local_roots: ["{root}"]
            accept_destructive: true
        - s3_cp:
            buckets: ["kvendra-com-prod"]
            local_roots: ["{root}"]
            accept_destructive: true
    - name: kvendra.git
      operations:
        - clone:
            repos: ["github.com/KvendraAI/*"]
            local_roots: ["{root}"]
            accept_destructive: true
    - name: kvendra.pypi
      operations:
        - upload:
            local_roots: ["{root}"]
            accept_destructive: true
"#
    ))
}

fn sa2_sync(s: &ProfileSpec, src: &str, dst: &str) -> kvendra::error::KvendraResult<()> {
    check(
        s,
        "kvendra.aws",
        "s3_sync",
        &env_args("s3_sync", json!({ "src": src, "dst": dst })),
    )
}

#[test]
fn sa2_green_operand_inside_a_root_passes() {
    let (_g, root) = sa2_roots_fixture();
    let s = sa2_transfer_spec(&root);
    let r = sa2_sync(&s, &format!("{root}/dist"), "s3://kvendra-com-prod/x");
    assert!(r.is_ok(), "in-root source must pass; got {r:?}");
    let r = sa2_sync(
        &s,
        &format!("{root}/not-yet-built"),
        "s3://kvendra-com-prod/x",
    );
    assert!(
        r.is_ok(),
        "absent leaf with an in-root parent must pass; got {r:?}"
    );
    let r = check(
        &s,
        "kvendra.aws",
        "s3_cp",
        &env_args(
            "s3_cp",
            json!({ "src": "s3://kvendra-com-prod/k", "dst": format!("{root}/dist/k") }),
        ),
    );
    assert!(
        r.is_ok(),
        "in-root download destination must pass; got {r:?}"
    );
}

#[test]
fn sa2_green_traversal_and_string_prefix_trap_are_denied() {
    let (_g, root) = sa2_roots_fixture();
    let s = sa2_transfer_spec(&root);
    for src in [
        format!("{root}/../../etc"),
        format!("{root}-evil/x"),
        format!("{root}-evil"),
    ] {
        let r = sa2_sync(&s, &src, "s3://kvendra-com-prod/x");
        assert!(r.is_err(), "{src} must be denied; got {r:?}");
    }
}

#[cfg(unix)]
#[test]
fn sa2_green_symlink_escape_is_denied() {
    let (_g, root) = sa2_roots_fixture();
    std::os::unix::fs::symlink("/etc", format!("{root}/link")).unwrap();
    std::os::unix::fs::symlink("/nonexistent-kvendra-target", format!("{root}/dangling")).unwrap();
    let s = sa2_transfer_spec(&root);
    let r = sa2_sync(&s, &format!("{root}/link"), "s3://kvendra-com-prod/x");
    assert!(
        r.is_err(),
        "symlink out of the root must be denied; got {r:?}"
    );
    let r = check(
        &s,
        "kvendra.aws",
        "s3_cp",
        &env_args(
            "s3_cp",
            json!({ "src": "s3://kvendra-com-prod/k", "dst": format!("{root}/dangling") }),
        ),
    );
    assert!(
        r.is_err(),
        "a dangling-symlink destination must be denied; got {r:?}"
    );
}

#[test]
fn sa2_green_malformed_remotes_are_never_treated_as_local() {
    let (_g, root) = sa2_roots_fixture();
    let s = sa2_transfer_spec(&root);
    for dst in ["S3://kvendra-com-prod/k", "s3:///k"] {
        let r = sa2_sync(&s, &format!("{root}/dist"), dst);
        assert!(r.is_err(), "{dst} must be denied; got {r:?}");
    }
}

#[test]
fn sa2_green_git_clone_without_dst_is_denied() {
    let (_g, root) = sa2_roots_fixture();
    let s = sa2_transfer_spec(&root);
    let url = "https://github.com/KvendraAI/kvendra-cli";
    let absent = env_args("clone", json!({ "url": url }));
    let err = check(&s, "kvendra.git", "clone", &absent).unwrap_err();
    assert!(err.to_string().contains("fail-closed"), "{err}");
    let ok = env_args(
        "clone",
        json!({ "url": url, "dst": format!("{root}/kvendra-cli") }),
    );
    let r = check(&s, "kvendra.git", "clone", &ok);
    assert!(r.is_ok(), "in-root clone destination must pass; got {r:?}");
}

#[test]
fn sa2_green_pypi_upload_dist_is_bounded() {
    let (_g, root) = sa2_roots_fixture();
    let s = sa2_transfer_spec(&root);
    let ok = env_args(
        "upload",
        json!({ "dist": format!("{root}/dist/pkg-1.0.tar.gz") }),
    );
    let r = check(&s, "kvendra.pypi", "upload", &ok);
    assert!(r.is_ok(), "in-root dist must pass; got {r:?}");
    let glob = env_args("upload", json!({ "dist": format!("{root}/dist/*") }));
    assert!(check(&s, "kvendra.pypi", "upload", &glob).is_ok());
    let bad = env_args("upload", json!({ "dist": "/etc" }));
    assert!(check(&s, "kvendra.pypi", "upload", &bad).is_err());
}

#[test]
fn sa2_green_signing_requires_local_roots_but_runtime_validate_does_not_brick() {
    let s = spec_of(AWS_BUCKET_SCOPE);
    let err = kvendra::allowlist::validate_for_signing(&s).unwrap_err();
    assert!(err.to_string().contains("local_roots"), "{err}");
    assert!(
        validate(&s).is_ok(),
        "the runtime validator must not brick the whole profile"
    );
    let (_g, root) = sa2_roots_fixture();
    assert!(kvendra::allowlist::validate_for_signing(&sa2_transfer_spec(&root)).is_ok());
}

// ═════════════════════════════════════════════════════════════════════════
// SA3 — ISSUE-KVD-CLI-705EF0 (MED)
// The `KVENDRA_APPROVAL_MODE` env var outranks the HMAC-signed policy.
//
// RED at e41b652: `resolve_mode` (src/approval/policy.rs:13-20) is
// `env.or(profile).unwrap_or(global)` — the ONLY unverified input wins over
// two HMAC-protected ones. Pure function only: no env mutation (this binary
// has no access to `crate::test_env_lock()`), and no dispatch with a
// destructive op (that would reach the approval backend).
// ═════════════════════════════════════════════════════════════════════════

/// The attack in one line: a same-uid attacker (or a poisoned MCP launcher)
/// exports `KVENDRA_APPROVAL_MODE=silent` and every prompt the owner signed
/// into `config.toml` disappears.
#[test]
fn sa3_env_must_not_weaken_the_signed_approval_mode() {
    // implementer (D5): `resolve_mode` is REMOVED in favour of
    // `resolve_mode_ratcheted(env, profile, global, allow_env_downgrade)`
    // returning an `ApprovalOutcome`. Re-author the CALL, never the assertion:
    // a looser env value must not lower the signed mode.
    let resolved = policy::resolve_mode_ratcheted(
        Some(ApprovalMode::Silent),
        None,
        ApprovalMode::AskDestructive,
        false,
    )
    .mode;
    assert_eq!(
        resolved,
        ApprovalMode::AskDestructive,
        "an unsigned env var must never LOWER the HMAC-signed approval mode \
         (env is a one-way ratchet: Silent < AskDestructive < Ask)"
    );
}

/// Same defect one level down: the signed PER-PROFILE override is discarded
/// too, not just the global default.
#[test]
fn sa3_env_must_not_weaken_the_signed_profile_override() {
    let resolved = policy::resolve_mode_ratcheted(
        Some(ApprovalMode::Silent),
        Some(ApprovalMode::Ask),
        ApprovalMode::AskDestructive,
        false,
    )
    .mode;
    assert_eq!(
        resolved,
        ApprovalMode::Ask,
        "a looser env var must not override the signed per-profile `approval.mode`"
    );
}

/// GUARD (green before AND after) — the ratchet is ONE-WAY: tightening from
/// the environment stays legal, so CI/automation can still harden.
#[test]
fn sa3_guard_env_may_still_tighten_the_signed_mode() {
    let resolved = policy::resolve_mode_ratcheted(
        Some(ApprovalMode::Ask),
        None,
        ApprovalMode::AskDestructive,
        false,
    )
    .mode;
    assert_eq!(
        resolved,
        ApprovalMode::Ask,
        "a STRICTER env value must still win — the ratchet only blocks downgrades"
    );
}

/// GUARD — the strictness order the ratchet is built on must agree with the
/// behaviour `should_prompt` already implements (Silent < AskDestructive < Ask).
#[test]
fn sa3_guard_strictness_order_agrees_with_should_prompt() {
    for destructive in [false, true] {
        let silent = policy::should_prompt(ApprovalMode::Silent, destructive);
        let ask_destructive = policy::should_prompt(ApprovalMode::AskDestructive, destructive);
        let ask = policy::should_prompt(ApprovalMode::Ask, destructive);
        assert!(
            !silent || ask_destructive,
            "Silent must never prompt more than AskDestructive (destructive={destructive})"
        );
        assert!(
            !ask_destructive || ask,
            "AskDestructive must never prompt more than Ask (destructive={destructive})"
        );
    }
}

// GREEN-only (implementer) — added once `ApprovalOutcome` landed. The e2e
// row assertion (env=silent, signed=AskDestructive, NON-destructive op) lives
// in-crate as `sa3_env_silent_is_ignored_and_audit_flagged_e2e`
// (src/mcp/server.rs) because it needs `crate::test_env_lock()`.

#[test]
fn sa3_green_global_downgrade_outcome_is_ignored_and_flagged() {
    use policy::{ApprovalSource, EnvOverride};
    let o = policy::resolve_mode_ratcheted(
        Some(ApprovalMode::Silent),
        None,
        ApprovalMode::AskDestructive,
        false,
    );
    assert_eq!(
        (o.mode, o.source, o.env_override),
        (
            ApprovalMode::AskDestructive,
            ApprovalSource::Signed,
            Some(EnvOverride::DowngradeIgnored)
        )
    );
    let flags = o.audit_flags();
    for f in [
        policy::FLAG_APPROVAL_ENV_IGNORED,
        policy::FLAG_APPROVAL_MODE_ASK_DESTRUCTIVE,
        policy::FLAG_APPROVAL_SRC_SIGNED,
    ] {
        assert!(flags.contains(&f), "missing {f} in {flags:?}");
    }
    assert_eq!(policy::FLAG_APPROVAL_ENV_IGNORED, "approval_env_ignored");
}

/// Pins the audit-sketch defect: the signed baseline is
/// `profile.unwrap_or(global)`, NOT `env.or(profile)` vs `global`.
#[test]
fn sa3_green_profile_downgrade_outcome_keeps_the_signed_profile() {
    use policy::{ApprovalSource, EnvOverride};
    let o = policy::resolve_mode_ratcheted(
        Some(ApprovalMode::Silent),
        Some(ApprovalMode::Ask),
        ApprovalMode::AskDestructive,
        false,
    );
    assert_eq!(
        (o.mode, o.source, o.env_override),
        (
            ApprovalMode::Ask,
            ApprovalSource::Profile,
            Some(EnvOverride::DowngradeIgnored)
        )
    );
}

#[test]
fn sa3_green_signed_opt_in_lets_env_downgrade_and_flags_it() {
    use policy::{ApprovalSource, EnvOverride};
    let o = policy::resolve_mode_ratcheted(
        Some(ApprovalMode::Silent),
        None,
        ApprovalMode::AskDestructive,
        true,
    );
    assert_eq!(
        (o.mode, o.source, o.env_override),
        (
            ApprovalMode::Silent,
            ApprovalSource::Env,
            Some(EnvOverride::DowngradeApplied)
        )
    );
    assert!(
        o.audit_flags()
            .contains(&policy::FLAG_APPROVAL_MODE_OVERRIDDEN)
    );
}

#[test]
fn sa3_green_env_downgrade_opt_in_is_off_by_default() {
    assert!(!Config::default().approval.allow_env_downgrade);
}

// ═════════════════════════════════════════════════════════════════════════
// SA4 — ISSUE-KVD-CLI-F4ED93 (MED)
// Audit-chain HMAC input is non-injective and the layout version is not MACed.
//
// RED at e41b652: every builder pipe-joins its fields with no escaping or
// length prefix (src/audit/hmac.rs:62 v1, :102 v2, :146 v3) and each layout is
// a pure SUFFIX extension of the previous one; the verifier picks the builder
// from the row's OWN `hmac_version` column (src/audit/reader.rs:92-138), which
// is never authenticated. A v3 row can therefore be re-labelled v2 with its
// diagnostics folded into `remote_audit_id` and `verify_chain` still says OK.
// ═════════════════════════════════════════════════════════════════════════

/// The collision, isolated. Two DIFFERENT rows (one carrying diagnostics under
/// v3, one carrying a pipe-laden `remote_audit_id` under v2) produce the SAME
/// tag — which is exactly what makes the downgrade below undetectable.
#[test]
fn sa4_v3_and_v2_must_not_collide_on_folded_diagnostics() {
    let v3 = compute_hmac_v3(
        b"k",
        7,
        1,
        "prod",
        "kvendra.shell",
        "exec",
        "de",
        "error",
        "warn",
        "",
        "ab",
        None,
        Some("ALLOWLIST_VIOLATION"),
        Some("ref not allowed"),
    );
    let v2 = compute_hmac_v2(
        b"k",
        7,
        1,
        "prod",
        "kvendra.shell",
        "exec",
        "de",
        "error",
        "warn",
        "",
        "ab",
        Some("|ALLOWLIST_VIOLATION|ref not allowed"),
    );
    assert_ne!(
        v3, v2,
        "the MAC must commit to the TUPLE, not to a flat pipe-joined byte \
         string: a v3 row with (remote=NULL, code, message) and a v2 row whose \
         remote_audit_id is '|code|message' are different rows and must not \
         share a tag (layout version must be domain-separated inside the MAC)"
    );
}

/// The same collision reached through the REAL writer: drive a call the
/// enforcer denies so the dispatcher persists a genuine `status=error` row
/// with `error_code` + `error_message`, then apply the downgrade with the
/// row's `hmac_hex` UNTOUCHED.
#[tokio::test]
async fn sa4_v3_to_v2_downgrade_of_a_real_error_row_must_break_verification() {
    let (_dir, ctx) = bootstrap("shell.profile", SHELL_ECHO_ONLY, DetectionSeverity::Warn).await;
    // `id` is not in `binaries: ["echo"]` → AllowlistViolation pre-dispatch,
    // so nothing is ever spawned.
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
    assert!(
        resp.error.is_some(),
        "the denied call must produce an error"
    );
    drain(&ctx).await;

    let key = ctx.vault.audit_hmac_key().unwrap();
    let db = ctx.vault.audit_db_path();

    // Control: the untouched chain verifies.
    {
        let conn = kvendra::audit::reader::open_readonly(&db).unwrap();
        assert!(
            kvendra::audit::reader::verify_chain(&conn, &key).is_ok(),
            "precondition: the freshly written chain must verify"
        );
    }

    // The forgery: relabel the layout and fold the two diagnostic columns into
    // `remote_audit_id`. `hmac_hex` is NOT recomputed — it does not need to be.
    let target_id: i64 = {
        let conn = rusqlite::Connection::open(&db).unwrap();
        let id = conn
            .query_row(
                "SELECT id FROM audit_events WHERE status = 'error' AND error_code IS NOT NULL \
                 ORDER BY id ASC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .expect("the denied call must have written an error row with a code");
        conn.execute(
            "UPDATE audit_events SET hmac_version = 2, \
             remote_audit_id = COALESCE(remote_audit_id,'') || '|' || COALESCE(error_code,'') \
             || '|' || COALESCE(error_message,''), \
             error_code = NULL, error_message = NULL WHERE id = ?1",
            [id],
        )
        .unwrap();
        id
    };

    let conn = kvendra::audit::reader::open_readonly(&db).unwrap();
    let verdict = kvendra::audit::reader::verify_chain(&conn, &key);
    assert!(
        verdict.is_err(),
        "row #{target_id} was silently downgraded v3→v2 with its diagnostics \
         folded into remote_audit_id and its hmac_hex untouched — \
         `audit verify` MUST report the chain as broken, got {verdict:?}"
    );
}

/// GUARD (green before AND after) — the classic tamper must keep being caught,
/// so the v4 layout cannot be "detects nothing, fails everything".
#[tokio::test]
async fn sa4_guard_status_flip_is_still_detected() {
    let (_dir, ctx) = bootstrap("shell.profile", SHELL_ECHO_ONLY, DetectionSeverity::Warn).await;
    let _ = dispatch(
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
    drain(&ctx).await;

    let key = ctx.vault.audit_hmac_key().unwrap();
    let db = ctx.vault.audit_db_path();
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            "UPDATE audit_events SET status = 'ok' WHERE status = 'error'",
            [],
        )
        .unwrap();
    }
    let conn = kvendra::audit::reader::open_readonly(&db).unwrap();
    assert!(
        kvendra::audit::reader::verify_chain(&conn, &key).is_err(),
        "flipping status error→ok must always break the chain"
    );
}

// GREEN-only (implementer): with the v4 layout in place add —
//   * `compute_hmac_v4` byte vectors: None vs Some("") differ; a `|` planted in
//     `primitive` cannot alias `action`; the version byte is bound;
//   * frozen GOLDEN HEX vectors for v1/v2/v3 so a refactor cannot silently
//     change how the owner's real rows verify;
//   * `schema_version_and_hmac_layout_are_decoupled` (migrations::CURRENT_VERSION
//     stays 3, hmac::CURRENT_HMAC_LAYOUT becomes 4);
//   * interior version downgrade in a legacy prefix → detected by the monotonic
//     rule; `kvendra audit commit-layout` pins legacy rows;
//   * `tools/call` with `name = "kvendra.shell|x"` → refused with the
//     `invalid_tool_field_denied` flag (dispatcher-level charset validation);
//   * `kvendra audit --verify` exits NON-ZERO on a layout violation
//     (cli/audit.rs:127 currently falls through to `Ok(())`).
// Canary that must keep passing UNMODIFIED:
//   tests/integration_audit_error_diagnostics.rs::hmac_chain_verifies_with_legacy_and_v3_error_rows.

/// GREEN-only — v4 byte vectors through the public API: `None` vs `Some("")`
/// differ, a `|` planted in `primitive` cannot alias `action`, and the layout
/// is bound (the same tuple never shares a tag with its legacy v3 form).
#[test]
fn sa4_green_v4_byte_vectors() {
    use kvendra::audit::hmac::compute_hmac_v4;
    let v4 = |primitive: &str, action: &str, remote: Option<&str>| {
        compute_hmac_v4(
            b"k", 7, 1, "prod", primitive, action, "de", "error", "warn", "", "ab", remote, None,
            None,
        )
    };
    assert_ne!(
        v4("kvendra.shell", "exec", None),
        v4("kvendra.shell", "exec", Some(""))
    );
    assert_ne!(
        v4("kvendra.shell|exec", "", None),
        v4("kvendra.shell", "exec", None)
    );
    assert_ne!(
        v4("kvendra.shell|", "exec", None),
        v4("kvendra.shell", "|exec", None)
    );
    let legacy = compute_hmac_v3(
        b"k",
        7,
        1,
        "prod",
        "kvendra.shell",
        "exec",
        "de",
        "error",
        "warn",
        "",
        "ab",
        None,
        None,
        None,
    );
    assert_ne!(v4("kvendra.shell", "exec", None), legacy);
}

/// GREEN-only — FROZEN golden hex vectors for the legacy layouts, captured
/// from the v0.6.4 builders. They are how the owner's real rows verify.
#[test]
fn sa4_green_legacy_layouts_are_frozen() {
    use kvendra::audit::hmac::compute_hmac_v1;
    let k = b"kvendra-golden-key";
    let (p, pr, a, h, s, sv, f, prev) = (
        "github.kvendraai.cli-write",
        "kvendra.git",
        "push",
        "deadbeef",
        "ok",
        "info",
        "approval_src_signed",
        "00ff",
    );
    let t = 1_700_000_000_123;
    assert_eq!(
        compute_hmac_v1(k, 42, t, p, pr, a, h, s, sv, f, prev),
        "6c608df645f6b1b02387745456882d1a216062432e22a189a4b8d81de3d951fc"
    );
    assert_eq!(
        compute_hmac_v2(k, 42, t, p, pr, a, h, s, sv, f, prev, None),
        "f907d01bb67f2d7b655936c451639b6043a095e3be3f9de973c6b488ca88759f"
    );
    assert_eq!(
        compute_hmac_v2(
            k,
            42,
            t,
            p,
            pr,
            a,
            h,
            s,
            sv,
            f,
            prev,
            Some("01H1234567890ABCDEFGHJKMNP")
        ),
        "2ba363387c71f7a487c1618aa8967b451271b2b567011a67ef983274eea531b4"
    );
    assert_eq!(
        compute_hmac_v3(k, 42, t, p, pr, a, h, s, sv, f, prev, None, None, None),
        "e6cc8f540cfe8e3b054f4c5ea79701065f8e24704cfdaf0b2fde00fb4912c2ff"
    );
    assert_eq!(
        compute_hmac_v3(
            k,
            43,
            1_700_000_000_456,
            "shell.profile",
            "kvendra.shell",
            "exec",
            "deadbeef",
            "error",
            "warn",
            "allowlist_denied",
            "00ff",
            None,
            Some("ALLOWLIST_VIOLATION"),
            Some("binary 'id' not allowed | see allowlist"),
        ),
        "e8d9a78fe668aed6fd2bf349d1373c3dd3b6b11ab2b08441c29ed32fb851aceb"
    );
}

#[test]
fn sa4_green_schema_version_and_hmac_layout_are_decoupled() {
    assert_eq!(kvendra::audit::migrations::CURRENT_VERSION, 3);
    assert_eq!(kvendra::audit::hmac::CURRENT_HMAC_LAYOUT, 4);
}

/// Insert one row signed with the FROZEN legacy builder of `layout`, exactly
/// as a v0.6.4 binary would have written it. Returns its tag.
#[allow(clippy::too_many_arguments)]
fn insert_legacy_row(
    conn: &rusqlite::Connection,
    key: &[u8],
    layout: i64,
    id: i64,
    primitive: &str,
    status: &str,
    remote: Option<&str>,
    error_code: Option<&str>,
    error_message: Option<&str>,
    prev: &str,
) -> String {
    let (ts, profile, action, args, severity, flags) =
        (1_700_000_000_000 + id, "p", "exec", "ab", "info", "");
    let tag = match layout {
        1 => kvendra::audit::hmac::compute_hmac_v1(
            key, id, ts, profile, primitive, action, args, status, severity, flags, prev,
        ),
        2 => compute_hmac_v2(
            key, id, ts, profile, primitive, action, args, status, severity, flags, prev, remote,
        ),
        3 => compute_hmac_v3(
            key,
            id,
            ts,
            profile,
            primitive,
            action,
            args,
            status,
            severity,
            flags,
            prev,
            remote,
            error_code,
            error_message,
        ),
        other => panic!("not a legacy layout: {other}"),
    };
    conn.execute(
        "INSERT INTO audit_events (id, ts_unix_ms, profile_id, primitive, action, args_hash_hex,
         status, severity, flags, prev_hmac_hex, hmac_hex, remote_audit_id, hmac_version,
         error_code, error_message)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        rusqlite::params![
            id,
            ts,
            profile,
            primitive,
            action,
            args,
            status,
            severity,
            flags,
            prev,
            tag,
            remote,
            layout,
            error_code,
            error_message
        ],
    )
    .unwrap();
    tag
}

/// A v0.6.4-shaped chain: v1 → v2 (with a remote id) → v3 error row (whose
/// free-form message carries a `|`) → v3 ok row. Returns the last tag.
fn write_0_6_4_chain(ctx: &Arc<ServerContext>) -> String {
    let key = ctx.vault.audit_hmac_key().unwrap();
    let conn = rusqlite::Connection::open(ctx.vault.audit_db_path()).unwrap();
    let h1 = insert_legacy_row(
        &conn,
        &key,
        1,
        1,
        "kvendra.system",
        "ok",
        None,
        None,
        None,
        "",
    );
    let h2 = insert_legacy_row(
        &conn,
        &key,
        2,
        2,
        "kvendra.git",
        "ok",
        Some("01H1234567890ABCDEFGHJKMNP"),
        None,
        None,
        &h1,
    );
    let h3 = insert_legacy_row(
        &conn,
        &key,
        3,
        3,
        "kvendra.shell",
        "error",
        None,
        Some("ALLOWLIST_VIOLATION"),
        Some("binary 'id' not allowed | see allowlist"),
        &h2,
    );
    insert_legacy_row(
        &conn,
        &key,
        3,
        4,
        "kvendra.shell",
        "ok",
        None,
        None,
        None,
        &h3,
    )
}

async fn deny_one_shell_call(ctx: &Arc<ServerContext>) {
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
    assert!(resp.error.is_some());
}

fn verify(ctx: &Arc<ServerContext>) -> kvendra::error::KvendraResult<()> {
    let key = ctx.vault.audit_hmac_key().unwrap();
    let conn = kvendra::audit::reader::open_readonly(&ctx.vault.audit_db_path()).unwrap();
    kvendra::audit::reader::verify_chain(&conn, &key)
}

/// GREEN-only — BACKWARD COMPAT: a chain written by v0.6.4 (v1/v2/v3 rows,
/// legacy MACs untouched) keeps verifying after the upgrade, and the new
/// writer appends v4 rows onto it.
#[tokio::test]
async fn sa4_green_chain_written_by_0_6_4_still_verifies_after_upgrade() {
    let (_dir, ctx) = bootstrap("shell.profile", SHELL_ECHO_ONLY, DetectionSeverity::Warn).await;
    write_0_6_4_chain(&ctx);
    assert!(
        verify(&ctx).is_ok(),
        "the untouched v0.6.4 chain must verify"
    );

    deny_one_shell_call(&ctx).await;
    drain(&ctx).await;
    let conn = rusqlite::Connection::open(ctx.vault.audit_db_path()).unwrap();
    let versions: Vec<i64> = conn
        .prepare("SELECT hmac_version FROM audit_events ORDER BY id ASC")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(versions, vec![1, 2, 3, 3, 4]);
    let r = verify(&ctx);
    assert!(
        r.is_ok(),
        "legacy prefix + new v4 row must verify, got {r:?}"
    );
}

/// GREEN-only — interior downgrade INSIDE the legacy prefix. The first v3 row
/// is the case a pure monotonic rule cannot see (v2,v2,[v3→v2],v3): it is
/// caught because the fold needs a `|` in `remote_audit_id`, which makes the
/// legacy encoding non-canonical, and the verifier refuses it.
#[tokio::test]
async fn sa4_green_interior_legacy_downgrade_is_detected() {
    for target in [3_i64, 4] {
        let (_dir, ctx) =
            bootstrap("shell.profile", SHELL_ECHO_ONLY, DetectionSeverity::Warn).await;
        write_0_6_4_chain(&ctx);
        {
            let conn = rusqlite::Connection::open(ctx.vault.audit_db_path()).unwrap();
            conn.execute(
                "UPDATE audit_events SET hmac_version = 2, \
                 remote_audit_id = COALESCE(remote_audit_id,'') || '|' || COALESCE(error_code,'') \
                 || '|' || COALESCE(error_message,''), \
                 error_code = NULL, error_message = NULL WHERE id = ?1",
                [target],
            )
            .unwrap();
        }
        let r = verify(&ctx);
        assert!(
            matches!(
                r,
                Err(kvendra::error::KvendraError::AuditLayoutViolation { row, .. }) if row == target
            ),
            "legacy row #{target} downgraded v3→v2 must be a layout violation, got {r:?}"
        );
    }
}

/// GREEN-only — once a v4 row exists, a legacy row after it is refused even
/// when its legacy MAC is genuine (post-fix writers never emit legacy rows).
#[tokio::test]
async fn sa4_green_legacy_row_after_v4_is_rejected() {
    let (_dir, ctx) = bootstrap("shell.profile", SHELL_ECHO_ONLY, DetectionSeverity::Warn).await;
    write_0_6_4_chain(&ctx);
    deny_one_shell_call(&ctx).await;
    drain(&ctx).await;
    let key = ctx.vault.audit_hmac_key().unwrap();
    let conn = rusqlite::Connection::open(ctx.vault.audit_db_path()).unwrap();
    let last: String = conn
        .query_row("SELECT hmac_hex FROM audit_events WHERE id = 5", [], |r| {
            r.get(0)
        })
        .unwrap();
    insert_legacy_row(
        &conn,
        &key,
        3,
        6,
        "kvendra.shell",
        "ok",
        None,
        None,
        None,
        &last,
    );
    let r = verify(&ctx);
    assert!(
        matches!(
            r,
            Err(kvendra::error::KvendraError::AuditLayoutViolation { row: 6, .. })
        ),
        "a legacy row after a v4 row must be refused, got {r:?}"
    );
}

/// GREEN-only — an unknown layout is an explicit error, never absorbed by a
/// `>= 3` fall-through.
#[tokio::test]
async fn sa4_green_unknown_layout_is_rejected() {
    let (_dir, ctx) = bootstrap("shell.profile", SHELL_ECHO_ONLY, DetectionSeverity::Warn).await;
    deny_one_shell_call(&ctx).await;
    drain(&ctx).await;
    {
        let conn = rusqlite::Connection::open(ctx.vault.audit_db_path()).unwrap();
        conn.execute("UPDATE audit_events SET hmac_version = 5", [])
            .unwrap();
    }
    let r = verify(&ctx);
    assert!(
        matches!(
            r,
            Err(kvendra::error::KvendraError::AuditLayoutViolation { .. })
        ),
        "hmac_version 5 must be refused, got {r:?}"
    );
}

/// GREEN-only — a `|` in the tool name or the operation is refused by the
/// dispatcher with `invalid_tool_field_denied`.
#[tokio::test]
async fn sa4_green_pipe_in_tool_name_or_operation_is_refused() {
    for (name, op) in [("kvendra.shell|x", "exec"), ("kvendra.shell", "exec|x")] {
        let (_dir, ctx) =
            bootstrap("shell.profile", SHELL_ECHO_ONLY, DetectionSeverity::Warn).await;
        let resp = dispatch(
            call(
                name,
                json!({
                    "profile_id": "shell.profile",
                    "operation": op,
                    "args": { "binary": "echo", "argv": ["hi"] }
                }),
            ),
            ctx.clone(),
        )
        .await;
        assert!(resp.error.is_some(), "{name}/{op} must be refused");
        let rows = audit_rows(&ctx).await;
        assert!(
            rows.iter().any(|(_, flags, status)| status == "error"
                && flags.split(',').any(|f| f == "invalid_tool_field_denied")),
            "{name}/{op}: expected an error row flagged invalid_tool_field_denied, got {rows:?}"
        );
        assert!(verify(&ctx).is_ok(), "the refusal row itself must verify");
    }
}

/// Iter2 (log/terminal injection) — the refusal row for a hostile tool name
/// stores an escaped, length-capped form: no control characters, no `|`,
/// still flagged `invalid_tool_field_denied`, still verifying.
#[tokio::test]
async fn iter2_hostile_tool_name_is_stored_escaped_and_capped() {
    let hostile = format!("kvendra.shell\x1b[2J\r\nFAKE|row{}", "\x07".repeat(300));
    let (_dir, ctx) = bootstrap("shell.profile", SHELL_ECHO_ONLY, DetectionSeverity::Warn).await;
    let resp = dispatch(
        call(
            &hostile,
            json!({
                "profile_id": "shell.profile",
                "operation": "exec",
                "args": { "binary": "echo", "argv": ["hi"] }
            }),
        ),
        ctx.clone(),
    )
    .await;
    assert!(resp.error.is_some(), "hostile tool name must be refused");
    let rows = audit_rows(&ctx).await;
    let (primitive, _, _) = rows
        .iter()
        .find(|(_, flags, status)| {
            status == "error" && flags.split(',').any(|f| f == "invalid_tool_field_denied")
        })
        .unwrap_or_else(|| panic!("no invalid_tool_field_denied row: {rows:?}"));
    assert!(
        primitive
            .chars()
            .all(|c| c.is_ascii() && !c.is_ascii_control() && c != '|'),
        "stored tool name carries raw hostile bytes: {primitive:?}"
    );
    assert!(primitive.len() <= 131, "not capped: {}", primitive.len());
    assert!(primitive.starts_with("kvendra.shell\\u{1b}"), "{primitive}");
    assert!(verify(&ctx).is_ok(), "the refusal row itself must verify");
}

/// GREEN-only — `kvendra audit --verify` exits NON-ZERO on a layout
/// violation (it used to print "BROKEN" and fall through to `Ok(())`). The
/// child gets the temp `KVENDRA_HOME`; this process's env is untouched.
#[tokio::test]
async fn sa4_green_cli_audit_verify_exits_nonzero_on_layout_violation() {
    use std::io::Write;
    let (dir, ctx) = bootstrap("shell.profile", SHELL_ECHO_ONLY, DetectionSeverity::Warn).await;
    deny_one_shell_call(&ctx).await;
    drain(&ctx).await;
    {
        let conn = rusqlite::Connection::open(ctx.vault.audit_db_path()).unwrap();
        conn.execute("UPDATE audit_events SET hmac_version = 5", [])
            .unwrap();
    }
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_kvendra"))
        .args(["audit", "--verify", "--password-stdin"])
        .env("KVENDRA_HOME", dir.path())
        .env_remove("KVENDRA_PASSWORD")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"hunter2-run1-audit\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !out.status.success(),
        "audit --verify must exit non-zero on a layout violation; stdout: {stdout}"
    );
    assert!(stdout.contains("BROKEN"), "stdout: {stdout}");
}

// ─── SA4-F3 — `kvendra audit commit-layout` pins legacy rows ──────────────
//
// v1/v2 rows keep columns OUTSIDE their frozen MAC (v1: remote_audit_id +
// error_code/error_message; v2: the diagnostics) and every legacy layout
// canonicalizes NULL to ''. The commitment row (v4, appended — nothing is
// rewritten) binds a digest over every column of every legacy row.

fn commit_layout(
    ctx: &Arc<ServerContext>,
) -> kvendra::error::KvendraResult<kvendra::audit::layout_commit::CommitOutcome> {
    let key = ctx.vault.audit_hmac_key().unwrap();
    let conn = kvendra::audit::reader::open_readonly(&ctx.vault.audit_db_path()).unwrap();
    kvendra::audit::layout_commit::commit_legacy_layout(&conn, &key, 1_800_000_000_000)
}

fn chain_report(
    ctx: &Arc<ServerContext>,
) -> kvendra::error::KvendraResult<kvendra::audit::reader::ChainReport> {
    let key = ctx.vault.audit_hmac_key().unwrap();
    let conn = kvendra::audit::reader::open_readonly(&ctx.vault.audit_db_path()).unwrap();
    kvendra::audit::reader::verify_chain_report(&conn, &key)
}

fn tamper(ctx: &Arc<ServerContext>, sql: &str) {
    let conn = rusqlite::Connection::open(ctx.vault.audit_db_path()).unwrap();
    conn.execute(sql, []).unwrap();
}

/// The unbound-column forgeries of the validator finding (SA4-F3).
const SA4_LEGACY_UNBOUND_EDITS: &[&str] = &[
    // v1 row #1: diagnostics + remote id are outside the v1 MAC.
    "UPDATE audit_events SET error_code = 'ALLOWLIST_VIOLATION' WHERE id = 1",
    "UPDATE audit_events SET error_message = 'forged reason' WHERE id = 1",
    "UPDATE audit_events SET remote_audit_id = '01HFORGED' WHERE id = 1",
    // v2 row #2: diagnostics are outside the v2 MAC.
    "UPDATE audit_events SET error_code = 'ALLOWLIST_VIOLATION' WHERE id = 2",
    // v3 row #4: NULL↔'' is canonicalized away by every legacy MAC.
    "UPDATE audit_events SET remote_audit_id = '' WHERE id = 4",
    "UPDATE audit_events SET error_code = '' WHERE id = 4",
];

/// GREEN-only — once committed, forging diagnostics into a v1/v2 row (or a
/// NULL↔'' edit on any legacy row) is a layout violation at the commitment.
#[tokio::test]
async fn sa4_green_commit_layout_detects_forged_legacy_diagnostics() {
    for sql in SA4_LEGACY_UNBOUND_EDITS {
        let (_dir, ctx) =
            bootstrap("shell.profile", SHELL_ECHO_ONLY, DetectionSeverity::Warn).await;
        drain(&ctx).await;
        write_0_6_4_chain(&ctx);
        assert!(matches!(
            commit_layout(&ctx).unwrap(),
            kvendra::audit::layout_commit::CommitOutcome::Committed {
                row: 5,
                legacy_rows: 4,
                ..
            }
        ));
        assert!(verify(&ctx).is_ok(), "the fresh commitment must verify");
        tamper(&ctx, sql);
        let r = verify(&ctx);
        assert!(
            matches!(
                r,
                Err(kvendra::error::KvendraError::AuditLayoutViolation { row: 5, .. })
            ),
            "{sql}: a committed legacy row must not be forgeable, got {r:?}"
        );
    }
}

/// GREEN-only — without a commitment, legacy rows verify exactly as before
/// (the documented residual gap) and are reported as uncommitted.
#[tokio::test]
async fn sa4_green_uncommitted_legacy_rows_verify_as_before() {
    for sql in SA4_LEGACY_UNBOUND_EDITS {
        let (_dir, ctx) =
            bootstrap("shell.profile", SHELL_ECHO_ONLY, DetectionSeverity::Warn).await;
        drain(&ctx).await;
        write_0_6_4_chain(&ctx);
        tamper(&ctx, sql);
        let rep = chain_report(&ctx).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
        assert_eq!(
            (
                rep.legacy_rows,
                rep.committed_legacy_rows(),
                rep.uncommitted_legacy_rows()
            ),
            (4, 0, 4)
        );
    }
}

/// GREEN-only — commit-layout is idempotent, a no-op on an empty or v4-only
/// log, and new v4 rows keep appending and verifying after the commitment.
#[tokio::test]
async fn sa4_green_commit_layout_is_idempotent() {
    use kvendra::audit::layout_commit::CommitOutcome;
    let (_dir, ctx) = bootstrap("shell.profile", SHELL_ECHO_ONLY, DetectionSeverity::Warn).await;
    drain(&ctx).await;
    assert_eq!(commit_layout(&ctx).unwrap(), CommitOutcome::NothingToCommit);

    let (_dir2, ctx2) = bootstrap("shell.profile", SHELL_ECHO_ONLY, DetectionSeverity::Warn).await;
    deny_one_shell_call(&ctx2).await;
    drain(&ctx2).await;
    assert_eq!(
        commit_layout(&ctx2).unwrap(),
        CommitOutcome::NothingToCommit
    );
    assert!(verify(&ctx2).is_ok());

    let (_dir3, ctx3) = bootstrap("shell.profile", SHELL_ECHO_ONLY, DetectionSeverity::Warn).await;
    drain(&ctx3).await;
    write_0_6_4_chain(&ctx3);
    assert!(matches!(
        commit_layout(&ctx3).unwrap(),
        CommitOutcome::Committed { row: 5, .. }
    ));
    assert_eq!(
        commit_layout(&ctx3).unwrap(),
        CommitOutcome::AlreadyCommitted {
            row: 5,
            legacy_rows: 4
        }
    );
    let rep = chain_report(&ctx3).unwrap();
    assert_eq!(
        (rep.rows, rep.commitment_rows, rep.committed_legacy_rows()),
        (5, 1, 4)
    );
}

fn run_cli(home: &std::path::Path, args: &[&str], password: &str) -> std::process::Output {
    use std::io::Write;
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_kvendra"))
        .args(args)
        .env("KVENDRA_HOME", home)
        .env_remove("KVENDRA_PASSWORD")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{password}\n").as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// GREEN-only — CLI exit codes of `kvendra audit commit-layout` (temp
/// `KVENDRA_HOME` only).
#[tokio::test]
async fn sa4_green_cli_commit_layout_exit_codes() {
    const PW: &str = "hunter2-run1-audit";
    let (dir, ctx) = bootstrap("shell.profile", SHELL_ECHO_ONLY, DetectionSeverity::Warn).await;
    drain(&ctx).await;
    write_0_6_4_chain(&ctx);
    let home = dir.path();
    let commit = ["audit", "commit-layout", "--password-stdin"];
    let verify_args = ["audit", "--verify", "--password-stdin"];

    let out = run_cli(home, &verify_args, PW);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("0 committed, 4 uncommitted"), "{stdout}");

    let out = run_cli(home, &commit, "wrong-password");
    assert!(!out.status.success(), "a wrong password must fail");
    assert_eq!(chain_report(&ctx).unwrap().commitment_rows, 0);

    let out = run_cli(home, &commit, PW);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(
        stdout.contains("Committed 4 legacy-layout rows"),
        "{stdout}"
    );

    let out = run_cli(home, &commit, PW);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("Already committed"), "{stdout}");

    let out = run_cli(home, &verify_args, PW);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("4 committed, 0 uncommitted"), "{stdout}");

    tamper(
        &ctx,
        "UPDATE audit_events SET error_code = 'ALLOWLIST_VIOLATION' WHERE id = 1",
    );
    let out = run_cli(home, &verify_args, PW);
    assert!(
        !out.status.success(),
        "verify must exit non-zero on a forged committed row"
    );
    let out = run_cli(home, &commit, PW);
    assert!(
        !out.status.success(),
        "commit-layout must refuse (not re-commit) over a forged committed row"
    );
    assert_eq!(
        rusqlite::Connection::open(ctx.vault.audit_db_path())
            .unwrap()
            .query_row("SELECT COUNT(*) FROM audit_events", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        5,
        "a refused commit appends nothing"
    );

    let empty = tempfile::tempdir().unwrap();
    let out = run_cli(empty.path(), &commit, PW);
    assert!(out.status.success(), "no audit log is a no-op");
}

// ═════════════════════════════════════════════════════════════════════════
// SA5 — ISSUE-KVD-CLI-3319F0 (MED)
// Broker-supplied `template_id` is joined into a filesystem path unvalidated.
//
// RED at e41b652: `Template.template_id` is decoded as a free `String`
// (src/protocol/v1.rs:123) and `template_cache_path` does a LEXICAL
// `cache_root.join(format!("{id}.yaml"))` (src/workspace/allowlist_sync.rs:49).
// `Path::join` DISCARDS the base on an absolute operand and `..` survives the
// join, so a hostile broker picks any writable path.
//
// The write-boundary proof lives in-crate (`write_template_atomic` is private):
// src/workspace/allowlist_sync.rs `sa5_*`. Here we pin the path-building half,
// which is pub.
// ═════════════════════════════════════════════════════════════════════════

/// `starts_with` is NOT containment — the canonical trap of this finding.
/// A `..` segment survives the join, so the lexical path still "starts with"
/// the cache root while resolving far outside it. The containment predicate
/// must be `parent() == Some(cache_root)`.
#[test]
fn sa5_traversal_template_id_must_not_escape_the_cache_root() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let root = cache_root(home, "ws-test");

    // `template_cache_path` returns `KvendraResult<PathBuf>` since the fix:
    // the hostile id is refused instead of building a path at all.
    let p = template_cache_path(home, "ws-test", "../../../allowlists/profile-alpha");
    assert!(
        p.is_err(),
        "a template id must never build a path outside the sync cache root \
         (`{}`); the builder returned {p:?} — note a lexical `..` path still \
         passes the `starts_with` test, which is why containment must be \
         parent-equality",
        root.display()
    );
}

/// The ETag sidecar shares the same builder and the same hole.
#[test]
fn sa5_absolute_template_id_must_not_escape_the_cache_root() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let root = cache_root(home, "ws-test");
    let escapee = dir.path().join("outside").join("evil");

    let p = template_etag_path(home, "ws-test", &escapee.to_string_lossy());
    assert!(
        p.is_err(),
        "an ABSOLUTE template id discards the base in `Path::join`; the etag \
         builder returned {p:?}, which must be refused as outside `{}`",
        root.display()
    );
}

/// GUARD (green before AND after) — a legitimate broker id must keep resolving
/// to exactly one file directly under the cache root.
#[test]
fn sa5_guard_legit_template_id_stays_under_the_cache_root() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let root = cache_root(home, "ws-test");
    let yaml = template_cache_path(home, "ws-test", "github-deploy-tmpl-v1").unwrap();
    let etag = template_etag_path(home, "ws-test", "github-deploy-tmpl-v1").unwrap();
    assert_eq!(yaml.parent(), Some(root.as_path()));
    assert_eq!(etag.parent(), Some(root.as_path()));
}

/// GREEN-only — the full hostile-id table is refused by BOTH builders with a
/// `KvendraError::Config` naming "template id" and the `{:?}`-quoted id.
/// (`sync_once` counting the skip in `report.failed` with the
/// `workspace_template_id_rejected` warning, and `clear_stale_blocked` gated
/// on `report.failed == 0`, need a live broker and are verified by review.)
#[test]
fn sa5_hostile_template_id_table_is_refused_by_both_builders() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let too_long = "a".repeat(kvendra::path_id::MAX_PATH_COMPONENT_ID_LEN + 1);
    let ids: [&str; 10] = [
        "",
        ".",
        "..",
        "a/b",
        "a\\b",
        "a\0b",
        "a b",
        "tmpl\n",
        "plantillañ",
        &too_long,
    ];
    for id in ids {
        for (builder, r) in [
            (
                "template_cache_path",
                template_cache_path(home, "ws-test", id),
            ),
            (
                "template_etag_path",
                template_etag_path(home, "ws-test", id),
            ),
        ] {
            match r {
                Err(kvendra::error::KvendraError::Config(msg)) => {
                    assert!(
                        msg.contains("template id") && msg.contains(&format!("{id:?}")),
                        "{builder}({id:?}) refused with a message that does not name \
                         the template id: {msg:?}"
                    );
                }
                other => panic!("{builder}({id:?}) must be Err(Config), got {other:?}"),
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════
// SA6 — ISSUE-KVD-CLI-BFACC4 (MED)
// See the in-crate tests in `src/cli/config_approval.rs` (`sa6_*`): the
// subcommands read `KVENDRA_HOME` from the process environment, which can only
// be mutated under `crate::test_env_lock()` (pub(crate), src/lib.rs:41).
//
// Pure half that CAN live here: `Config::load` itself is correct — it returns
// defaults ONLY for an ABSENT file and an Err for every integrity failure. The
// bug is entirely in the five callers that do `.unwrap_or_default()` and then
// `save()`.
// ═════════════════════════════════════════════════════════════════════════

/// GUARD (green before AND after) — pins the invariant the fix depends on:
/// every `Err` from `Config::load` is an INTEGRITY failure, so propagating it
/// with `?` at the writer sites cannot break first-run.
#[test]
fn sa6_guard_absent_config_loads_defaults_while_tampered_config_errors() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    kvendra::config::ensure_layout(home).unwrap();
    let v = Vault::new(home.to_path_buf());
    v.create_with_params(b"hunter2-run1-sa6", fast_params())
        .unwrap();
    v.unlock(b"hunter2-run1-sa6", 30).unwrap();

    // Absent → Ok(defaults). This is why `?` is safe at the writer sites.
    assert!(
        Config::load(home, Some(&v)).is_ok(),
        "an ABSENT config.toml must load as signed defaults (first run)"
    );

    // Signed, then tampered by appending after the `_hmac` trailer.
    let mut cfg = Config::default();
    cfg.detection.severity = DetectionSeverity::Block;
    cfg.approval.mode = ApprovalMode::Ask;
    cfg.save(home, &v).unwrap();
    let path = home.join("config.toml");
    let signed = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("{signed}appended_by_attacker = true\n")).unwrap();

    let err = Config::load(home, Some(&v)).unwrap_err().to_string();
    assert!(
        err.contains("config_tampered_detected"),
        "content appended after the `_hmac` trailer must be refused, got: {err}"
    );
}

// ═════════════════════════════════════════════════════════════════════════
// SA7 — ISSUE-KVD-CLI-9B3395 (MED)
// The destructive catalog omits github.release and github.add_topics.
//
// RED at e41b652: `CATALOG` (src/allowlist/catalog.rs:59-146) has 15 rules and
// neither `release` (POST /releases, github.rs:148-157) nor `add_topics`
// (PUT /topics, github.rs:381-389) is among them. A catalog MISS is OPEN:
// `validate_destructive_opt_in` (validator.rs:87) never demands opt-in and
// `lookup_destructive` → `should_prompt` never prompts. The capabilities
// manifest (src/cli/capabilities.rs:62-72) declares both destructive — two
// hand-maintained tables that disagree, with only a SUBSET test between them.
//
// Pure functions only — a `release` dispatch would hit api.github.com and,
// after the fix, open an approval dialog.
// ═════════════════════════════════════════════════════════════════════════

const GH_NO_OPT_IN: &str = r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - release:
            repos: ["KvendraAI/kvendra-cli"]
        - add_topics:
            repos: ["KvendraAI/kvendra-cli"]
"#;

#[test]
fn sa7_github_release_must_be_destructive() {
    assert!(
        catalog::is_destructive(
            "kvendra.github",
            "release",
            &json!({ "repo": "KvendraAI/kvendra-cli", "tag_name": "v9.9.9" })
        ),
        "publishing a GitHub release is irreversible-by-default and is already \
         declared destructive by the capabilities manifest — the enforcement \
         catalog must agree"
    );
}

#[test]
fn sa7_github_add_topics_must_be_destructive() {
    assert!(
        catalog::is_destructive(
            "kvendra.github",
            "add_topics",
            &json!({ "repo": "KvendraAI/kvendra-cli", "topics": ["pwned"] })
        ),
        "add_topics rewrites public repository metadata — it must be catalogued \
         destructive"
    );
}

/// Consent gate as the runtime actually calls it (`lookup_destructive` with the
/// INNER payload — the H2 shape).
#[test]
fn sa7_lookup_destructive_must_see_release_and_add_topics() {
    let s = spec_of(GH_NO_OPT_IN);
    for (op, args) in [
        (
            "release",
            json!({ "repo": "KvendraAI/kvendra-cli", "tag_name": "v1" }),
        ),
        (
            "add_topics",
            json!({ "repo": "KvendraAI/kvendra-cli", "topics": [] }),
        ),
    ] {
        assert!(
            policy::lookup_destructive(&s, "kvendra.github", op, &args),
            "kvendra.github.{op} must resolve destructive at the approval gate"
        );
    }
}

/// Sign-time half: an allowlist granting `release` / `add_topics` WITHOUT
/// `accept_destructive: true` is accepted today, so the owner never sees the
/// `[⚠ DESTRUCTIVE — owner accepted]` marker either.
#[test]
fn sa7_release_without_opt_in_must_be_rejected_by_the_validator() {
    let s = spec_of(GH_NO_OPT_IN);
    let r = validate(&s);
    assert!(
        r.is_err(),
        "an allowlist granting kvendra.github.release / add_topics without \
         `accept_destructive: true` must be REFUSED at validate time; got {r:?}"
    );
    let msg = r.unwrap_err().to_string();
    assert!(
        msg.contains("kvendra.github.release") && msg.contains("accept_destructive"),
        "the rejection must name the offending operation and the required \
         opt-in, got: {msg}"
    );
}

/// The anti-drift invariant this finding exists for: the wire-public manifest
/// and the enforcement catalog are two hand-maintained tables. Every op the
/// manifest publishes as destructive MUST have a rule in the catalog, or the
/// published contract is a lie.
#[test]
fn sa7_published_destructive_ops_must_all_have_a_catalog_rule() {
    let manifest = kvendra::cli::capabilities::build_manifest();
    let mut orphans: Vec<String> = Vec::new();
    for p in &manifest.primitives {
        for op in &p.destructive_ops {
            let has_rule = catalog::CATALOG
                .iter()
                .any(|r| r.primitive == p.id && r.operation == op.as_str());
            if !has_rule {
                orphans.push(format!("{}.{op}", p.id));
            }
        }
    }
    assert!(
        orphans.is_empty(),
        "the capabilities manifest publishes these ops as destructive but the \
         enforcement catalog has no rule for them (no opt-in demanded, no \
         approval prompt, no destructive marker): {orphans:?}"
    );
}

/// GUARD (green before AND after) — read-only ops must NOT become destructive
/// when the default is inverted (D3); otherwise every profile listing
/// `read_repo` would need `accept_destructive` and the fix would be worse than
/// the bug.
#[test]
fn sa7_guard_read_only_ops_stay_non_destructive() {
    for (p, op) in [
        ("kvendra.github", "read_repo"),
        ("kvendra.github", "read_issue"),
        ("kvendra.github", "list_issues"),
        ("kvendra.npm", "read_metadata"),
        ("kvendra.pypi", "read_metadata"),
        ("kvendra.git", "pull"),
    ] {
        assert!(
            !catalog::is_destructive(p, op, &Value::Null),
            "{p}.{op} is read-only and must stay non-destructive"
        );
    }
}

// GREEN-only (implementer) — added once `catalog::{has_rule, is_read_only,
// READ_ONLY_OPS}` landed. `destructive_ops_equal_enforcement_catalog` and the
// frozen `published_destructive_ops_match_if_kvd_cli_5d9fb5` snapshot live
// in-crate in src/cli/capabilities.rs (replacing the subset-only test).

#[test]
fn sa7_unclassified_future_op_is_destructive() {
    assert!(catalog::is_destructive(
        "kvendra.github",
        "delete_repo_v2",
        &Value::Null
    ));
    assert!(catalog::is_destructive(
        "kvendra.npm",
        "unpublish",
        &Value::Null
    ));
}

#[test]
fn sa7_every_primitive_op_is_classified() {
    let mut total = 0usize;
    for p in kvendra::primitives::catalog() {
        for op in p.operations {
            total += 1;
            assert!(
                catalog::has_rule(p.name, op) ^ catalog::is_read_only(p.name, op),
                "{}.{op} must be ruled XOR read-only",
                p.name
            );
        }
    }
    assert_eq!(catalog::CATALOG.len() + catalog::READ_ONLY_OPS.len(), total);
}

#[test]
fn sa7_git_commit_has_an_annotated_rule() {
    assert!(catalog::CATALOG.iter().any(|r| r.primitive == "kvendra.git"
        && r.operation == "commit"
        && r.kind == catalog::DestructiveKind::Annotated));
}

/// Compat guard: the owner's real `github.kvendraai.cli-write` shape —
/// `release` / `add_topics` with `destructive: true` + `accept_destructive:
/// true` — must stay valid, and must resolve destructive at the gate.
#[test]
fn sa7_guard_explicit_opt_in_shape_stays_valid() {
    let s = spec_of(
        r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - release:
            repos: ["KvendraAI/kvendra-cli"]
            destructive: true
            accept_destructive: true
        - add_topics:
            repos: ["KvendraAI/kvendra-cli"]
            destructive: true
            accept_destructive: true
"#,
    );
    assert!(validate(&s).is_ok(), "{:?}", validate(&s));
    for op in ["release", "add_topics"] {
        assert!(policy::lookup_destructive(
            &s,
            "kvendra.github",
            op,
            &json!({ "repo": "KvendraAI/kvendra-cli" })
        ));
    }
}

// ═════════════════════════════════════════════════════════════════════════
// SA8 — ISSUE-KVD-CLI-8F501A (MED)
// A low-entropy decoy hides every real token of the same provider.
//
// RED at e41b652: `detect` (src/detection/mod.rs:102-127) asks the RegexSet
// WHICH providers matched, then takes the LEFTMOST match only (:113) and tests
// the entropy of that single sample (:117). A decoy with the right prefix and
// 36 identical characters (0.669 bits/char, far below ENTROPY_THRESHOLD = 3.5)
// therefore disqualifies the WHOLE provider for that tool-call. The OUTBOUND
// redactor (`sanitize_output`, :158-167) already gets this right — it filters
// per match — so the decider and the executor disagree.
// ═════════════════════════════════════════════════════════════════════════

/// 36 × 'a' after the prefix: matches `ghp_[A-Za-z0-9]{36}` exactly, entropy
/// 0.669 bits/char.
const DECOY_GHP: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// A real-shaped token, entropy 5.03 bits/char (same fixture as
/// src/detection/mod.rs:217).
const REAL_GHP: &str = "ghp_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaaaa";

#[test]
fn sa8_decoy_must_not_mask_a_real_token_of_the_same_provider() {
    let haystack = format!("{DECOY_GHP} {REAL_GHP}");
    let hits = detect(&haystack);
    let found = hits
        .iter()
        .find(|h| h.provider == "github_pat_classic" && h.matched_text == REAL_GHP);
    assert!(
        found.is_some(),
        "a real github PAT placed AFTER a low-entropy decoy of the same \
         provider must still be detected — the entropy filter belongs per \
         match, not on the leftmost sample; detect() returned {hits:?}"
    );
}

/// GUARD (green before AND after) — the decoy alone must stay unreported, so
/// the fix does not simply drop the entropy filter and flood every call with
/// false positives.
#[test]
fn sa8_guard_decoy_alone_is_still_not_reported() {
    assert!(
        detect(DECOY_GHP).is_empty(),
        "a low-entropy string must not be reported on its own"
    );
}

/// GUARD (green before AND after) — the real token alone is detected today;
/// this pins that the decoy, not the pattern, is what breaks detection.
#[test]
fn sa8_guard_real_token_alone_is_reported() {
    let hits = detect(REAL_GHP);
    assert_eq!(
        hits.len(),
        1,
        "the real token alone must be reported exactly once; got {hits:?}"
    );
}

/// End-to-end at the severity that matters: with `detection.severity = block`
/// the dispatcher must refuse the call and quarantine the profile BEFORE the
/// allowlist and approval gates (server.rs:748-826) — so this e2e can never
/// open a dialog.
#[tokio::test]
async fn sa8_decoy_must_not_defeat_the_inbound_block_gate() {
    let (_dir, ctx) = bootstrap("shell.profile", SHELL_ECHO_ONLY, DetectionSeverity::Block).await;
    let payload = format!("{DECOY_GHP} {REAL_GHP}");
    let resp = dispatch(
        call(
            "kvendra.shell",
            json!({
                "profile_id": "shell.profile",
                "operation": "exec",
                // `id` is outside `binaries: ["echo"]`, so even in the RED
                // state (detection blind) nothing is ever spawned.
                "args": { "binary": "id", "argv": [payload] }
            }),
        ),
        ctx.clone(),
    )
    .await;

    let err = resp
        .error
        .as_ref()
        .expect("a secret smuggled past the decoy must be refused");
    assert!(
        err.message.contains("severity=block"),
        "the inbound detection gate must refuse the call at severity=block; \
         got: {}",
        err.message
    );

    let rows = audit_rows(&ctx).await;
    assert!(
        rows.iter()
            .any(|(_, flags, _)| flags.contains("detection_blocked")),
        "the audit row must carry `detection_blocked`; rows: {rows:?}"
    );
}

// GREEN-only (implementer): with the shared `matches_above_threshold` selector
// in place add —
//   * two real tokens of the same provider → both reported;
//   * `"{real} {real} {real}"` → de-duplicated to 1 (never 0);
//   * cross-provider mix (ghp decoy + npm decoy + ghp real + npm real) → 2 hits,
//     each the REAL token;
//   * inbound/outbound symmetry: every `detect` hit is absent from
//     `sanitize_output`, the decoy survives verbatim, and
//     `<redacted:github_pat_classic>` is present;
//   * `REDACT_ONLY_PROVIDERS` (jwt, google_oauth_token) still exempt inbound and
//     `ALWAYS_REDACT_PROVIDERS` (private_key_pem) still ignores the threshold.

// ─────────────────────────────────────────────────────────────────────────
// SA8-F1 (validation-loop iteration 2, Medium) — the per-match gate was still
// bypassable at 23347f5:
//   * OVERLAP: a rejected decoy's tail swallows the real token's prefix and
//     `find_iter` resumes at the decoy's END, inside the real token
//     (`AKIA`+12×`A`+AKID, `sk-`+48×`a`+openai, `ghp_`+33×`a`+PAT, …);
//   * DILUTION: in-charset low-entropy padding glued to a real key under an
//     unbounded quantifier drags the WHOLE-match entropy below 3.5 (anthropic,
//     pypi, slack, gitlab, stripe, openai) — inbound blind AND the key echoed
//     back verbatim by `sanitize_output`.
// Each probe below is asserted inbound (`detect`) and outbound
// (`sanitize_output`) for every provider shape.
// ─────────────────────────────────────────────────────────────────────────

/// (provider, real-shaped token, decoy prefix, overlap pad length, pad char)
const SA8_F1_CASES: &[(&str, &str, &str, usize, char)] = &[
    (
        "anthropic_key",
        "sk-ant-api03-Zq7Wm2Xv8Nb4Kc6Rt9Yh3Jd5Fg1Ls0PuAeB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJ_x-QwErTyUiOp",
        "sk-ant-",
        60,
        'a',
    ),
    (
        "pypi_token",
        "pypi-AgEIcHlwaS5vcmcCJDgyZWUxMTk5LTRkMzAtNGE5MS04YzVjLTk2ZjQ4YzI3ZDViYwACKlszLCJlMmU3MWMxMy01YjQ2LTRkOTMtYjMyOC1lY2EyZWVjZDQ3M2YiXQAABiBp",
        "pypi-AgEI",
        30,
        'a',
    ),
    (
        "slack_token",
        "xoxb-1234567890-9876543210123-aB3kP9zX1mQ7rL5tY2vN4wE6",
        "xoxb-",
        10,
        'a',
    ),
    (
        "gitlab_pat",
        "glpat-aB3kP9zX1mQ7rL5tY2vN",
        "glpat-",
        20,
        'a',
    ),
    (
        "stripe_secret_key",
        "sk_live_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0",
        "sk_live_",
        24,
        'a',
    ),
    (
        "openai_key",
        "sk-aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJ",
        "sk-",
        48,
        'a',
    ),
    ("aws_akid", "AKIAIOSFODNN7EXAMPLE", "AKIA", 12, 'A'),
    ("github_pat_classic", REAL_GHP, "ghp_", 33, 'a'),
];

fn sa8_f1_case(provider: &str) -> (&'static str, &'static str, usize, char) {
    let (_, real, prefix, k, pad) = SA8_F1_CASES
        .iter()
        .find(|(p, ..)| *p == provider)
        .unwrap_or_else(|| panic!("no SA8-F1 case for {provider}"));
    (real, prefix, *k, *pad)
}

fn sa8_f1_assert_caught(provider: &str, shape: &str, real: &str, haystack: &str) {
    let hits = detect(haystack);
    assert!(
        hits.iter()
            .any(|h| h.provider == provider && h.matched_text.contains(real)),
        "{provider}/{shape}: inbound detect() missed the real token; providers \
         reported: {:?}",
        hits.iter().map(|h| h.provider.as_str()).collect::<Vec<_>>()
    );
    let out = sanitize_output(haystack);
    assert!(
        !out.contains(real),
        "{provider}/{shape}: the real token survived outbound redaction"
    );
    assert!(
        out.contains(&format!("<redacted:{provider}>")),
        "{provider}/{shape}: no `<redacted:{provider}>` marker in the output"
    );
}

/// OVERLAP: decoy prefix + pad sized so the decoy match swallows the real
/// token's prefix.
fn sa8_f1_overlap(provider: &str) {
    let (real, prefix, k, pad) = sa8_f1_case(provider);
    let hay = format!("{prefix}{}{real}", pad.to_string().repeat(k));
    sa8_f1_assert_caught(provider, "overlap", real, &hay);
}

/// DILUTION: real key followed (and, separately, preceded under the same
/// prefix) by 2000 in-charset pad characters — no decoy needed.
fn sa8_f1_dilution(provider: &str) {
    let (real, prefix, _, pad) = sa8_f1_case(provider);
    let padding = pad.to_string().repeat(2000);
    sa8_f1_assert_caught(provider, "dilution", real, &format!("{real}{padding}"));
    sa8_f1_assert_caught(
        provider,
        "pre-dilution",
        real,
        &format!("{prefix}{padding}{real}"),
    );
}

#[test]
fn sa8_f1_anthropic_overlap_and_dilution_are_caught() {
    sa8_f1_overlap("anthropic_key");
    sa8_f1_dilution("anthropic_key");
}

#[test]
fn sa8_f1_pypi_overlap_and_dilution_are_caught() {
    sa8_f1_overlap("pypi_token");
    sa8_f1_dilution("pypi_token");
}

#[test]
fn sa8_f1_slack_overlap_and_dilution_are_caught() {
    sa8_f1_overlap("slack_token");
    sa8_f1_dilution("slack_token");
}

#[test]
fn sa8_f1_gitlab_overlap_and_dilution_are_caught() {
    sa8_f1_overlap("gitlab_pat");
    sa8_f1_dilution("gitlab_pat");
}

#[test]
fn sa8_f1_stripe_overlap_and_dilution_are_caught() {
    sa8_f1_overlap("stripe_secret_key");
    sa8_f1_dilution("stripe_secret_key");
}

#[test]
fn sa8_f1_openai_overlap_and_dilution_are_caught() {
    sa8_f1_overlap("openai_key");
    sa8_f1_dilution("openai_key");
}

#[test]
fn sa8_f1_aws_akid_overlap_and_padding_are_caught() {
    sa8_f1_overlap("aws_akid");
    sa8_f1_dilution("aws_akid");
}

#[test]
fn sa8_f1_github_overlap_and_padding_are_caught() {
    sa8_f1_overlap("github_pat_classic");
    sa8_f1_dilution("github_pat_classic");
}

/// GUARD — the window gate must not turn a decoy that is low-entropy
/// EVERYWHERE into a finding, however long it is, for any provider.
#[test]
fn sa8_f1_guard_lone_low_entropy_decoys_stay_unreported() {
    for (provider, _, prefix, _, pad) in SA8_F1_CASES {
        for n in [16usize, 60, 500, 5000] {
            let decoy = format!("{prefix}{}", pad.to_string().repeat(n));
            assert!(
                detect(&decoy).is_empty(),
                "{provider}: a lone decoy with {n} pad chars was reported"
            );
            assert_eq!(
                sanitize_output(&decoy),
                decoy,
                "{provider}: a lone decoy was mangled by the redactor"
            );
        }
    }
}

/// End-to-end: the openai overlap probe must trip the severity=block gate.
#[tokio::test]
async fn sa8_f1_overlap_must_not_defeat_the_inbound_block_gate() {
    let (_dir, ctx) = bootstrap("shell.profile", SHELL_ECHO_ONLY, DetectionSeverity::Block).await;
    let (real, prefix, k, pad) = sa8_f1_case("openai_key");
    let payload = format!("{prefix}{}{real}", pad.to_string().repeat(k));
    let resp = dispatch(
        call(
            "kvendra.shell",
            json!({
                "profile_id": "shell.profile",
                "operation": "exec",
                "args": { "binary": "id", "argv": [payload] }
            }),
        ),
        ctx.clone(),
    )
    .await;
    let err = resp
        .error
        .as_ref()
        .expect("a key smuggled behind an overlapping decoy must be refused");
    assert!(
        err.message.contains("severity=block"),
        "the inbound detection gate must refuse at severity=block; got: {}",
        err.message
    );
}

// ═════════════════════════════════════════════════════════════════════════
// SA10 — ISSUE-KVD-CLI-0F929A (MED) — supply chain.
//
// Not expressible as a Rust test: the subject is the repository and the CI
// workflows, not the crate. TEST_PLAN FLOW-9 defines eight SHELL checks
// (`git ls-files --error-unmatch Cargo.lock`, `git check-ignore -v Cargo.lock`,
// `grep -- '--locked' .github/`, `git grep cargo-deny -- .github/`,
// `cargo metadata --locked`, `cargo-deny check`, …). They were executed at
// e41b652 and their RED output is recorded verbatim in the TEST entity; the
// implementer adds `scripts/ci-supply-chain-check.sh` + the `deny` job.
//
// TRAP pinned for whoever re-runs them: `git ls-files Cargo.lock` alone exits 0
// with EMPTY output — the check is inert without `--error-unmatch`.
// ═════════════════════════════════════════════════════════════════════════
