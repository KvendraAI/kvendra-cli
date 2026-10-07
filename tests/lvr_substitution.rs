//! REQ-KVD-11F906 — broker substitution:
//! - TEST-KVD-CLI-NEW-3 (AC-LVR-3): undefined / unverified / locked refuse
//!   WITHOUT executing.
//! - TEST-KVD-CLI-NEW-7 (AC-LVR-7): unbounded positions → `lvr_position_unbounded`.
//! - TEST-KVD-CLI-NEW-8 (AC-LVR-8): type validation at use time + no shell.
//! - TEST-KVD-CLI-NEW-9 (RF-CLI-6/8): audit flags (O6), rate limit, error data.

mod lvr_common;

use lvr_common::*;
use serde_json::json;

const SHELL_YAML: &str = r#"profile_id: p
secret:
  type: github_pat
allowlist:
  primitives:
    - name: kvendra.shell
      operations:
        - exec:
            binaries: ["touch", "ls", "sh", "pwd", "git"]
            cwd_pattern: "^{WS_RE}(/.*)?$"
            accept_destructive: true
        - ls_tpl:
            binaries: ["ls"]
            args_constraints:
              - allowed: ["-la", "*"]
            accept_destructive: true
        - ls_prefix:
            binaries: ["ls"]
            args_constraints:
              - allowed: ["-la", "{WS}/*"]
            accept_destructive: true
        - no_cwd_pattern:
            binaries: ["pwd"]
            accept_destructive: true
        - trivial_cwd:
            binaries: ["pwd"]
            cwd_pattern: ".*"
            accept_destructive: true
    - name: kvendra.git
      operations:
        - commit:
            cwd_pattern: "^{WS_RE}(/.*)?$"
            accept_destructive: true
    - name: kvendra.http
      operations:
        - request:
            url_pattern_regex: ["^https://api\\.kvd-sentinel-allowed\\.example/"]
            methods: ["POST"]
            accept_destructive: true
"#;

fn touch_call(f: &Fixture, var: &str) -> kvendra::mcp::protocol::JsonRpcRequest {
    let marker = f.ws.join("kvd-sentinel-marker");
    call(
        "kvendra.shell",
        "exec",
        json!({"binary": "touch", "argv": [marker.to_string_lossy()], "cwd": format!("{{{{lvr:{var}}}}}")}),
    )
}

// ───────────────────────── TEST-3 / AC-LVR-3 ─────────────────────────

#[tokio::test]
async fn undefined_unverified_and_locked_never_execute() {
    let f = fixture(SHELL_YAML).await;
    let marker = f.ws.join("kvd-sentinel-marker");

    let resp = run(&f, touch_call(&f, "missing")).await;
    assert_eq!(
        error_type(&resp).as_deref(),
        Some("lvr_undefined"),
        "{resp}"
    );
    assert_eq!(
        resp.pointer("/error/data/key").and_then(|k| k.as_str()),
        Some("missing")
    );
    assert!(!marker.exists(), "an undefined variable must not execute");

    let resp = run(&f, touch_call(&f, "raw")).await;
    assert_eq!(
        error_type(&resp).as_deref(),
        Some("lvr_unverified"),
        "{resp}"
    );
    assert!(!marker.exists(), "an unverified variable must not execute");
    assert!(!resp.to_string().contains("kvd-sentinel-unverified"));

    // Positive control: the same call with a verified variable runs.
    let resp = run(&f, touch_call(&f, "ws")).await;
    assert!(resp.get("result").is_some(), "{resp}");
    assert!(marker.exists(), "control: the verified call executes");
    std::fs::remove_file(&marker).unwrap();

    // Vault locked (no session blob in the temp home → no self-heal).
    f.ctx.vault.lock();
    let resp = run(&f, touch_call(&f, "ws")).await;
    assert_eq!(
        error_type(&resp).as_deref(),
        Some("lvr_vault_locked"),
        "{resp}"
    );
    assert_eq!(
        resp.pointer("/error/data/help/topic")
            .and_then(|t| t.as_str()),
        Some("vault-locked-pending-unlock")
    );
    assert!(
        !marker.exists(),
        "a locked vault must not execute (no fallback)"
    );
}

#[tokio::test]
async fn escaped_reference_passes_literally() {
    let f = fixture(SHELL_YAML).await;
    // `\{{lvr:ws}}` in a free field is a mention: no substitution, no
    // refusal; the primitive receives the literal with its backslash.
    let resp = run(
        &f,
        call(
            "kvendra.shell",
            "exec",
            json!({"binary": "ls", "argv": ["\\{{lvr:ws}}"], "cwd": "{{lvr:ws}}"}),
        ),
    )
    .await;
    assert_ne!(error_type(&resp).as_deref(), Some("lvr_position_unbounded"));
    // The mention was NOT substituted: the workspace path never shows up as the
    // argument `ls` was asked to list.
    assert!(!resp.to_string().contains("kvd-sentinel-ws'"), "{resp}");
    if cfg!(windows) {
        // On Windows the command line is flattened by CreateProcess and the
        // runner's MSYS `ls` re-parses it (backslash and brace handling), so its
        // echo of the literal is mangled; the broker still passed it verbatim.
        assert!(resp.to_string().contains("lvr:ws"), "{resp}");
    } else {
        assert!(resp.to_string().contains("\\\\{{lvr:ws}}"), "{resp}");
    }
}

#[tokio::test]
async fn profile_id_reference_is_resolved_before_the_id_gate() {
    let f = fixture(SHELL_YAML).await;
    let resp = run(
        &f,
        call_as(
            "{{lvr:prof}}",
            "kvendra.shell",
            "exec",
            json!({"binary": "pwd", "argv": [], "cwd": "{{lvr:ws}}"}),
        ),
    )
    .await;
    assert!(resp.get("result").is_some(), "{resp}");
    // A profile_id variable pointing outside the vault is refused.
    kvendra::vars::set_var(
        &f.ctx.vault,
        "ghost",
        kvendra::vars::VarType::ProfileId,
        "kvd-sentinel-ghost",
        true,
    )
    .unwrap();
    let resp = run(
        &f,
        call_as(
            "{{lvr:ghost}}",
            "kvendra.shell",
            "exec",
            json!({"binary": "pwd", "argv": []}),
        ),
    )
    .await;
    assert_eq!(
        error_type(&resp).as_deref(),
        Some("lvr_profile_not_in_vault"),
        "{resp}"
    );
}

#[tokio::test]
async fn cfg_reference_in_bounded_position_is_refused() {
    let f = fixture(SHELL_YAML).await;
    let resp = run(
        &f,
        call(
            "kvendra.shell",
            "exec",
            json!({"binary": "pwd", "argv": [], "cwd": "{{cfg:kvd.ws}}"}),
        ),
    )
    .await;
    assert_eq!(
        error_type(&resp).as_deref(),
        Some("cfg_ref_not_resolvable_by_broker"),
        "{resp}"
    );
}

// ───────────────────────── TEST-7 / AC-LVR-7 ─────────────────────────

#[tokio::test]
async fn unbounded_positions_are_refused() {
    let f = fixture(SHELL_YAML).await;
    let cases: Vec<(&str, &str, &str, serde_json::Value)> = vec![
        (
            "argv under a * template slot",
            "kvendra.shell",
            "ls_tpl",
            json!({"binary": "ls", "argv": ["-la", "{{lvr:ws}}"]}),
        ),
        (
            "cwd without cwd_pattern",
            "kvendra.shell",
            "no_cwd_pattern",
            json!({"binary": "pwd", "argv": [], "cwd": "{{lvr:ws}}"}),
        ),
        (
            "trivial cwd_pattern .*",
            "kvendra.shell",
            "trivial_cwd",
            json!({"binary": "pwd", "argv": [], "cwd": "{{lvr:ws}}"}),
        ),
        (
            "git commit message",
            "kvendra.git",
            "commit",
            json!({"cwd": "{{lvr:ws}}", "message": "msg {{lvr:s}}"}),
        ),
        (
            "http body",
            "kvendra.http",
            "request",
            json!({"url": "https://api.kvd-sentinel-allowed.example/x", "method": "POST", "body": "{{lvr:s}}"}),
        ),
        (
            "interpreter binary",
            "kvendra.shell",
            "exec",
            json!({"binary": "sh", "argv": ["-c", "true"], "cwd": "{{lvr:ws}}"}),
        ),
        (
            "git with -c",
            "kvendra.shell",
            "exec",
            json!({"binary": "git", "argv": ["-c", "core.pager=cat", "status"], "cwd": "{{lvr:ws}}"}),
        ),
    ];
    for (case, prim, op, args) in cases {
        let resp = run(&f, call(prim, op, args)).await;
        assert_eq!(
            error_type(&resp).as_deref(),
            Some("lvr_position_unbounded"),
            "[{case}] {resp}"
        );
    }
    // `binary` is never a bounded position; the allowlist's literal
    // `binaries` list already refuses it (the echo is masked).
    let resp = run(
        &f,
        call(
            "kvendra.shell",
            "exec",
            json!({"binary": "{{lvr:s}}", "argv": []}),
        ),
    )
    .await;
    assert!(resp.get("error").is_some(), "{resp}");
    assert!(!resp.to_string().contains(SENTINEL_STRING), "{resp}");
}

#[tokio::test]
async fn argv_slot_with_prefix_template_is_bounded() {
    let f = fixture(SHELL_YAML).await;
    let sub = f.ws.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    let resp = run(
        &f,
        call(
            "kvendra.shell",
            "ls_prefix",
            json!({"binary": "ls", "argv": ["-la", "{{lvr:ws}}/sub"]}),
        ),
    )
    .await;
    assert!(resp.get("result").is_some(), "{resp}");
}

// ───────────────────────── TEST-8 / AC-LVR-8 ─────────────────────────

#[tokio::test]
async fn path_swapped_for_a_symlink_is_refused_at_use_time() {
    let f = fixture(SHELL_YAML).await;
    let real = f.ws.join("real");
    std::fs::create_dir_all(&real).unwrap();
    kvendra::vars::set_var(
        &f.ctx.vault,
        "swap",
        kvendra::vars::VarType::Path,
        &real.to_string_lossy(),
        true,
    )
    .unwrap();
    // Swap the directory for a symlink that escapes elsewhere.
    std::fs::remove_dir(&real).unwrap();
    let elsewhere = f.root.join("kvd-sentinel-elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&elsewhere, &real).unwrap();
    #[cfg(unix)]
    {
        let resp = run(
            &f,
            call(
                "kvendra.shell",
                "exec",
                json!({"binary": "pwd", "argv": [], "cwd": "{{lvr:swap}}"}),
            ),
        )
        .await;
        assert_eq!(
            error_type(&resp).as_deref(),
            Some("lvr_path_not_canonical"),
            "{resp}"
        );
    }
}

#[test]
fn values_are_validated_by_type() {
    use kvendra::vars::VarType::*;
    use kvendra::vars::validate::validate;
    let cases: &[(kvendra::vars::VarType, &str)] = &[
        (String, "a;b"),
        (String, "$(id)"),
        (String, "a\0b"),
        (String, "a\nb"),
        (Path, "/kvd-sentinel/../etc"),
        (Port, "0"),
        (Port, "65536"),
        (Port, "080"),
        (Host, "user@kvd-sentinel.example"),
    ];
    for (t, v) in cases {
        assert!(validate(*t, v).is_err(), "{t:?} {v:?} must be rejected");
    }
}

/// Static check: every primitive spawns through `spawn::hardened_command`
/// and none uses a shell (`sh -c`) as the program (RF-CLI-5).
#[test]
fn primitives_never_spawn_through_a_shell() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/primitives");
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if !name.ends_with(".rs") || name == "spawn.rs" {
            continue;
        }
        let src = std::fs::read_to_string(&path).unwrap();
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code.contains("Command::new("),
            "{name}: spawn must go through spawn::hardened_command"
        );
        // (`git -c <config>` in git.rs is git's own flag, not a shell.)
        for shell in [
            "hardened_command(\"sh\")",
            "hardened_command(\"bash\")",
            "hardened_command(\"zsh\")",
            "\"/bin/sh\"",
        ] {
            assert!(!code.contains(shell), "{name}: shell invocation {shell}");
        }
    }
}

// ───────────────────────── TEST-9 / RF-CLI-6/8 ─────────────────────────

#[tokio::test]
async fn audit_records_references_per_o6_and_never_string_values() {
    let f = fixture(SHELL_YAML).await;
    let resp = run(
        &f,
        call(
            "kvendra.shell",
            "exec",
            json!({"binary": "ls", "argv": [], "cwd": "{{lvr:ws}}"}),
        ),
    )
    .await;
    assert!(resp.get("result").is_some(), "{resp}");
    // A string variable used in a refused free position.
    let _ = run(
        &f,
        call(
            "kvendra.git",
            "commit",
            json!({"cwd": "{{lvr:ws}}", "message": "{{lvr:s}}"}),
        ),
    )
    .await;
    let rows = audit_rows(&f).await;
    let all = format!("{rows:?}");
    // O6: cwd → reference AND resolved value.
    assert!(
        rows.iter()
            .any(|(fl, _, _)| fl.contains(&format!("lvr:ws={}", f.ws_str()))),
        "{all}"
    );
    // A string variable: hash only, never the value.
    assert!(rows.iter().any(|(fl, _, _)| fl.contains("lvr:s#")), "{all}");
    assert!(
        !all.contains(SENTINEL_STRING),
        "string value in audit: {all}"
    );
    assert!(
        rows.iter().any(|(fl, _, _)| fl.contains("lvr_denied")),
        "{all}"
    );
}

#[tokio::test]
async fn resolution_is_rate_limited_per_key() {
    let f = fixture(SHELL_YAML).await;
    let mut codes = Vec::new();
    for _ in 0..12 {
        let resp = run(
            &f,
            call(
                "kvendra.git",
                "commit",
                json!({"cwd": f.ws_str(), "message": "{{lvr:s}}"}),
            ),
        )
        .await;
        codes.push(error_type(&resp).unwrap_or_default());
    }
    assert!(
        codes.iter().any(|c| c == "lvr_rate_limited"),
        "burst 10 → the 11th resolution is limited: {codes:?}"
    );
    assert_eq!(codes[0], "lvr_position_unbounded");
}

#[tokio::test]
async fn error_data_never_carries_the_value() {
    let f = fixture(SHELL_YAML).await;
    let resp = run(
        &f,
        call(
            "kvendra.shell",
            "no_cwd_pattern",
            json!({"binary": "pwd", "argv": [], "cwd": "{{lvr:ws}}"}),
        ),
    )
    .await;
    let data = resp.pointer("/error/data").unwrap();
    assert_eq!(data["key"], "ws");
    assert!(data["hint"].as_str().is_some_and(|h| !h.is_empty()));
    assert!(!resp.to_string().contains(&f.ws_str()));
}
