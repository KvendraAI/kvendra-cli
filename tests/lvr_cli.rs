//! REQ-KVD-11F906 — `kvendra vars` CLI surface + shared grammar vectors.
//! - TEST-KVD-CLI-NEW-4 (AC-LVR-4): `set/unset/reveal/verify` refuse without
//!   a real TTY, `KVENDRA_PASSWORD` does not help, `--password-stdin` does not
//!   exist. The happy path with a real TTY is a MANUAL owner test.
//! - TEST-KVD-CLI-NEW-9 (part): `list` / `status` / `scan` never print values;
//!   scan input bounds, rate limit and the vault-locked warning (O3/O7).
//! - TEST-KVD-ENTERPRISE-NEW-3 (CLI side): the reference parser matches the
//!   core conformance vectors, copied byte for byte (sha256 pinned).
//!
//! Every invocation runs with `KVENDRA_HOME` and `HOME` in a tempdir.

mod lvr_common;

use assert_cmd::Command;
use kvendra::vars::refs::{Ns, keys};
use kvendra::vars::{self, VarType};
use kvendra::vault::Vault;
use lvr_common::{PASSWORD, SENTINEL_STRING, fast_params};
use sha2::{Digest, Sha256};

const VECTORS_SHA256: &str = "e079e006f77d0698b1f1aaac924acc2e72684b00735f1b8e2d1f2705f4dc75c6";

fn kvendra(home: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("kvendra").unwrap();
    c.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("KVENDRA_HOME", home.join("kvhome"))
        .env("RUST_LOG", "off");
    // Windows: the session token store binds the wrap key to COMPUTERNAME and
    // USERNAME (src/session/wrap_key.rs), and SystemRoot is needed by any
    // Windows process. Pass the test process's own values through.
    #[cfg(windows)]
    for var in ["COMPUTERNAME", "USERNAME", "SystemRoot"] {
        if let Some(v) = std::env::var_os(var) {
            c.env(var, v);
        }
    }
    c
}

// ───────────────────────── TEST-4 / AC-LVR-4 ─────────────────────────

#[test]
fn human_commands_refuse_without_a_real_tty() {
    let dir = tempfile::tempdir().unwrap();
    let cases: &[&[&str]] = &[
        &["vars", "set", "ws", "--type", "path"],
        &["vars", "unset", "ws"],
        &["vars", "reveal", "ws"],
        &["vars", "verify", "ws"],
        &["vars", "verify", "--all"],
    ];
    for args in cases {
        // On Windows the value commands (set/reveal/verify) refuse up front
        // as unsupported, before the TTY guard; `unset` still hits the guard.
        let expected = if cfg!(windows) && args[1] != "unset" {
            "vars_unsupported_platform"
        } else {
            "vars_rejected_"
        };
        // Captured stdio (assert_cmd pipes stdin/stdout) → refused.
        let out = kvendra(dir.path()).args(*args).output().unwrap();
        assert!(!out.status.success(), "{args:?} must fail");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains(expected), "{args:?}: {err}");
        // KVENDRA_PASSWORD changes nothing.
        let out = kvendra(dir.path())
            .args(*args)
            .env("KVENDRA_PASSWORD", "kvd-sentinel-pw")
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains(expected));
    }
    // There is no --password-stdin flag (clap rejects it).
    let out = kvendra(dir.path())
        .args(["vars", "set", "ws", "--type", "path", "--password-stdin"])
        .write_stdin("kvd-sentinel-pw\n")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unexpected argument"), "{err}");
}

// ───────────────────────── list / status / scan ─────────────────────────

/// Vault + vars in `<tmp>/kvhome`, plus an active session blob written by
/// `kvendra unlock` (KVENDRA_PASSWORD path) so the session-only commands work.
fn home_with_session(with_vars: bool) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let kvhome = root.join("kvhome");
    kvendra::config::ensure_layout(&kvhome).unwrap();
    let v = Vault::new(kvhome.clone());
    v.create_with_params(PASSWORD, fast_params()).unwrap();
    v.unlock(PASSWORD, 30).unwrap();
    if with_vars {
        vars::set_var(&v, "s", VarType::String, SENTINEL_STRING, true).unwrap();
        vars::set_var(&v, "p", VarType::Port, "8443", false).unwrap();
    }
    let out = kvendra(&root)
        .args(["unlock"])
        .env("KVENDRA_PASSWORD", std::str::from_utf8(PASSWORD).unwrap())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "test unlock failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (dir, root)
}

#[test]
fn list_and_status_never_print_values() {
    let (_d, root) = home_with_session(true);
    let out = kvendra(&root)
        .args(["vars", "list", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"key\":\"s\""), "{stdout}");
    assert!(!stdout.contains(SENTINEL_STRING) && !stdout.contains("8443"));

    let out = kvendra(&root)
        .args(["vars", "status", "--declared-stdin", "--json"])
        .write_stdin(r#"[{"key":"s","type":"string"},{"key":"missing","type":"path"}]"#)
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["vars"][0]["present"], true);
    assert_eq!(v["vars"][0]["type_ok"], true);
    assert_eq!(v["vars"][1]["present"], false);
    assert_eq!(v["undeclared_local"][0], "p");
    assert!(
        !out.stdout
            .windows(SENTINEL_STRING.len())
            .any(|w| w == SENTINEL_STRING.as_bytes())
    );
}

#[test]
fn scan_reports_keys_and_counts_only() {
    let (_d, root) = home_with_session(true);
    let input = format!(
        r#"{{"content":"a {s} b {s} port 8443 and nothing else"}}"#,
        s = SENTINEL_STRING
    );
    let out = kvendra(&root)
        .args(["vars", "scan", "--stdin", "--json"])
        .write_stdin(input)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "hits → exit 3");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v, serde_json::json!({"hits": [{"key": "s", "count": 2}]}));

    let out = kvendra(&root)
        .args(["vars", "scan", "--stdin", "--json"])
        .write_stdin("a perfectly clean text without values")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));

    // Minimum input length (anti prefix-oracle).
    let out = kvendra(&root)
        .args(["vars", "scan", "--stdin", "--json"])
        .write_stdin("kvd-sentinel")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stdout).contains("input_too_short"));

    // One audit row per scan, never the value.
    let conn = rusqlite::Connection::open(root.join("kvhome").join("audit.db")).unwrap();
    let flags: Vec<String> = conn
        .prepare("SELECT flags FROM audit_events WHERE action = 'vars_scan'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert_eq!(flags.len(), 2, "{flags:?}");
    assert!(flags[0].contains("hits:2") && flags[0].contains("lvr:s"));
    assert!(!flags.iter().any(|f| f.contains(SENTINEL_STRING)));
}

#[test]
fn scan_is_rate_limited_across_invocations() {
    let (_d, root) = home_with_session(true);
    let kvhome = root.join("kvhome");
    let v = Vault::new(kvhome.clone());
    v.unlock(PASSWORD, 30).unwrap();
    let mut outcomes = Vec::new();
    for _ in 0..(kvendra::cli::vars::SCAN_MAX_PER_MINUTE + 1) {
        outcomes.push(
            kvendra::cli::vars::scan_text(&kvhome, &v, "some sixteen+ bytes of text").unwrap(),
        );
    }
    assert_eq!(
        outcomes.last(),
        Some(&kvendra::cli::vars::ScanOutcome::RateLimited)
    );
    assert!(matches!(
        outcomes[0],
        kvendra::cli::vars::ScanOutcome::Hits(ref h) if h.is_empty()
    ));
}

#[test]
fn scan_with_locked_vault_says_skipped_never_clean() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    kvendra::config::ensure_layout(&root.join("kvhome")).unwrap();
    let out = kvendra(&root)
        .args(["vars", "scan", "--stdin", "--json"])
        .write_stdin("some text that is long enough")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&out.stderr).contains("scan omitido: vault bloqueado"));
}

// ───────────────────────── shared grammar vectors ─────────────────────────

#[test]
fn reference_parser_matches_the_core_vectors() {
    let raw = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/local-refs.vectors.json"),
    )
    .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&raw)),
        VECTORS_SHA256,
        "tests/fixtures/local-refs.vectors.json must be a byte-for-byte copy of core's"
    );
    let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let refs = v["refs"].as_array().unwrap();
    assert!(!refs.is_empty());
    for case in refs {
        let text = case["text"].as_str().unwrap();
        let want = |ns: &str| -> Vec<String> {
            case[ns]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| k.as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(keys(text, Ns::Cfg), want("cfg"), "cfg: {}", case["name"]);
        assert_eq!(keys(text, Ns::Lvr), want("lvr"), "lvr: {}", case["name"]);
    }
}

// ───────────────────── security review: no value outside the TTY ─────────────────────

/// Blocker fix — `reveal` without a real TTY fails and prints NO value on
/// stdout or stderr (there is no fallback channel).
#[cfg(unix)]
#[test]
fn reveal_without_tty_fails_without_printing_the_value() {
    let (_d, root) = home_with_session(true);
    for args in [
        &["vars", "reveal", "s"][..],
        &["vars", "verify", "s"][..],
        &["vars", "verify", "--all"][..],
    ] {
        let out = kvendra(&root)
            .args(args)
            .env("KVENDRA_PASSWORD", std::str::from_utf8(PASSWORD).unwrap())
            .output()
            .unwrap();
        assert!(!out.status.success(), "{args:?}");
        for stream in [&out.stdout, &out.stderr] {
            let s = String::from_utf8_lossy(stream);
            assert!(
                !s.contains(SENTINEL_STRING),
                "{args:?} printed the value: {s}"
            );
        }
    }
}

/// Blocker fix (Windows): commands that read or show a value refuse with a
/// clear message and never print it.
#[cfg(windows)]
#[test]
fn value_commands_are_unsupported_on_windows() {
    let (_d, root) = home_with_session(true);
    for args in [
        &["vars", "reveal", "s"][..],
        &["vars", "verify", "s"][..],
        &["vars", "set", "s", "--type", "string"][..],
    ] {
        let out = kvendra(&root).args(args).output().unwrap();
        assert!(!out.status.success(), "{args:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("requiere una consola real"), "{args:?}: {err}");
        assert!(!String::from_utf8_lossy(&out.stdout).contains(SENTINEL_STRING));
        assert!(!err.contains(SENTINEL_STRING));
    }
}

/// N1 — `kvendra audit` (human and --json) re-symbolizes local values when
/// the vault is unlocked.
#[tokio::test]
async fn audit_listing_masks_local_values() {
    let (_d, root) = home_with_session(true);
    let kvhome = root.join("kvhome");
    let v = Vault::new(kvhome.clone());
    v.unlock(PASSWORD, 30).unwrap();
    let writer =
        kvendra::audit::AuditWriter::spawn(kvhome.join("audit.db"), v.audit_hmac_key().unwrap())
            .unwrap();
    writer
        .record(kvendra::audit::AuditEvent {
            ts_unix_ms: 1,
            profile_id: "p".into(),
            primitive: "kvendra.shell".into(),
            action: "exec".into(),
            args_hash_hex: "00".into(),
            status: kvendra::audit::Status::Error,
            severity: kvendra::audit::Severity::Warn,
            flags: format!("lvr:s={SENTINEL_STRING}"),
            remote_audit_id: None,
            error_code: Some("RUNTIME_ERROR".into()),
            error_message: Some(format!("failed near {SENTINEL_STRING}")),
        })
        .await
        .unwrap();
    writer.shutdown().await;

    for args in [&["audit", "--json"][..], &["audit"][..]] {
        let out = kvendra(&root).args(args).output().unwrap();
        assert!(out.status.success(), "{args:?}");
        let s = String::from_utf8_lossy(&out.stdout);
        assert!(!s.contains(SENTINEL_STRING), "{args:?} leaked: {s}");
        assert!(s.contains("{{lvr:s}}"), "{args:?}: {s}");
    }
}
