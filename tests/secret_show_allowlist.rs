//! `kvendra secret show-allowlist <profile_id> [--json]` — Seguridad
//! 2026-10-07: alternativa legítima a leer el vault desde Bash.
//!
//! - signed allowlist + active session → `VALID`, exit 0;
//! - YAML altered after signing → `TAMPERED`, exit 1;
//! - YAML copied from another profile (valid HMAC, wrong id) → `TAMPERED`;
//! - vault locked (no session blob) → YAML printed, "no verificado", exit 0,
//!   no password prompt;
//! - hostile `profile_id` → refused before any disk access;
//! - the secret plaintext never appears in the output.
//!
//! ISOLATION: every invocation runs with a cleared env, `HOME` and
//! `KVENDRA_HOME` inside a tempdir. Never the real `~/.kvendra`.

use assert_cmd::Command;
use kvendra::vault::{Profile, Vault, kdf::KdfParams};
use std::path::{Path, PathBuf};

const PASSWORD: &str = "kvd-sentinel-show-allowlist-pw";
const SECRET: &[u8] = b"kvd-sentinel-secret-plaintext-91c2";
const YAML: &str = "profile_id: p\nsecret:\n  type: github_pat\nallowlist:\n  primitives:\n    - name: kvendra.shell\n      operations:\n        - run:\n            binaries: [\"echo\"]\n";

fn kvendra(root: &Path) -> Command {
    let mut c = Command::cargo_bin("kvendra").unwrap();
    c.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", root)
        .env("KVENDRA_HOME", root.join("kvhome"))
        .env("RUST_LOG", "off");
    c
}

fn save_meta(v: &Vault, id: &str, hmac: Option<String>) {
    v.save_profile_meta(&Profile {
        profile_id: id.into(),
        secret_type: "github_pat".into(),
        created_at: "2026-10-07T00:00:00Z".into(),
        expiration: None,
        unsafe_raw_token_enabled: false,
        quarantined: false,
        allowlist_hmac_hex: hmac,
    })
    .unwrap();
}

/// Vault in `<tmp>/kvhome` with profile `p` (secret + signed allowlist).
/// `with_session` writes the active session blob via `kvendra unlock`.
fn sandbox(with_session: bool) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    assert!(root.starts_with(std::env::temp_dir().canonicalize().unwrap()));
    let kvhome = root.join("kvhome");
    kvendra::config::ensure_layout(&kvhome).unwrap();
    let v = Vault::new(kvhome.clone());
    v.create_with_params(
        PASSWORD.as_bytes(),
        KdfParams {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: vec![7u8; 16],
        },
    )
    .unwrap();
    v.unlock(PASSWORD.as_bytes(), 30).unwrap();
    v.put_secret("p", SECRET).unwrap();
    std::fs::write(v.profile_allowlist_path("p"), YAML).unwrap();
    let key = v.allowlist_hmac_key().unwrap();
    save_meta(
        &v,
        "p",
        Some(kvendra::vault::compute_allowlist_hmac(
            &key,
            YAML.as_bytes(),
        )),
    );
    if with_session {
        let out = kvendra(&root)
            .args(["unlock"])
            .env("KVENDRA_PASSWORD", PASSWORD)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "test unlock failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    (dir, root)
}

fn no_secret(out: &std::process::Output) {
    for s in [&out.stdout, &out.stderr] {
        assert!(
            !s.windows(SECRET.len()).any(|w| w == SECRET),
            "secret leaked"
        );
    }
}

#[test]
fn signed_allowlist_with_session_is_valid() {
    let (_d, root) = sandbox(true);
    let out = kvendra(&root)
        .args(["secret", "show-allowlist", "p"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("HMAC: VALID"), "{s}");
    assert!(s.contains("binaries: [\"echo\"]"), "{s}");
    no_secret(&out);

    let out = kvendra(&root)
        .args(["secret", "show-allowlist", "p", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["profile_id"], "p");
    assert_eq!(v["hmac"], "VALID");
    assert_eq!(v["yaml"], YAML);
    no_secret(&out);
}

#[test]
fn altered_yaml_is_tampered() {
    let (_d, root) = sandbox(true);
    let path = root.join("kvhome").join("allowlists").join("p.yaml");
    std::fs::write(&path, YAML.replace("\"echo\"", "\"bash\"")).unwrap();
    let out = kvendra(&root)
        .args(["secret", "show-allowlist", "p", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["hmac"], "TAMPERED");
    no_secret(&out);
}

#[test]
fn missing_hmac_is_no_hmac() {
    let (_d, root) = sandbox(true);
    let v = Vault::new(root.join("kvhome"));
    save_meta(&v, "p", None);
    let out = kvendra(&root)
        .args(["secret", "show-allowlist", "p"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("HMAC: NO_HMAC"));
}

/// Pentest S1b parity: a YAML + valid HMAC copied from profile `p` into `q`
/// is not VALID for `q`.
#[test]
fn allowlist_copied_from_another_profile_is_tampered() {
    let (_d, root) = sandbox(true);
    let v = Vault::new(root.join("kvhome"));
    let hmac = v.load_profile_meta("p").unwrap().allowlist_hmac_hex;
    save_meta(&v, "q", hmac);
    std::fs::copy(v.profile_allowlist_path("p"), v.profile_allowlist_path("q")).unwrap();
    let out = kvendra(&root)
        .args(["secret", "show-allowlist", "q", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let j: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(j["hmac"], "TAMPERED");
}

#[test]
fn locked_vault_prints_yaml_unverified_without_prompt() {
    let (_d, root) = sandbox(false);
    let out = kvendra(&root)
        .args(["secret", "show-allowlist", "p"])
        .write_stdin("")
        .timeout(std::time::Duration::from_secs(30))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("HMAC: no verificado (vault bloqueado)"), "{s}");
    assert!(s.contains("profile_id: p"), "{s}");
    assert!(!s.to_lowercase().contains("password"), "{s}");
    no_secret(&out);

    let out = kvendra(&root)
        .args(["secret", "show-allowlist", "p", "--json"])
        .output()
        .unwrap();
    let j: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(j["hmac"], "UNVERIFIED");
}

#[test]
fn hostile_profile_id_is_refused() {
    let (_d, root) = sandbox(true);
    for id in ["../p", "..", "a/b", "/etc/passwd", ".hidden"] {
        let out = kvendra(&root)
            .args(["secret", "show-allowlist", id])
            .output()
            .unwrap();
        assert!(!out.status.success(), "{id} must be refused");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.to_lowercase().contains("profile"), "{id}: {err}");
        assert!(out.stdout.is_empty(), "{id}: printed {:?}", out.stdout);
    }
}

#[test]
fn hmac_state_core() {
    use kvendra::cli::secret::{AllowlistHmacState as S, allowlist_hmac_state};
    let key = [9u8; 32];
    let good = kvendra::vault::compute_allowlist_hmac(&key, YAML.as_bytes());
    assert_eq!(
        allowlist_hmac_state(None, Some(&good), "p", YAML),
        S::Unverified
    );
    assert_eq!(allowlist_hmac_state(Some(&key), None, "p", YAML), S::NoHmac);
    assert_eq!(
        allowlist_hmac_state(Some(&key), Some(&good), "p", YAML),
        S::Valid
    );
    assert_eq!(
        allowlist_hmac_state(Some(&key), Some(&good), "q", YAML),
        S::Tampered
    );
    assert_eq!(
        allowlist_hmac_state(Some(&key), Some(&good), "p", &format!("{YAML}#x\n")),
        S::Tampered
    );
}

const SENTINEL_CWD: &str = "/kvd-sentinel-home/work-7f3a9c";

/// Re-sign profile `p` with a YAML whose `cwd_pattern` holds the sentinel,
/// and store the sentinel as local variable `ws` in `vars.blob`.
fn sentinel_allowlist(root: &Path) -> String {
    let yaml = format!("{YAML}            cwd_pattern: \"^{SENTINEL_CWD}(/.*)?$\"\n");
    let v = Vault::new(root.join("kvhome"));
    v.unlock(PASSWORD.as_bytes(), 30).unwrap();
    std::fs::write(v.profile_allowlist_path("p"), &yaml).unwrap();
    let key = v.allowlist_hmac_key().unwrap();
    save_meta(
        &v,
        "p",
        Some(kvendra::vault::compute_allowlist_hmac(
            &key,
            yaml.as_bytes(),
        )),
    );
    kvendra::vars::set_var(&v, "ws", kvendra::vars::VarType::String, SENTINEL_CWD, true).unwrap();
    yaml
}

/// Seguridad 0.7.0 — the output goes through the same known-values filter as
/// `kvendra audit`: with the vault unlocked the local value is re-symbolized
/// as `{{lvr:ws}}`, while the HMAC (computed on the original bytes) stays
/// VALID.
#[test]
fn output_resymbolizes_local_values_hmac_on_original() {
    let (_d, root) = sandbox(true);
    sentinel_allowlist(&root);
    for json in [false, true] {
        let mut args = vec!["secret", "show-allowlist", "p"];
        if json {
            args.push("--json");
        }
        let out = kvendra(&root).args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        let s = String::from_utf8_lossy(&out.stdout);
        assert!(!s.contains(SENTINEL_CWD), "json={json} leaked: {s}");
        assert!(s.contains("{{lvr:ws}}"), "json={json}: {s}");
        if json {
            let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(v["hmac"], "VALID");
        } else {
            assert!(s.contains("HMAC: VALID"), "{s}");
        }
        assert!(!String::from_utf8_lossy(&out.stderr).contains(SENTINEL_CWD));
    }
}

/// Vault locked → printed as is (same behaviour as `kvendra audit`).
#[test]
fn locked_vault_output_is_not_resymbolized() {
    let (_d, root) = sandbox(false);
    let yaml = sentinel_allowlist(&root);
    let out = kvendra(&root)
        .args(["secret", "show-allowlist", "p", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["hmac"], "UNVERIFIED");
    assert_eq!(v["yaml"], yaml);
}
