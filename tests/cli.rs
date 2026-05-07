//! Integration tests for the `kvendra` binary.

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

#[test]
fn cli_version() {
    Command::cargo_bin("kvendra")
        .unwrap()
        .arg("--version")
        .assert()
        .success();
}

#[test]
fn cli_help_lists_subcommands() {
    Command::cargo_bin("kvendra")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("init"))
        .stdout(contains("unlock"))
        .stdout(contains("lock"))
        .stdout(contains("recover"))
        .stdout(contains("secret"))
        .stdout(contains("primitive"))
        .stdout(contains("mcp"))
        .stdout(contains("audit"))
        .stdout(contains("dashboard"))
        .stdout(contains("completion"))
        .stdout(contains("config"));
}

#[test]
fn primitive_list_enumerates_canonical_primitives() {
    Command::cargo_bin("kvendra")
        .unwrap()
        .args(["primitive", "list"])
        .assert()
        .success()
        .stdout(contains("kvendra.git"))
        .stdout(contains("kvendra.github"))
        .stdout(contains("kvendra.npm"))
        .stdout(contains("kvendra.pypi"))
        .stdout(contains("kvendra.aws"))
        .stdout(contains("kvendra.http"))
        .stdout(contains("kvendra.shell"))
        .stdout(contains("kvendra.unsafe.raw_token"))
        .stdout(contains("[UNSAFE]"));
}

#[test]
fn completion_bash_emits_script() {
    let assert = Command::cargo_bin("kvendra")
        .unwrap()
        .args(["completion", "bash"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(!stdout.is_empty(), "bash completion script empty");
    assert!(
        stdout.contains("_kvendra"),
        "bash completion missing _kvendra: {stdout}"
    );
}

#[test]
fn completion_zsh_emits_script() {
    Command::cargo_bin("kvendra")
        .unwrap()
        .args(["completion", "zsh"])
        .assert()
        .success()
        .stdout(contains("_kvendra"));
}

#[test]
fn completion_fish_emits_script() {
    Command::cargo_bin("kvendra")
        .unwrap()
        .args(["completion", "fish"])
        .assert()
        .success()
        .stdout(contains("kvendra"));
}

// ---- REQ-KVD-005 / ISSUE-KVD-CLI-017 ----
//
// `fetch` removed; `migrate-to-keychain-acl` added; `mcp serve --use-keychain`
// added (mutually exclusive with `--password-env` / `--no-unlock`).

#[test]
fn config_mcp_password_fetch_subcommand_removed() {
    Command::cargo_bin("kvendra")
        .unwrap()
        .args(["config", "mcp-password", "fetch"])
        .assert()
        .failure()
        .stderr(contains("unrecognized subcommand").or(contains("error")));
}

#[test]
fn config_mcp_password_help_lists_new_subcommands() {
    Command::cargo_bin("kvendra")
        .unwrap()
        .args(["config", "mcp-password", "--help"])
        .assert()
        .success()
        .stdout(contains("enable"))
        .stdout(contains("migrate-to-keychain-acl"))
        .stdout(contains("status"))
        .stdout(contains("disable"));
}

#[test]
fn config_mcp_password_help_does_not_list_fetch() {
    let assert = Command::cargo_bin("kvendra")
        .unwrap()
        .args(["config", "mcp-password", "--help"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(
        !stdout.contains(" fetch "),
        "fetch subcommand still listed in help: {stdout}"
    );
}

#[test]
fn mcp_serve_help_lists_use_keychain_flag() {
    Command::cargo_bin("kvendra")
        .unwrap()
        .args(["mcp", "serve", "--help"])
        .assert()
        .success()
        .stdout(contains("--use-keychain"));
}

#[test]
fn mcp_serve_use_keychain_conflicts_with_password_env() {
    // clap should reject combining --use-keychain with --password-env.
    Command::cargo_bin("kvendra")
        .unwrap()
        .args([
            "mcp",
            "serve",
            "--use-keychain",
            "--password-env",
            "ignored",
        ])
        .assert()
        .failure()
        .stderr(contains("cannot be used with").or(contains("conflict")));
}

#[test]
fn mcp_serve_use_keychain_conflicts_with_no_unlock() {
    Command::cargo_bin("kvendra")
        .unwrap()
        .args(["mcp", "serve", "--use-keychain", "--no-unlock"])
        .assert()
        .failure()
        .stderr(contains("cannot be used with").or(contains("conflict")));
}

/// E2E regression for the bug uncovered by the alpha.7 smoke (caveat E2E-D-1):
/// `kvendra secret set-allowlist <profile> --file <yaml>` post-REQ-007 needs
/// the `kvendra/allowlist-hmac/v1` HKDF sub-key, which only exists while the
/// session is unlocked. The pre-fix dispatcher invoked `set_allowlist` without
/// an `ensure_unlocked` call, so any caller hit `KvendraError::VaultLocked`.
/// The fix wires `ensure_unlocked` (env-var or `--password-stdin`) through the
/// CLI command, and this test exercises the full subprocess path that the
/// previous unit tests bypassed by calling helpers directly.
///
/// Slow (Argon2id high-cost on init); opt-in with `cargo test -- --include-ignored`.
#[cfg(unix)]
#[test]
#[ignore = "slow argon2 cost — opt-in via `cargo test -- --include-ignored`"]
fn secret_set_allowlist_unlocks_vault_via_env_var() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    // Bootstrap the vault — same env vars used by the smoke harness.
    Command::cargo_bin("kvendra")
        .unwrap()
        .args(["init", "--no-verify"])
        .env("KVENDRA_HOME", home)
        .env("KVENDRA_INIT_PASSWORD", "hunter2-set-allowlist-cli")
        .env("KVENDRA_INIT_CONFIRM_CODE", "0")
        .assert()
        .success();
    // Create a profile.
    Command::cargo_bin("kvendra")
        .unwrap()
        .args([
            "secret",
            "add",
            "smoke.gh",
            "--secret-type",
            "github_pat",
            "--secret-env",
            "FAKE_TOKEN",
        ])
        .env("KVENDRA_HOME", home)
        .env("KVENDRA_PASSWORD", "hunter2-set-allowlist-cli")
        .env("FAKE_TOKEN", "ghp_fakefakefake1234567890aBcDeFgHiJkLmN")
        .assert()
        .success();
    // Write a minimal allowlist YAML to a temp file.
    let yaml_path = dir.path().join("allowlist.yaml");
    let mut f = std::fs::File::create(&yaml_path).unwrap();
    f.write_all(
        b"profile_id: smoke.gh\n\
          secret:\n  type: github_pat\n\
          allowlist:\n  primitives:\n    - name: kvendra.git\n      operations:\n        - pull:\n            repos: [\"github.com/KvendraAI/*\"]\n",
    )
    .unwrap();
    // The fix under test: the dispatcher must unlock the vault using
    // KVENDRA_PASSWORD before computing the allowlist HMAC.
    Command::cargo_bin("kvendra")
        .unwrap()
        .args([
            "secret",
            "set-allowlist",
            "smoke.gh",
            "--file",
            yaml_path.to_str().unwrap(),
        ])
        .env("KVENDRA_HOME", home)
        .env("KVENDRA_PASSWORD", "hunter2-set-allowlist-cli")
        .assert()
        .success()
        .stdout(contains("HMAC persisted"));
    // Sanity-check the on-disk profile meta has the new field populated.
    let meta_raw = std::fs::read_to_string(home.join("profiles/smoke.gh.json")).unwrap();
    assert!(
        meta_raw.contains("allowlist_hmac_hex"),
        "profile meta JSON missing allowlist_hmac_hex after set-allowlist: {meta_raw}"
    );
}

/// E2E regression for the bug uncovered by the alpha.8 smoke (caveat E2E-B-2):
/// `Config::load(home, None)` returned `Err("cannot verify")` for any signed
/// `config.toml` (every alpha.7+ vault), and `kvendra unlock` swallowed it via
/// `unwrap_or_default()`. The fallback `Config::default()` clobbered every
/// user-set preference (most notably `master_password_cache: os-keychain`),
/// silently disabling the REQ-005 keychain fast-path from alpha.7 onwards.
///
/// The fix lets `Config::load(.., None)` parse signed configs without
/// verifying — the post-unlock load (`Config::load(.., Some(&vault))`) still
/// enforces the HMAC and home_canonical checks. This test drives the full
/// `kvendra unlock` subprocess against a vault with `os-keychain` selected
/// and asserts that the cache mode survives the bootstrap path.
///
/// Slow (Argon2id high-cost on init); opt-in with `cargo test -- --include-ignored`.
#[cfg(unix)]
#[test]
#[ignore = "slow argon2 cost — opt-in via `cargo test -- --include-ignored`"]
fn unlock_preserves_user_preferences_from_signed_config() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    Command::cargo_bin("kvendra")
        .unwrap()
        .args(["init", "--no-verify"])
        .env("KVENDRA_HOME", home)
        .env("KVENDRA_INIT_PASSWORD", "hunter2-pref-preservation")
        .env("KVENDRA_INIT_CONFIRM_CODE", "0")
        .assert()
        .success();
    // Flip master_password_cache to os-keychain via the CLI subcommand
    // (this is the same path a real user would take).
    Command::cargo_bin("kvendra")
        .unwrap()
        .args(["config", "keychain", "enable"])
        .env("KVENDRA_HOME", home)
        .env("KVENDRA_PASSWORD", "hunter2-pref-preservation")
        .assert()
        .success();
    // Confirm that the signed config really has the new cache mode (sanity).
    let cfg = std::fs::read_to_string(home.join("config.toml")).unwrap();
    assert!(
        cfg.contains("master_password_cache = \"os-keychain\""),
        "config.toml did not flip cache mode: {cfg}"
    );
    // The pre-fix bug: `kvendra unlock` would reload the signed config with
    // None vault, hit "cannot verify", and revert the cache mode to RamOnly.
    // Post-fix: unlock should preserve the os-keychain setting through the
    // bootstrap path. We assert that by verifying the post-unlock keychain
    // status reports the user's preference correctly (not the default).
    Command::cargo_bin("kvendra")
        .unwrap()
        .args(["unlock"])
        .env("KVENDRA_HOME", home)
        .env("KVENDRA_PASSWORD", "hunter2-pref-preservation")
        .assert()
        .success();
    let assert = Command::cargo_bin("kvendra")
        .unwrap()
        .args(["config", "keychain", "status"])
        .env("KVENDRA_HOME", home)
        .env("KVENDRA_PASSWORD", "hunter2-pref-preservation")
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(
        stdout.contains("OsKeychain"),
        "post-unlock cache mode reverted to RamOnly (E2E-B-2 regression): {stdout}"
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn config_mcp_password_enable_rejects_on_non_macos() {
    // REQ-KVD-005 AC-USE-KEYCHAIN-4: explicit reject on Windows / Linux to
    // avoid a false sense of biometric protection. Workaround = env var.
    let assert = Command::cargo_bin("kvendra")
        .unwrap()
        .args(["config", "mcp-password", "enable"])
        .write_stdin("anything\n")
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(
        stderr.to_lowercase().contains("macos")
            || stderr.contains("KVENDRA_MCP_PASSWORD")
            || stderr.contains("not available"),
        "expected macOS-only / unavailable message, got: {stderr}"
    );
}
