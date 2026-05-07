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
