//! Integration tests for the `kvendra` binary.

use assert_cmd::Command;
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
