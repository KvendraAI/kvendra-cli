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
        .stdout(contains("secret"))
        .stdout(contains("primitive"))
        .stdout(contains("mcp"))
        .stdout(contains("audit"));
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
