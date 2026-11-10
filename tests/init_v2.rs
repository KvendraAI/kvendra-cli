//! REQ-KVD-CLI-CFB449 F2 (ISSUE-KVD-CLI-E73A9E) — `kvendra init` builds a
//! v2 vault + recovery.blob transactionally (AC-REC-10).
//!
//! Every run uses a fresh tempdir as `KVENDRA_HOME` and `HOME`. Fault and
//! crash injection tests need `--features test-hooks`.

use assert_cmd::Command;
use kvendra::vault::Vault;
use kvendra::vault::envelope::{Sentinel, parse_phrase};
use std::path::Path;

const PW: &str = "kvd-init-v2-password";

fn init_cmd(home: &Path) -> Command {
    let mut c = Command::cargo_bin("kvendra").unwrap();
    c.args(["init", "--no-verify"])
        .env("KVENDRA_HOME", home)
        .env("HOME", home)
        .env("KVENDRA_INIT_PASSWORD", PW)
        .env_remove("KVENDRA_TEST_FAIL_AT")
        .env_remove("KVENDRA_TEST_CRASH_AT");
    c
}

fn phrase_from_stdout(stdout: &str) -> String {
    let mut lines = stdout.lines();
    while let Some(l) = lines.next() {
        if l.starts_with("BIP-39 mnemonic") {
            return lines.next().unwrap().trim().to_string();
        }
    }
    panic!("no mnemonic in stdout");
}

fn assert_v2_vault_bound_to(home: &Path, phrase: &str) {
    let v = Vault::new(home.to_path_buf());
    let Sentinel::V2(s) = v.read_sentinel().unwrap() else {
        panic!("init must write sentinel v2");
    };
    let r = v.read_recovery_blob().unwrap();
    assert_eq!(r.version, 1);
    assert_eq!(r.vault_id, s.vault_id, "same vault_id in both files");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [
            v.sentinel_path(),
            v.recovery_blob_path(),
            v.recovery_codes_path(),
        ] {
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    let mk = v.open_recovery(&parse_phrase(phrase).unwrap()).unwrap();
    v.unlock(PW.as_bytes(), 30).unwrap();
    assert_eq!(&v.peek_session_derived_key().unwrap(), mk.as_bytes());
}

/// AC-REC-10 + banner + final message (production Argon2id cost: one run).
#[test]
fn init_writes_v2_vault_bound_to_the_shown_phrase() {
    let dir = tempfile::tempdir().unwrap();
    let out = init_cmd(dir.path())
        .env_remove("KVENDRA_TEST_FAST_KDF")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let phrase = phrase_from_stdout(&stdout);
    assert_eq!(phrase.split(' ').count(), 12);
    assert_v2_vault_bound_to(dir.path(), &phrase);
    assert!(stdout.contains("What the 12 words do: they recover access to THIS vault"));
    assert!(
        stdout.contains("What the 8 codes do: they authorise `kvendra config rebind-home` only.")
    );
    assert!(stdout.contains("They do NOT recover a forgotten password."));
    assert!(stdout.contains("Recovery phrase bound to this vault (recovery.blob)."));
    // D1 — 0.9.0 cannot restore onto a new machine with backup + phrase.
    assert!(!stdout.contains("restored from"), "{stdout}");
    assert!(!stdout.contains("on a new one"), "{stdout}");
    let v = Vault::new(dir.path().to_path_buf());
    let Sentinel::V2(s) = v.read_sentinel().unwrap() else {
        unreachable!()
    };
    assert_eq!(
        (s.kdf.m_cost_kib, s.kdf.t_cost, s.kdf.p_cost),
        (65_536, 3, 1)
    );

    // init.rs:81 — second init refuses with the new text.
    let again = init_cmd(dir.path()).output().unwrap();
    assert!(!again.status.success());
    let err = String::from_utf8_lossy(&again.stderr);
    assert!(
        err.contains("kvendra recover") && err.contains("kvendra passwd"),
        "{err}"
    );
    assert!(!err.contains("to rotate the master password"), "{err}");
}

/// A wrong confirmation code aborts before any vault write and removes the
/// `--save-to` file this run created.
#[test]
fn aborted_confirmation_writes_nothing_and_removes_save_to() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let save = dir.path().join("codes.txt");
    let out = Command::cargo_bin("kvendra")
        .unwrap()
        .args(["init", "--save-to"])
        .arg(&save)
        .env("KVENDRA_HOME", &home)
        .env("HOME", dir.path())
        .env("KVENDRA_INIT_PASSWORD", PW)
        .env("KVENDRA_INIT_CONFIRM_CODE", "0000-0000-00")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!save.exists(), "--save-to must be removed on abort");
    for f in [
        "sentinel.blob",
        "recovery.blob",
        "recovery_codes.json",
        "config.toml",
        "audit.db",
    ] {
        assert!(!home.join(f).exists(), "{f} written on abort");
    }
}

#[cfg(feature = "test-hooks")]
mod hooks {
    use super::*;

    const STEPS: &[&str] = &[
        "init.before_recovery_codes",
        "init.after_recovery_codes",
        "init.before_recovery_blob",
        "init.after_recovery_blob",
        "init.before_audit",
        "init.after_audit",
        "init.before_config",
        "init.after_config",
        "init.before_sentinel_commit",
        "init.before_sentinel_rename",
    ];

    fn fast(c: &mut Command) -> &mut Command {
        c.env("KVENDRA_TEST_FAST_KDF", "1")
    }

    fn assert_no_vault(home: &Path) {
        for f in [
            "sentinel.blob",
            "sentinel.blob.init-tmp",
            "recovery.blob",
            "recovery_codes.json",
            "config.toml",
            "audit.db",
            "audit.db-wal",
            "audit.db-shm",
        ] {
            assert!(!home.join(f).exists(), "{f} left after rollback");
        }
    }

    /// AC-REC-10 / AC-REC-5 — a failure injected at every write step rolls
    /// everything back (including `--save-to`); a later init succeeds.
    #[test]
    fn injected_failure_at_each_step_rolls_back() {
        for step in STEPS {
            let dir = tempfile::tempdir().unwrap();
            let home = dir.path().join("home");
            let save = dir.path().join("codes.txt");
            let out = fast(&mut init_cmd(&home))
                .arg("--save-to")
                .arg(&save)
                .env("KVENDRA_TEST_FAIL_AT", step)
                .output()
                .unwrap();
            assert!(!out.status.success(), "{step}: init must fail");
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("injected failure"),
                "{step}"
            );
            assert_no_vault(&home);
            assert!(!save.exists(), "{step}: --save-to must be removed");
            let ok = fast(&mut init_cmd(&home)).output().unwrap();
            assert!(ok.status.success(), "{step}: retry failed");
            assert_v2_vault_bound_to(
                &home,
                &phrase_from_stdout(&String::from_utf8_lossy(&ok.stdout)),
            );
            assert!(
                !std::fs::read_dir(&home).unwrap().any(|e| e
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".init-orphans")),
                "{step}: rollback must leave nothing to quarantine"
            );
        }
    }

    /// A crash (no rollback ran) at every step never leaves a usable-looking
    /// half vault: no sentinel. The next init quarantines the leftovers in
    /// `.init-orphans-*` (never deletes them) and succeeds.
    #[test]
    fn crash_at_each_step_is_recovered_by_next_init() {
        for step in STEPS {
            let dir = tempfile::tempdir().unwrap();
            let home = dir.path().join("home");
            let out = fast(&mut init_cmd(&home))
                .env("KVENDRA_TEST_CRASH_AT", step)
                .output()
                .unwrap();
            assert_eq!(
                out.status.code(),
                Some(kvendra::fault::CRASH_EXIT_CODE),
                "{step}"
            );
            assert!(
                !home.join("sentinel.blob").exists(),
                "{step}: sentinel before commit"
            );
            let leftovers: Vec<String> = std::fs::read_dir(&home)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|n| {
                    n.starts_with("recovery")
                        || n.starts_with("audit")
                        || n.starts_with("config")
                        || n.starts_with("sentinel")
                })
                .collect();
            let ok = fast(&mut init_cmd(&home)).output().unwrap();
            assert!(
                ok.status.success(),
                "{step}: {}",
                String::from_utf8_lossy(&ok.stderr)
            );
            assert_v2_vault_bound_to(
                &home,
                &phrase_from_stdout(&String::from_utf8_lossy(&ok.stdout)),
            );
            if !leftovers.is_empty() {
                let orphans = std::fs::read_dir(&home)
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .find(|p| {
                        p.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with(".init-orphans-")
                    })
                    .unwrap_or_else(|| panic!("{step}: leftovers {leftovers:?} not quarantined"));
                for n in &leftovers {
                    assert!(orphans.join(n).exists(), "{step}: {n} lost");
                }
                assert!(String::from_utf8_lossy(&ok.stderr).contains("aborted `kvendra init`"));
            }
        }
    }

    /// `--save-to` holds the same content shape as 0.8.0.
    #[test]
    fn save_to_content_matches_banner() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let save = dir.path().join("codes.txt");
        let out = fast(&mut init_cmd(&home))
            .arg("--save-to")
            .arg(&save)
            .output()
            .unwrap();
        assert!(out.status.success());
        let stdout = String::from_utf8_lossy(&out.stdout);
        let phrase = phrase_from_stdout(&stdout);
        let content = std::fs::read_to_string(&save).unwrap();
        let mut lines = content.lines();
        assert_eq!(
            lines.next(),
            Some("# kvendra recovery codes — KEEP THIS FILE OFFLINE")
        );
        assert_eq!(lines.next(), Some(format!("mnemonic: {phrase}").as_str()));
        assert_eq!(lines.next(), Some("codes:"));
        let codes: Vec<&str> = lines.map(|l| l.trim_start_matches("  - ")).collect();
        assert_eq!(codes.len(), 8);
        for c in codes {
            assert!(stdout.contains(&format!("    {c}")));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&save).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    /// M1 — a symlink or an existing file at `--save-to` is refused untouched
    /// and nothing of the vault is written; a failure right after the file
    /// was created removes it.
    #[cfg(unix)]
    #[test]
    fn save_to_symlink_or_existing_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let target = dir.path().join("victim.txt");
        std::fs::write(&target, b"kvd-victim").unwrap();
        let link = dir.path().join("codes-link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        for save in [link.clone(), target.clone()] {
            let out = fast(&mut init_cmd(&home))
                .arg("--save-to")
                .arg(&save)
                .output()
                .unwrap();
            assert!(!out.status.success());
            assert!(String::from_utf8_lossy(&out.stderr).contains("refusing to write --save-to"));
            assert_eq!(std::fs::read(&target).unwrap(), b"kvd-victim");
            assert_no_vault(&home);
        }
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );

        let save = dir.path().join("codes.txt");
        let out = fast(&mut init_cmd(&home))
            .arg("--save-to")
            .arg(&save)
            .env("KVENDRA_TEST_FAIL_AT", "init.after_save_to")
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(
            !save.exists(),
            "a failure after creating --save-to must remove it"
        );
        assert_no_vault(&home);
    }

    /// M2 — two concurrent inits on one home: exactly one vault, coherent
    /// (the winner's phrase recovers it, its password opens it).
    #[test]
    fn concurrent_inits_leave_exactly_one_coherent_vault() {
        for _ in 0..3 {
            let dir = tempfile::tempdir().unwrap();
            let home = dir.path().join("home");
            std::fs::create_dir_all(&home).unwrap();
            let spawn = || {
                let mut c = std::process::Command::new(assert_cmd::cargo::cargo_bin("kvendra"));
                c.args(["init", "--no-verify"])
                    .env("KVENDRA_HOME", &home)
                    .env("HOME", &home)
                    .env("KVENDRA_INIT_PASSWORD", PW)
                    .env("KVENDRA_TEST_FAST_KDF", "1")
                    .env_remove("KVENDRA_TEST_FAIL_AT")
                    .env_remove("KVENDRA_TEST_CRASH_AT")
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped());
                c.spawn().unwrap()
            };
            let (a, b) = (spawn(), spawn());
            let outs = [a.wait_with_output().unwrap(), b.wait_with_output().unwrap()];
            let ok: Vec<_> = outs.iter().filter(|o| o.status.success()).collect();
            assert_eq!(ok.len(), 1, "exactly one init must win");
            let loser = outs.iter().find(|o| !o.status.success()).unwrap();
            let err = String::from_utf8_lossy(&loser.stderr);
            assert!(
                err.contains("another `kvendra init` is running")
                    || err.contains("already initialized"),
                "{err}"
            );
            assert_v2_vault_bound_to(
                &home,
                &phrase_from_stdout(&String::from_utf8_lossy(&ok[0].stdout)),
            );
        }
    }
}
