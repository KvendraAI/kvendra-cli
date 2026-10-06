//! ISSUE-KVD-CLI-C7A858 — path traversal through `profile_id` in
//! `kvendra secret <add|rotate|revoke|get-meta|validate|set-allowlist>` and in
//! the `Vault` layer (`src/vault/mod.rs` `profile_{blob,meta,allowlist}_path`).
//!
//! The MCP dispatcher validates `profile_id` with the shared canonicalizer
//! (`crate::path_id::is_safe_path_component`, PAT-KVD-CLI-C18A74) before it
//! reaches a vault path, but the local `kvendra secret` CLI and the `Vault`
//! methods themselves interpolate the raw identifier into
//! `secrets/<id>.blob`, `profiles/<id>.json` and `allowlists/<id>.yaml`.
//!
//! These tests express the behaviour EXPECTED AFTER THE FIX:
//!   * every hostile `profile_id` is refused with an explicit validation
//!     error (not an incidental ENOENT / ENAMETOOLONG / NUL io error),
//!   * the refusal happens BEFORE the master password is requested and
//!     BEFORE `--file` is read,
//!   * the sandbox tree (home + outside + abs targets) is byte-identical
//!     before and after the command,
//!   * the legitimate control identifiers keep working (FLOW-8 / C1).
//!
//! RED at 0f65bf9 (the bug). FLOW-8 and the FLOW-9 control are GREEN today.
//!
//! ISOLATION (hard rule): every test runs inside a `tempfile::tempdir()`
//! `T` with `T/home` as `KVENDRA_HOME`, `T/outside` and `T/abs` as escape
//! targets; subprocesses get a CLEARED environment with
//! `KVENDRA_HOME=T/home` and `HOME=T`. `assert_sandboxed` guards that the
//! home hangs from the system temp dir and is never the real `~/.kvendra`.

use assert_cmd::Command;
use kvendra::vault::Vault;
use kvendra::vault::kdf::KdfParams;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const PW: &str = "hunter2-c7a858";

// ─────────────────────────────────────────────────────────────────────────
// Sandbox
// ─────────────────────────────────────────────────────────────────────────

struct Sandbox {
    tmp: TempDir,
}

impl Sandbox {
    /// `T/home` = initialised vault (fast Argon2id), `T/outside`, `T/abs`.
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sb = Sandbox { tmp };
        sb.assert_sandboxed();
        std::fs::create_dir_all(sb.outside()).unwrap();
        std::fs::create_dir_all(sb.abs()).unwrap();
        kvendra::config::ensure_layout(&sb.home()).unwrap();
        let v = Vault::new(sb.home());
        v.create_with_params(
            PW.as_bytes(),
            KdfParams {
                m_cost_kib: 19_456,
                t_cost: 2,
                p_cost: 1,
                salt: vec![7u8; 16],
            },
        )
        .unwrap();
        sb
    }

    fn root(&self) -> PathBuf {
        self.tmp.path().to_path_buf()
    }
    fn home(&self) -> PathBuf {
        self.root().join("home")
    }
    fn outside(&self) -> PathBuf {
        self.root().join("outside")
    }
    fn abs(&self) -> PathBuf {
        self.root().join("abs")
    }

    /// Guard: the vault home MUST hang from the system temp dir and MUST NOT
    /// be the owner's real `~/.kvendra`.
    fn assert_sandboxed(&self) {
        let sys_tmp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let root = std::fs::canonicalize(self.root()).unwrap();
        assert!(
            root.starts_with(&sys_tmp),
            "sandbox root {root:?} is not under the system temp dir {sys_tmp:?}"
        );
        if let Some(h) = std::env::var_os("HOME") {
            let real = PathBuf::from(h).join(".kvendra");
            assert_ne!(self.home(), real, "sandbox home is the REAL ~/.kvendra");
            assert!(!self.home().starts_with(&real));
        }
    }

    /// `kvendra` subprocess with a CLEARED environment pinned to the sandbox.
    fn cmd(&self, with_password: bool) -> Command {
        self.assert_sandboxed();
        let mut c = Command::cargo_bin("kvendra").unwrap();
        c.env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("TMPDIR", std::env::temp_dir())
            .env("HOME", self.root())
            .env("KVENDRA_HOME", self.home())
            .env("KVD_TEST_SECRET", "s3cr3t-c7a858-plaintext")
            .current_dir(self.root())
            .write_stdin("");
        if with_password {
            c.env("KVENDRA_PASSWORD", PW);
        }
        c
    }

    /// Recursive snapshot of the WHOLE sandbox: relative path → bytes
    /// (directories recorded with an empty marker).
    fn snapshot(&self) -> BTreeMap<String, Option<Vec<u8>>> {
        fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Option<Vec<u8>>>) {
            let Ok(rd) = std::fs::read_dir(dir) else {
                return;
            };
            for e in rd.flatten() {
                let p = e.path();
                let rel = p.strip_prefix(base).unwrap().to_string_lossy().into_owned();
                let ft = e.file_type().unwrap();
                if ft.is_dir() {
                    out.insert(format!("{rel}/"), None);
                    walk(base, &p, out);
                } else {
                    out.insert(rel, Some(std::fs::read(&p).unwrap_or_default()));
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(&self.root(), &self.root(), &mut out);
        out
    }

    fn write_bait(&self, path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }
}

/// Human-readable diff of two snapshots (created / deleted / modified).
fn diff(
    before: &BTreeMap<String, Option<Vec<u8>>>,
    after: &BTreeMap<String, Option<Vec<u8>>>,
) -> Vec<String> {
    let mut d = Vec::new();
    for (k, v) in after {
        match before.get(k) {
            None => d.push(format!("CREATED  {k}")),
            Some(b) if b != v => d.push(format!("MODIFIED {k}")),
            _ => {}
        }
    }
    for k in before.keys() {
        if !after.contains_key(k) {
            d.push(format!("DELETED  {k}"));
        }
    }
    d
}

/// Hostile payload matrix (P1-P12 minus P8 NUL, which argv cannot carry —
/// covered in FLOW-9). `<T>` is substituted with the sandbox root.
fn hostile_payloads(sb: &Sandbox) -> Vec<(&'static str, String)> {
    vec![
        ("P1", "../x".into()),
        ("P2", "../../outside/y".into()),
        ("P3", "a/b".into()),
        ("P4", "..".into()),
        ("P5", ".".into()),
        ("P6", ".hidden".into()),
        ("P7", sb.abs().join("z").to_string_lossy().into_owned()),
        ("P9", "a\\b".into()),
        ("P10a", "\u{2025}x".into()), // ‥x (two-dot leader)
        ("P10b", "\u{FF0E}\u{FF0E}\u{FF0F}x".into()), // ．．／x (fullwidth)
        ("P10c", "plantilla\u{00F1}".into()), // plantillañ
        ("P11a", "a".repeat(129)),
        ("P11b", "a".repeat(251)),
        ("P12a", "a..b".into()),
        ("P12b", "x/../y".into()),
    ]
}

const IO_LEAK_MARKERS: &[&str] = &[
    "No such file",
    "File name too long",
    "os error",
    "Not a directory",
    "Is a directory",
];

/// Outcome check shared by every subprocess flow. Returns `None` when the
/// command behaved as expected after the fix, or a description of the
/// deviation (used to build the RED report).
fn check_refused(
    label: &str,
    out: &std::process::Output,
    before: &BTreeMap<String, Option<Vec<u8>>>,
    after: &BTreeMap<String, Option<Vec<u8>>>,
    forbidden_stdout: &[&str],
) -> Option<String> {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let both = format!("{stdout}\n{stderr}");
    let mut problems = Vec::new();
    if out.status.success() {
        problems.push("exit 0 (accepted)".to_string());
    }
    let d = diff(before, after);
    if !d.is_empty() {
        problems.push(format!("sandbox changed: {d:?}"));
    }
    if !both.to_lowercase().contains("profile_id") && !both.to_lowercase().contains("profile id") {
        problems.push("no explicit profile_id validation error".to_string());
    }
    for m in IO_LEAK_MARKERS {
        if both.contains(m) {
            problems.push(format!("incidental io error leaked ({m:?})"));
        }
    }
    for m in forbidden_stdout {
        if stdout.contains(m) {
            problems.push(format!("stdout leaked {m:?}"));
        }
    }
    if problems.is_empty() {
        None
    } else {
        Some(format!(
            "[{label}] {} | status={:?} | stderr={:?}",
            problems.join("; "),
            out.status.code(),
            stderr.trim()
        ))
    }
}

fn finish(flow: &str, failures: Vec<String>) {
    assert!(
        failures.is_empty(),
        "{flow}: {} hostile profile_id case(s) NOT refused cleanly:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn allowlist_yaml(profile_id: &str) -> String {
    format!(
        "profile_id: {profile_id:?}\n\
         secret:\n  type: generic\n\
         allowlist:\n  primitives:\n    - name: kvendra.shell\n      operations:\n        - exec:\n            binaries: [\"echo\"]\n            accept_destructive: true\n"
    )
}

fn profile_json(profile_id: &str, secret_type: &str) -> String {
    format!(
        "{{\"profile_id\":{profile_id:?},\"secret_type\":{secret_type:?},\
          \"created_at\":\"2026-10-06\",\"expiration\":null}}"
    )
}

// ─────────────────────────────────────────────────────────────────────────
// FLOW-1 — `secret add`
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn flow1_secret_add_refuses_hostile_profile_id_without_touching_disk() {
    let sb = Sandbox::new();
    let mut failures = Vec::new();
    for (label, id) in hostile_payloads(&sb) {
        let before = sb.snapshot();
        let out = sb
            .cmd(true)
            .args(["secret", "add", &id, "--secret-env", "KVD_TEST_SECRET"])
            .output()
            .unwrap();
        let after = sb.snapshot();
        if let Some(f) = check_refused(label, &out, &before, &after, &[]) {
            failures.push(f);
        }
    }
    finish("FLOW-1 add", failures);
}

/// The refusal must happen BEFORE the master password is requested: with no
/// `KVENDRA_PASSWORD` and an empty `--password-stdin`, the error must be the
/// profile_id validation, not a password / unlock failure.
#[test]
fn flow1_secret_add_rejects_before_asking_master_password() {
    let sb = Sandbox::new();
    let mut failures = Vec::new();
    for (label, id) in [("P1", "../x"), ("P2", "../../outside/y")] {
        let before = sb.snapshot();
        let out = sb
            .cmd(false)
            .args([
                "secret",
                "add",
                id,
                "--secret-env",
                "KVD_TEST_SECRET",
                "--password-stdin",
            ])
            .output()
            .unwrap();
        let after = sb.snapshot();
        let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
        if stderr.contains("password") {
            failures.push(format!(
                "[{label}] password path reached before id validation: {stderr:?}"
            ));
        }
        if let Some(f) = check_refused(label, &out, &before, &after, &[]) {
            failures.push(f);
        }
    }
    finish("FLOW-1 add (pre-password)", failures);
}

// ─────────────────────────────────────────────────────────────────────────
// FLOW-2 — `secret rotate` (bait T/outside/pwn.blob must survive)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn flow2_secret_rotate_must_not_overwrite_blob_outside_vault() {
    let sb = Sandbox::new();
    let bait = sb.outside().join("pwn.blob");
    sb.write_bait(&bait, "BAIT-ROTATE-ORIGINAL");
    let before = sb.snapshot();
    let out = sb
        .cmd(true)
        .args([
            "secret",
            "rotate",
            "../../outside/pwn",
            "--secret-env",
            "KVD_TEST_SECRET",
        ])
        .output()
        .unwrap();
    let after = sb.snapshot();
    let bait_now = std::fs::read_to_string(&bait).unwrap_or_default();
    let mut failures = Vec::new();
    if bait_now != "BAIT-ROTATE-ORIGINAL" {
        failures.push(format!(
            "[bait] T/outside/pwn.blob OVERWRITTEN with a vault blob ({} bytes)",
            bait_now.len()
        ));
    }
    if let Some(f) = check_refused("P2-bait", &out, &before, &after, &[]) {
        failures.push(f);
    }
    for (label, id) in hostile_payloads(&sb) {
        let before = sb.snapshot();
        let out = sb
            .cmd(true)
            .args(["secret", "rotate", &id, "--secret-env", "KVD_TEST_SECRET"])
            .output()
            .unwrap();
        let after = sb.snapshot();
        if let Some(f) = check_refused(label, &out, &before, &after, &[]) {
            failures.push(f);
        }
    }
    finish("FLOW-2 rotate", failures);
}

// ─────────────────────────────────────────────────────────────────────────
// FLOW-3 — `secret revoke` (NO password required → max impact)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn flow3_secret_revoke_must_not_delete_files_outside_vault() {
    let sb = Sandbox::new();
    for ext in ["blob", "json", "yaml"] {
        sb.write_bait(&sb.outside().join(format!("pwn.{ext}")), "BAIT-REVOKE");
    }
    let before = sb.snapshot();
    let out = sb
        .cmd(false)
        .args(["secret", "revoke", "../../outside/pwn"])
        .output()
        .unwrap();
    let after = sb.snapshot();
    let mut failures = Vec::new();
    for ext in ["blob", "json", "yaml"] {
        if !sb.outside().join(format!("pwn.{ext}")).exists() {
            failures.push(format!("[bait] T/outside/pwn.{ext} DELETED (no password)"));
        }
    }
    if let Some(f) = check_refused("P2-bait", &out, &before, &after, &[]) {
        failures.push(f);
    }
    finish("FLOW-3 revoke (outside)", failures);
}

/// Maximum impact: `revoke ../sentinel` resolves `secrets/../sentinel.blob`
/// = the master-password sentinel. Without it the vault cannot be unlocked
/// any more (every stored secret becomes unrecoverable). No password needed.
#[test]
fn flow3_secret_revoke_must_not_delete_vault_sentinel() {
    let sb = Sandbox::new();
    let sentinel = sb.home().join("sentinel.blob");
    assert!(sentinel.exists(), "precondition: sentinel present");
    let before = sb.snapshot();
    let out = sb
        .cmd(false)
        .args(["secret", "revoke", "../sentinel"])
        .output()
        .unwrap();
    let after = sb.snapshot();
    let mut failures = Vec::new();
    if !sentinel.exists() {
        // Prove the consequence: the vault is bricked.
        let unlock = Vault::new(sb.home()).unlock(PW.as_bytes(), 5);
        failures.push(format!(
            "[sentinel] T/home/sentinel.blob DELETED without password — vault bricked \
             (unlock now: {unlock:?})"
        ));
    }
    if let Some(f) = check_refused("../sentinel", &out, &before, &after, &[]) {
        failures.push(f);
    }
    finish("FLOW-3 revoke (sentinel)", failures);
}

#[test]
fn flow3_secret_revoke_must_not_delete_recovery_blob() {
    let sb = Sandbox::new();
    let recovery = sb.home().join("recovery.blob");
    sb.write_bait(&recovery, "BAIT-RECOVERY");
    let before = sb.snapshot();
    let out = sb
        .cmd(false)
        .args(["secret", "revoke", "../recovery"])
        .output()
        .unwrap();
    let after = sb.snapshot();
    let mut failures = Vec::new();
    if !recovery.exists() {
        failures.push("[recovery] T/home/recovery.blob DELETED without password".into());
    }
    if let Some(f) = check_refused("../recovery", &out, &before, &after, &[]) {
        failures.push(f);
    }
    finish("FLOW-3 revoke (recovery)", failures);
}

#[test]
fn flow3_secret_revoke_refuses_hostile_profile_id_matrix() {
    let sb = Sandbox::new();
    let mut failures = Vec::new();
    for (label, id) in hostile_payloads(&sb) {
        let before = sb.snapshot();
        let out = sb
            .cmd(false)
            .args(["secret", "revoke", &id])
            .output()
            .unwrap();
        let after = sb.snapshot();
        if let Some(f) = check_refused(label, &out, &before, &after, &[]) {
            failures.push(f);
        }
    }
    finish("FLOW-3 revoke (matrix)", failures);
}

// ─────────────────────────────────────────────────────────────────────────
// FLOW-4 — `secret get-meta` (no password; reads external JSON)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn flow4_secret_get_meta_must_not_read_json_outside_vault() {
    let sb = Sandbox::new();
    sb.write_bait(
        &sb.outside().join("leak.json"),
        &profile_json("leak", "LEAKMARKER_GETMETA"),
    );
    let mut failures = Vec::new();
    // Existing external file → content leak; missing one → existence oracle.
    for (label, id) in [
        ("leak-existing", "../../outside/leak"),
        ("oracle-missing", "../../outside/nope"),
    ] {
        let before = sb.snapshot();
        let out = sb
            .cmd(false)
            .args(["secret", "get-meta", id])
            .output()
            .unwrap();
        let after = sb.snapshot();
        if let Some(f) = check_refused(label, &out, &before, &after, &["LEAKMARKER_GETMETA"]) {
            failures.push(f);
        }
    }
    finish("FLOW-4 get-meta", failures);
}

// ─────────────────────────────────────────────────────────────────────────
// FLOW-5 — `secret validate` (no password; reads external json + yaml;
// ends with std::process::exit(1) → subprocess only)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn flow5_secret_validate_must_not_read_files_outside_vault() {
    let sb = Sandbox::new();
    sb.write_bait(
        &sb.outside().join("v.json"),
        &profile_json("v", "LEAKMARKER_VALIDATE"),
    );
    sb.write_bait(&sb.outside().join("v.yaml"), &allowlist_yaml("v"));
    let before = sb.snapshot();
    let out = sb
        .cmd(false)
        .args(["secret", "validate", "../../outside/v"])
        .output()
        .unwrap();
    let after = sb.snapshot();
    let failures: Vec<String> = check_refused(
        "P2-bait",
        &out,
        &before,
        &after,
        &[
            "LEAKMARKER_VALIDATE",
            "VALID \u{2713}",
            "kvendra.shell.exec",
        ],
    )
    .into_iter()
    .collect();
    finish("FLOW-5 validate", failures);
}

// ─────────────────────────────────────────────────────────────────────────
// FLOW-6 — `secret set-allowlist`
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn flow6_secret_set_allowlist_must_not_write_yaml_outside_vault() {
    let sb = Sandbox::new();
    // The YAML lives OUTSIDE the snapshot root so the snapshot only reflects
    // what the command writes.
    let yaml_dir = tempfile::tempdir().unwrap();
    let yaml = yaml_dir.path().join("al.yaml");
    std::fs::write(&yaml, allowlist_yaml("../../outside/y")).unwrap();
    let before = sb.snapshot();
    let out = sb
        .cmd(true)
        .args([
            "secret",
            "set-allowlist",
            "../../outside/y",
            "--file",
            yaml.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let after = sb.snapshot();
    let mut failures = Vec::new();
    if sb.outside().join("y.yaml").exists() {
        failures.push("[escape] T/outside/y.yaml WRITTEN by set-allowlist".into());
    }
    if let Some(f) = check_refused("P2", &out, &before, &after, &[]) {
        failures.push(f);
    }
    finish("FLOW-6 set-allowlist", failures);
}

/// The id must be refused BEFORE `--file` is read: a missing file must not
/// surface as an io error.
#[test]
fn flow6_secret_set_allowlist_rejects_before_reading_file() {
    let sb = Sandbox::new();
    let missing = sb.root().join("does-not-exist.yaml");
    let mut failures = Vec::new();
    for (label, id) in [("P1", "../x"), ("P2", "../../outside/y"), ("P3", "a/b")] {
        let before = sb.snapshot();
        let out = sb
            .cmd(false)
            .args([
                "secret",
                "set-allowlist",
                id,
                "--file",
                missing.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        let after = sb.snapshot();
        if let Some(f) = check_refused(label, &out, &before, &after, &[]) {
            failures.push(f);
        }
    }
    finish("FLOW-6 set-allowlist (pre-read)", failures);
}

// ─────────────────────────────────────────────────────────────────────────
// FLOW-7 — `secret list` (informative: only lists names inside secrets/)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn flow7_secret_list_only_reports_profiles_inside_secrets_dir() {
    let sb = Sandbox::new();
    sb.write_bait(&sb.outside().join("ghost.blob"), "x");
    let out = sb.cmd(false).args(["secret", "list"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("ghost"), "list escaped secrets/: {stdout}");
}

// ─────────────────────────────────────────────────────────────────────────
// FLOW-8 — positive control: full lifecycle with legitimate ids (C1)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn flow8_control_ids_full_lifecycle_stays_green() {
    let sb = Sandbox::new();
    let long = "a".repeat(128);
    for id in ["aws.kvendra.staging-deploy", "p1_test-2", long.as_str()] {
        sb.cmd(true)
            .args(["secret", "add", id, "--secret-env", "KVD_TEST_SECRET"])
            .assert()
            .success();
        assert!(sb.home().join(format!("secrets/{id}.blob")).exists());
        assert!(sb.home().join(format!("profiles/{id}.json")).exists());
        sb.cmd(false)
            .args(["secret", "get-meta", id])
            .assert()
            .success();
        sb.cmd(true)
            .args(["secret", "rotate", id, "--secret-env", "KVD_TEST_SECRET"])
            .assert()
            .success();
        let yaml_dir = tempfile::tempdir().unwrap();
        let yaml = yaml_dir.path().join("al.yaml");
        std::fs::write(&yaml, allowlist_yaml(id)).unwrap();
        sb.cmd(true)
            .args([
                "secret",
                "set-allowlist",
                id,
                "--file",
                yaml.to_str().unwrap(),
            ])
            .assert()
            .success();
        assert!(sb.home().join(format!("allowlists/{id}.yaml")).exists());
        sb.cmd(false)
            .args(["secret", "validate", id])
            .assert()
            .success();
        let list = sb.cmd(false).args(["secret", "list"]).output().unwrap();
        assert!(String::from_utf8_lossy(&list.stdout).contains(id));
        sb.cmd(false)
            .args(["secret", "revoke", id])
            .assert()
            .success();
        assert!(!sb.home().join(format!("secrets/{id}.blob")).exists());
    }
    // Nothing ever escaped the vault home; the vault itself is intact.
    let outside: Vec<_> = std::fs::read_dir(sb.outside()).unwrap().collect();
    assert!(
        outside.is_empty(),
        "control lifecycle wrote outside the vault"
    );
    assert!(sb.home().join("sentinel.blob").exists());
}

// ─────────────────────────────────────────────────────────────────────────
// FLOW-9 — Vault layer (defence in depth: callers other than the CLI)
// ─────────────────────────────────────────────────────────────────────────

fn vault_hostile_ids(sb: &Sandbox) -> Vec<(&'static str, String)> {
    let mut v = hostile_payloads(sb);
    v.push(("P8", "a\0b".into()));
    v
}

fn unlocked_vault(sb: &Sandbox) -> Vault {
    let v = Vault::new(sb.home());
    v.unlock(PW.as_bytes(), 5).unwrap();
    v
}

fn is_io(e: &kvendra::KvendraError) -> bool {
    matches!(e, kvendra::KvendraError::Io(_))
}

#[test]
fn flow9_vault_put_secret_refuses_hostile_profile_id() {
    let sb = Sandbox::new();
    let v = unlocked_vault(&sb);
    let mut failures = Vec::new();
    for (label, id) in vault_hostile_ids(&sb) {
        let before = sb.snapshot();
        let r = v.put_secret(&id, b"plaintext");
        let after = sb.snapshot();
        let d = diff(&before, &after);
        match &r {
            Ok(()) => failures.push(format!("[{label}] put_secret Ok; changes={d:?}")),
            Err(e) if is_io(e) => {
                failures.push(format!("[{label}] incidental io error {e}; changes={d:?}"))
            }
            Err(_) if !d.is_empty() => failures.push(format!("[{label}] changes={d:?}")),
            Err(_) => {}
        }
    }
    finish("FLOW-9 put_secret", failures);
}

#[test]
fn flow9_vault_get_secret_and_load_meta_refuse_hostile_profile_id() {
    let sb = Sandbox::new();
    // A blob sealed with the real key placed OUTSIDE the vault (simulates
    // reading attacker-chosen or out-of-tree files through the vault API).
    let v = unlocked_vault(&sb);
    v.put_secret("seed", b"OUTSIDE-PLAINTEXT").unwrap();
    std::fs::rename(
        sb.home().join("secrets/seed.blob"),
        sb.outside().join("y.blob"),
    )
    .unwrap();
    sb.write_bait(&sb.outside().join("y.json"), &profile_json("y", "LEAK"));
    let mut failures = Vec::new();
    match v.get_secret("../../outside/y") {
        Ok(p) => failures.push(format!(
            "[P2] get_secret decrypted a blob OUTSIDE the vault: {:?}",
            p.as_str().unwrap_or("?")
        )),
        Err(e) if is_io(&e) => failures.push(format!("[P2] get_secret io error {e}")),
        Err(_) => {}
    }
    match v.load_profile_meta("../../outside/y") {
        Ok(m) => failures.push(format!(
            "[P2] load_profile_meta read JSON OUTSIDE the vault (secret_type={})",
            m.secret_type
        )),
        Err(e) if is_io(&e) => failures.push(format!("[P2] load_profile_meta io error {e}")),
        Err(_) => {}
    }
    for (label, id) in vault_hostile_ids(&sb) {
        if let Err(e) = v.get_secret(&id)
            && is_io(&e)
        {
            failures.push(format!("[{label}] get_secret incidental io error {e}"));
        }
        if let Err(e) = v.load_profile_meta(&id)
            && is_io(&e)
        {
            failures.push(format!(
                "[{label}] load_profile_meta incidental io error {e}"
            ));
        }
    }
    finish("FLOW-9 get_secret/load_profile_meta", failures);
}

#[test]
fn flow9_vault_save_profile_meta_refuses_hostile_profile_id() {
    let sb = Sandbox::new();
    let v = Vault::new(sb.home());
    let mut failures = Vec::new();
    for (label, id) in vault_hostile_ids(&sb) {
        let p = kvendra::vault::Profile {
            profile_id: id.clone(),
            secret_type: "generic".into(),
            created_at: "2026-10-06".into(),
            expiration: None,
            unsafe_raw_token_enabled: false,
            quarantined: false,
            allowlist_hmac_hex: None,
        };
        let before = sb.snapshot();
        let r = v.save_profile_meta(&p);
        let after = sb.snapshot();
        let d = diff(&before, &after);
        match &r {
            Ok(()) => failures.push(format!("[{label}] save_profile_meta Ok; changes={d:?}")),
            Err(e) if is_io(e) => {
                failures.push(format!("[{label}] incidental io error {e}; changes={d:?}"))
            }
            Err(_) if !d.is_empty() => failures.push(format!("[{label}] changes={d:?}")),
            Err(_) => {}
        }
    }
    finish("FLOW-9 save_profile_meta", failures);
}

#[test]
fn flow9_vault_delete_profile_refuses_hostile_profile_id() {
    let sb = Sandbox::new();
    let v = Vault::new(sb.home());
    let mut failures = Vec::new();
    for (label, id) in [("../sentinel", "../sentinel".to_string())]
        .into_iter()
        .chain(vault_hostile_ids(&sb))
    {
        for ext in ["blob", "json", "yaml"] {
            sb.write_bait(&sb.outside().join(format!("y.{ext}")), "BAIT");
        }
        let before = sb.snapshot();
        let r = v.delete_profile(&id);
        let after = sb.snapshot();
        let d = diff(&before, &after);
        if r.is_ok() || !d.is_empty() {
            failures.push(format!("[{label}] delete_profile -> {r:?}; changes={d:?}"));
        }
    }
    finish("FLOW-9 delete_profile", failures);
}

/// Control (GREEN today and after the fix): legitimate ids round-trip through
/// the Vault API and stay inside `home`.
#[test]
fn flow9_vault_control_ids_round_trip() {
    let sb = Sandbox::new();
    let v = unlocked_vault(&sb);
    let long = "a".repeat(128);
    for id in ["aws.kvendra.staging-deploy", "p1_test-2", long.as_str()] {
        v.put_secret(id, b"pt").unwrap();
        assert_eq!(v.get_secret(id).unwrap().as_bytes(), b"pt");
        assert_eq!(
            v.profile_blob_path(id).parent(),
            Some(v.secrets_dir().as_path())
        );
        assert_eq!(
            v.profile_meta_path(id).parent(),
            Some(v.profiles_dir().as_path())
        );
        assert_eq!(
            v.profile_allowlist_path(id).parent(),
            Some(v.allowlists_dir().as_path())
        );
        v.delete_profile(id).unwrap();
    }
}
