//! Zip-slip in `kvendra::backup::bundle::extract_bundle`
//! (src/backup/bundle.rs:95 — `target_dir.join(&rel_path)` with the raw tar
//! entry path, no containment check).
//!
//! Found while auditing ISSUE-KVD-CLI-C7A858 (profile_id traversal) but OUT
//! OF ITS SCOPE: tracked as a separate ISSUE. The test is `#[ignore]` so it
//! does not block the C7A858 pipeline; run it explicitly with
//! `cargo test --test backup_bundle_zip_slip -- --ignored`.
//! RED at 0f65bf9. Mitigation today: the bundle is encrypted (AES-GCM under a
//! vault-derived key), so a hostile tar requires the backup key.
//!
//! Expected after the fix: an entry with a `..` component or an absolute path
//! is refused (Err) and nothing is written outside `target_dir`.
//!
//! ISOLATION: everything under one `tempfile::tempdir()`.

use std::path::Path;

/// Build a tar whose single entry has the RAW name `name` (bypassing the
/// `tar` crate's `set_path` guards, as a hostile producer would).
fn hostile_tar(name: &str, body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut b = tar::Builder::new(&mut buf);
        let mut h = tar::Header::new_gnu();
        let raw = &mut h.as_old_mut().name;
        raw[..name.len()].copy_from_slice(name.as_bytes());
        h.set_size(body.len() as u64);
        h.set_mode(0o600);
        h.set_cksum();
        b.append(&h, body).unwrap();
        b.finish().unwrap();
    }
    buf
}

fn assert_sandboxed(p: &Path) {
    let sys_tmp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    assert!(std::fs::canonicalize(p).unwrap().starts_with(sys_tmp));
}

#[test]
#[ignore = "zip-slip extract_bundle: separate ISSUE, out of scope of C7A858"]
fn extract_bundle_refuses_parent_traversal_entry() {
    let t = tempfile::tempdir().unwrap();
    assert_sandboxed(t.path());
    let target = t.path().join("home");
    let tar = hostile_tar("../escaped.txt", b"ZIPSLIP");
    let r = kvendra::backup::bundle::extract_bundle(&tar, &target);
    let escaped = t.path().join("escaped.txt");
    assert!(
        !escaped.exists(),
        "extract_bundle wrote OUTSIDE target_dir: {escaped:?} (result {r:?})"
    );
    assert!(r.is_err(), "a `..` entry must be refused, got {r:?}");
}

#[test]
#[ignore = "zip-slip extract_bundle: separate ISSUE, out of scope of C7A858"]
fn extract_bundle_refuses_absolute_entry() {
    let t = tempfile::tempdir().unwrap();
    assert_sandboxed(t.path());
    let target = t.path().join("home");
    let abs = t.path().join("abs").join("z.txt");
    let tar = hostile_tar(abs.to_str().unwrap(), b"ZIPSLIP-ABS");
    let r = kvendra::backup::bundle::extract_bundle(&tar, &target);
    assert!(
        !abs.exists(),
        "extract_bundle honoured an ABSOLUTE entry: {abs:?} (result {r:?})"
    );
    assert!(r.is_err(), "an absolute entry must be refused, got {r:?}");
}
