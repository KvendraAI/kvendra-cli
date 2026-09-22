//! Local-filesystem operands of brokered transfers — THE shared classifier
//! and canonicalizer (ISSUE-KVD-CLI-9D5CF5, PAT-KVD-CLI-C18A74).
//!
//! Some primitives move data between the local filesystem and a remote
//! service under the profile's credential: `aws.s3_sync` / `aws.s3_cp`
//! (`src`, `dst`), `git.clone` (`dst`) and `pypi.upload` (`dist`). Their
//! local side used to be a free-form agent string no layer constrained, so
//! any owner-readable directory could be synced into an allowlisted bucket
//! (or bytes written to any owner-writable path) without a prompt.
//!
//! This module owns the three facts both the enforcer and the validator
//! need, so the producer (primitive) and the enforcer can never disagree on
//! which string is a local path:
//!
//! - [`LOCAL_OPERAND_OPS`] — which `(primitive, operation)` carry a local
//!   operand, and in which wire field.
//! - [`classify_s3_operand`] — the object-store operand split (remote bucket
//!   vs. local path vs. malformed remote), also used by the aws primitive.
//! - [`resolve_local_path`] + [`is_within_roots`] — canonical containment
//!   against the allowlist's `local_roots`.

use serde_json::Value;
use std::path::{Path, PathBuf};

/// `(primitive, operation, local operand fields)` for every brokered transfer.
/// Field names are exactly the ones the primitives read (PAT-KVD-CLI-1A99C5).
pub const LOCAL_OPERAND_OPS: &[(&str, &str, &[&str])] = &[
    ("kvendra.aws", "s3_sync", &["src", "dst"]),
    ("kvendra.aws", "s3_cp", &["src", "dst"]),
    ("kvendra.git", "clone", &["dst"]),
    ("kvendra.pypi", "upload", &["dist"]),
];

/// `true` when `(primitive, operation)` moves data across the local
/// filesystem and therefore needs `local_roots`.
pub fn has_local_operand(primitive: &str, operation: &str) -> bool {
    LOCAL_OPERAND_OPS
        .iter()
        .any(|(p, o, _)| *p == primitive && *o == operation)
}

/// One side of an `aws s3 sync|cp` transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S3Operand<'a> {
    /// `s3://<bucket>[/<key>]`.
    Remote { bucket: &'a str },
    /// Anything else the AWS CLI would treat as a local path.
    Local(&'a str),
}

/// Split an object-store operand. A string that looks like a remote but is
/// not a well-formed `s3://<bucket>/…` URI (`S3://b/k`, `s3:///k`,
/// `https://…`, `s3:bucket`) is an ERROR, never silently treated as local:
/// treating it as a local path would dodge the bucket rule, and treating it as
/// a bucket would dodge the local-root rule.
pub fn classify_s3_operand(s: &str) -> Result<S3Operand<'_>, String> {
    if s.is_empty() {
        return Err("empty transfer operand".into());
    }
    if let Some(rest) = s.strip_prefix("s3://") {
        let bucket = rest.split('/').next().unwrap_or("");
        if bucket.is_empty() {
            return Err(format!("malformed s3 URI '{s}' (no bucket)"));
        }
        return Ok(S3Operand::Remote { bucket });
    }
    if s.contains("://") || s.to_ascii_lowercase().starts_with("s3:") {
        return Err(format!(
            "malformed remote operand '{s}' (only `s3://<bucket>/…` is a remote)"
        ));
    }
    Ok(S3Operand::Local(s))
}

/// The local operands of a call, as `(field, value)`. `Err` when a local
/// operand cannot be determined safely (malformed remote, `git clone` without
/// `dst` — which writes into the broker's own working directory).
///
/// A missing `src`/`dst`/`dist` is not reported: the primitive refuses the
/// call before anything runs, so there is nothing to constrain.
pub fn local_operands<'a>(
    primitive: &str,
    operation: &str,
    inner: &'a Value,
) -> Result<Vec<(&'static str, &'a str)>, String> {
    let Some((_, _, fields)) = LOCAL_OPERAND_OPS
        .iter()
        .find(|(p, o, _)| *p == primitive && *o == operation)
    else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for field in fields.iter().copied() {
        let Some(v) = inner.get(field).and_then(Value::as_str) else {
            if primitive == "kvendra.git" {
                return Err(format!(
                    "`{field}` absent — git clone would write into the broker's working \
                     directory"
                ));
            }
            continue;
        };
        if primitive == "kvendra.aws" {
            match classify_s3_operand(v)? {
                S3Operand::Remote { .. } => continue,
                S3Operand::Local(p) => out.push((field, p)),
            }
        } else {
            out.push((field, v));
        }
    }
    Ok(out)
}

/// Canonical absolute form of a local operand, resolved the same way the
/// brokered subprocess will resolve it (relative to the broker's cwd,
/// following symlinks). For a not-yet-existing leaf (download destination,
/// clone target, `dist/*` glob) the PARENT is canonicalized and the leaf
/// re-joined; a leaf that exists only as a dangling symlink is refused
/// (the write would follow it). `None` = unresolvable → caller denies.
pub fn resolve_local_path(p: &str) -> Option<PathBuf> {
    if p.is_empty() {
        return None;
    }
    let path = Path::new(p);
    if let Ok(c) = std::fs::canonicalize(path) {
        return Some(c);
    }
    if std::fs::symlink_metadata(path).is_ok() {
        return None;
    }
    let leaf = path.file_name()?;
    let parent = path
        .parent()
        .filter(|x| !x.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let cp = std::fs::canonicalize(parent).ok()?;
    Some(cp.join(leaf))
}

/// `Ok(true)` when the operand resolves inside (or equal to) one of `roots`.
/// Roots must be absolute; each is canonicalized and a root that does not
/// exist (or is relative) never matches. Containment is component-wise
/// (`Path::starts_with` on canonical paths), so `<root>-evil` does not match
/// `<root>` and `..` cannot survive canonicalization.
///
/// Iter3 — roots are re-canonicalized on every call, so a root that was a
/// real directory at signing time can later be swapped for a symlink. The
/// signing-time validator refuses a filesystem-root entry without
/// `accept_broad_scope`; the same rule is re-applied HERE at runtime, and
/// FAIL-CLOSED (`Err`, the whole call is refused — not just that root skipped):
/// - a declared root whose canonical form is `/` is refused unless
///   `accept_broad_scope` is set (otherwise a swap to `/` makes every operand
///   "inside");
/// - a declared root that is a dangling symlink (it exists as a link but no
///   longer resolves) is refused — a tamper signal, not a missing directory.
pub fn is_within_roots(
    operand: &str,
    roots: &[String],
    accept_broad_scope: bool,
) -> Result<bool, String> {
    let mut canonical_roots = Vec::with_capacity(roots.len());
    for r in roots {
        let rp = Path::new(r);
        if !rp.is_absolute() {
            continue;
        }
        match std::fs::canonicalize(rp) {
            Ok(root) => {
                if root.parent().is_none() && !accept_broad_scope {
                    return Err(format!(
                        "local root '{r}' resolves to the filesystem root at runtime — \
                         refusing without accept_broad_scope (fail-closed)"
                    ));
                }
                canonical_roots.push(root);
            }
            Err(_) if std::fs::symlink_metadata(rp).is_ok() => {
                return Err(format!(
                    "local root '{r}' no longer resolves (dangling symlink) — refusing \
                     (fail-closed)"
                ));
            }
            Err(_) => {}
        }
    }
    let Some(resolved) = resolve_local_path(operand) else {
        return Ok(false);
    };
    Ok(canonical_roots
        .iter()
        .any(|root| resolved.starts_with(root)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classify_splits_remote_local_and_malformed() {
        assert_eq!(
            classify_s3_operand("s3://b/k"),
            Ok(S3Operand::Remote { bucket: "b" })
        );
        assert_eq!(
            classify_s3_operand("s3://b"),
            Ok(S3Operand::Remote { bucket: "b" })
        );
        assert_eq!(
            classify_s3_operand("./build"),
            Ok(S3Operand::Local("./build"))
        );
        for bad in ["", "S3://b/k", "s3:///k", "s3:b", "https://x/y"] {
            assert!(classify_s3_operand(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn local_operands_table() {
        let v = json!({ "src": "/a", "dst": "s3://b/x" });
        assert_eq!(
            local_operands("kvendra.aws", "s3_sync", &v),
            Ok(vec![("src", "/a")])
        );
        assert!(local_operands("kvendra.git", "clone", &json!({ "url": "u" })).is_err());
        assert_eq!(
            local_operands("kvendra.pypi", "upload", &json!({ "dist": "d" })),
            Ok(vec![("dist", "d")])
        );
        assert_eq!(
            local_operands("kvendra.aws", "lambda_invoke", &v),
            Ok(Vec::new())
        );
    }

    #[test]
    fn containment_is_component_wise_and_canonical() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(dir.path().join("root-evil")).unwrap();
        let roots = vec![root.to_string_lossy().into_owned()];
        let r = root.to_string_lossy();
        let within = |p: &str, rs: &[String]| is_within_roots(p, rs, false).unwrap();
        assert!(within(&r, &roots));
        assert!(within(&format!("{r}/not-yet"), &roots));
        assert!(!within(&format!("{r}/../root-evil/x"), &roots));
        assert!(!within(&format!("{r}-evil/x"), &roots));
        assert!(!within(&format!("{r}/missing/deeper"), &roots));
        assert!(!within("/etc", &["relative/root".to_string()]));
        // A root that never existed simply never matches (not a hard deny).
        let missing = vec![dir.path().join("nope").to_string_lossy().into_owned()];
        assert!(!within(&r, &missing));
    }

    /// Iter3 — a declared root that is a real directory at signing time and is
    /// later swapped for a symlink to `/` must NOT make every operand
    /// "inside": the call is refused unless `accept_broad_scope` is set.
    #[cfg(unix)]
    #[test]
    fn runtime_swap_of_root_to_filesystem_root_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let roots = vec![root.to_string_lossy().into_owned()];
        assert_eq!(is_within_roots("/etc/hosts", &roots, false), Ok(false));

        // Swap: the directory becomes a symlink to `/`.
        std::fs::remove_dir(&root).unwrap();
        std::os::unix::fs::symlink("/", &root).unwrap();
        let err = is_within_roots("/etc/hosts", &roots, false)
            .expect_err("root swapped to / must fail closed");
        assert!(err.contains("filesystem root"), "{err}");
        // Even an operand that is lexically under the root is refused.
        assert!(is_within_roots(&format!("{}/etc", root.display()), &roots, false).is_err());
        // Explicit broad scope keeps the owner's signed intent working.
        assert_eq!(is_within_roots("/etc/hosts", &roots, true), Ok(true));
    }

    /// Iter3 — a literal `/` root (only signable with accept_broad_scope)
    /// is likewise refused at runtime without the flag.
    #[cfg(unix)]
    #[test]
    fn literal_filesystem_root_requires_broad_scope_at_runtime() {
        let roots = vec!["/".to_string()];
        assert!(is_within_roots("/etc", &roots, false).is_err());
        assert_eq!(is_within_roots("/etc", &roots, true), Ok(true));
    }

    /// Iter3 — a root that became a dangling symlink is refused outright.
    #[cfg(unix)]
    #[test]
    fn dangling_root_symlink_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::os::unix::fs::symlink(dir.path().join("gone"), &root).unwrap();
        let roots = vec![root.to_string_lossy().into_owned()];
        let err =
            is_within_roots("/etc", &roots, true).expect_err("dangling root must fail closed");
        assert!(err.contains("dangling"), "{err}");
    }
}
