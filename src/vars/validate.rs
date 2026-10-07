//! Per-type validation of local-variable values (REQ-KVD-11F906 RF-CLI-5,
//! AC-LVR-8). Runs on `set`/`verify` AND again on every substitution, so a
//! value that stopped being valid (a symlink swapped under a path) is refused
//! at use time.
//!
//! Common rules: no NUL / CR / LF, no whitespace, no shell metacharacter
//! `` ;|&$`<>(){}[]*?!'"\ ``, no `{{`, and bounded length (4096 for paths,
//! 1024 otherwise). The broker never invokes a shell (every primitive spawns
//! through `spawn::hardened_command`), so these rules are defence in depth.

use super::VarType;
use std::path::{Component, Path};

const MAX_PATH_LEN: usize = 4096;
const MAX_OTHER_LEN: usize = 1024;
const SHELL_META: &[char] = &[
    ';', '|', '&', '$', '`', '<', '>', '(', ')', '{', '}', '[', ']', '*', '?', '!', '\'', '"', '\\',
];

/// Validate `v` for `t`. Returns the normalized value, or the `lvr_*` code.
pub fn validate(t: VarType, v: &str) -> Result<String, &'static str> {
    let max = if t == VarType::Path {
        MAX_PATH_LEN
    } else {
        MAX_OTHER_LEN
    };
    if v.is_empty()
        || v.len() > max
        || v.contains("{{")
        || v.chars()
            .any(|c| c == '\0' || c.is_whitespace() || c.is_control())
        || v.chars().any(|c| SHELL_META.contains(&c))
    {
        return Err("lvr_type_invalid");
    }
    match t {
        VarType::Path => validate_path(v),
        VarType::Host => validate_host(v),
        VarType::Port => validate_port(v),
        VarType::ProfileId => {
            if crate::primitives::is_valid_profile_id(v) {
                Ok(v.to_string())
            } else {
                Err("lvr_type_invalid")
            }
        }
        VarType::String => {
            if v.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(c, '.' | '_' | ':' | '@' | '/' | '+' | '=' | ',' | '-')
            }) {
                Ok(v.to_string())
            } else {
                Err("lvr_type_invalid")
            }
        }
    }
}

/// Absolute, no `.`/`..` component, no `,` (the audit records cwd values in
/// a comma-joined column — O6), existing, and equal to its canonical form (no
/// symlink escape; the value is stored canonical).
fn validate_path(v: &str) -> Result<String, &'static str> {
    let p = Path::new(v);
    if !p.is_absolute() || v.contains(',') {
        return Err("lvr_type_invalid");
    }
    if p.components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("lvr_path_not_canonical");
    }
    match std::fs::canonicalize(p) {
        Ok(c) if c.as_os_str() == p.as_os_str() => Ok(v.to_string()),
        Ok(_) => Err("lvr_path_not_canonical"),
        Err(_) => Err("lvr_path_not_canonical"),
    }
}

/// Use-time check of the FINAL value of a path field (the variable may be a
/// prefix, e.g. `{{lvr:ws}}/repo`): no `.`/`..` component, and the deepest
/// existing ancestor (the path itself when it exists) is canonical.
pub fn final_path_is_canonical(v: &str) -> bool {
    let p = Path::new(v);
    if !p.is_absolute()
        || p.components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return false;
    }
    let mut cur = Some(p);
    while let Some(c) = cur {
        if c.exists() {
            return std::fs::canonicalize(c).is_ok_and(|canon| canon.as_path() == c);
        }
        cur = c.parent();
    }
    false
}

/// Lowercase RFC 1123 hostname or IPv4 literal; no `@`, `/`, `:`, `%`.
fn validate_host(v: &str) -> Result<String, &'static str> {
    if v.contains(['@', '/', ':', '%']) || v.len() > 253 {
        return Err("lvr_type_invalid");
    }
    let labels: Vec<&str> = v.split('.').collect();
    if labels
        .iter()
        .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()))
    {
        return v
            .parse::<std::net::Ipv4Addr>()
            .map(|_| v.to_string())
            .map_err(|_| "lvr_type_invalid");
    }
    let ok = labels.iter().all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    if ok {
        Ok(v.to_string())
    } else {
        Err("lvr_type_invalid")
    }
}

/// Digits only, 1..=65535, no leading zero.
fn validate_port(v: &str) -> Result<String, &'static str> {
    if !v.bytes().all(|b| b.is_ascii_digit()) || v.starts_with('0') {
        return Err("lvr_type_invalid");
    }
    match v.parse::<u32>() {
        Ok(n) if (1..=65535).contains(&n) => Ok(v.to_string()),
        _ => Err("lvr_type_invalid"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports() {
        assert!(validate(VarType::Port, "8443").is_ok());
        for bad in ["0", "65536", "080", "-1", "80a", ""] {
            assert!(validate(VarType::Port, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn hosts() {
        assert!(validate(VarType::Host, "kvd-sentinel.example").is_ok());
        assert!(validate(VarType::Host, "10.0.0.1").is_ok());
        for bad in [
            "user@host",
            "Host.example",
            "h/x",
            "h:1",
            "-h.example",
            "10.0.0.256",
            "1.2.3",
            "h%2e",
        ] {
            assert!(validate(VarType::Host, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn strings_and_common_rules() {
        assert!(validate(VarType::String, "kvd-sentinel:a@b/c+d=e,f").is_ok());
        for bad in [
            "a;b",
            "a$(b)",
            "a b",
            "a\nb",
            "a\0b",
            "a`b`",
            "{{lvr:x}}",
            "a|b",
            "a'b",
        ] {
            assert!(validate(VarType::String, bad).is_err(), "{bad:?}");
        }
        assert!(validate(VarType::ProfileId, "aws.kvd-sentinel").is_ok());
        assert!(validate(VarType::ProfileId, "../x").is_err());
    }

    #[test]
    fn paths() {
        let d = tempfile::tempdir().unwrap();
        let canon = d.path().canonicalize().unwrap();
        let real = canon.join("kvd-sentinel-real");
        std::fs::create_dir(&real).unwrap();
        let s = real.to_str().unwrap();
        assert_eq!(validate(VarType::Path, s).unwrap(), s);
        assert_eq!(
            validate(VarType::Path, &format!("{s}/../x")),
            Err("lvr_path_not_canonical")
        );
        assert!(validate(VarType::Path, "relative/x").is_err());
        assert!(validate(VarType::Path, &format!("{s}/missing")).is_err());
        #[cfg(unix)]
        {
            let link = canon.join("kvd-sentinel-link");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            assert_eq!(
                validate(VarType::Path, link.to_str().unwrap()),
                Err("lvr_path_not_canonical")
            );
            assert!(!final_path_is_canonical(&format!(
                "{}/new",
                link.to_str().unwrap()
            )));
        }
        assert!(final_path_is_canonical(&format!("{s}/not-yet/created")));
        assert!(!final_path_is_canonical(&format!("{s}/../x")));
    }
}
