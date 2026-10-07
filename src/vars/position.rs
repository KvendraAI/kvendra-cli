//! Bounded-position check (REQ-KVD-11F906 D3, RF-CLI-5, AC-LVR-7).
//!
//! A local reference is accepted only in a field whose FINAL value a signed
//! allowlist constraint checks:
//!
//! | Position | Bounding constraint |
//! |---|---|
//! | `profile_id` | the profile's own allowlist (`spec.profile_id` binding) |
//! | `args.cwd` | a NON-TRIVIAL `cwd_pattern` |
//! | `args.argv[i]` | `args_constraints`, when EVERY matching template has a literal or `prefix/*` token at `i` (never `*`) |
//! | `args.url` | `url_pattern_regex` / `endpoints` |
//! | `args.src` / `dst` / `dist` | `local_roots` (or `buckets` for an `s3://` operand) |
//!
//! Anything else (`message`, `body`, `title`, `operation`, `binary`, `env`,
//! `repo`…) → `lvr_position_unbounded`. Hardening on top (O10): no local
//! reference at all when `kvendra.shell` runs an interpreter / exec-wrapper
//! binary, or `git` with `-c` / `--config-env` / `config`.

use super::LvrError;
use super::resolve::{LvrSite, argv_index};
use crate::allowlist::dsl::ProfileSpec;
use crate::allowlist::enforcer::{argv_matches_template, operation_constraints, regex_full_match};
use crate::primitives::local_operand::LOCAL_OPERAND_OPS;
use serde_json::Value;

/// Binaries for which a local reference is never accepted (O10): they turn
/// an argument into code (`-c`, `-e`, `-exec`, scripts…).
pub const INTERPRETER_BINARIES: &[&str] = &[
    "bash",
    "sh",
    "zsh",
    "dash",
    "fish",
    "ksh",
    "csh",
    "tcsh",
    "node",
    "deno",
    "perl",
    "ruby",
    "osascript",
    "env",
    "xargs",
    "awk",
    "gawk",
    "find",
    "npx",
];

/// `true` when `binary` (basename) is an interpreter / exec wrapper, or `git`
/// invoked with config-injection flags (O10).
pub fn is_interpreter(binary: &str, argv: &[&str]) -> bool {
    let base = binary.rsplit('/').next().unwrap_or(binary);
    if base.starts_with("python") || INTERPRETER_BINARIES.contains(&base) {
        return true;
    }
    base == "git"
        && argv.iter().any(|a| {
            *a == "-c" || *a == "--config-env" || *a == "config" || a.starts_with("--config-env=")
        })
}

/// A `cwd_pattern` that bounds nothing (`.*`, `^.*$`, `^/.*`, or one that
/// accepts both `/` and `/tmp/x`) does not count as a bound.
pub fn is_trivial_cwd_pattern(pattern: &str) -> bool {
    let p = pattern.trim();
    matches!(p, ".*" | "^.*$" | "^/.*" | "/.*" | "^/.*$" | ".+" | "^.+$")
        || (regex_full_match(p, "/") && regex_full_match(p, "/tmp/x"))
}

/// Refuse any site outside a bounded field. `resolved` is the canonical MCP
/// envelope AFTER substitution.
pub fn check(
    spec: &ProfileSpec,
    primitive: &str,
    operation: &str,
    resolved: &Value,
    sites: &[LvrSite],
) -> Result<(), LvrError> {
    if sites.is_empty() {
        return Ok(());
    }
    let inner = resolved.get("args").cloned().unwrap_or(Value::Null);
    let argv: Vec<&str> = inner
        .get("argv")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    if primitive == "kvendra.shell" {
        let binary = inner
            .get(crate::primitives::shell::BINARY_FIELD)
            .and_then(Value::as_str)
            .unwrap_or("");
        if is_interpreter(binary, &argv) {
            return Err(LvrError::new(
                "lvr_position_unbounded",
                sites[0].key.clone(),
            ));
        }
    }

    let constraints = operation_constraints(spec, primitive, operation);
    for site in sites {
        let unbounded = || LvrError::new("lvr_position_unbounded", site.key.clone());
        if site.pointer == "/profile_id" {
            continue;
        }
        if primitive == "kvendra.unsafe.raw_token" {
            return Err(unbounded());
        }
        let Some(c) = constraints else {
            return Err(unbounded());
        };
        let bounded = match site.pointer.as_str() {
            "/args/cwd" => c
                .cwd_pattern
                .as_deref()
                .is_some_and(|p| !is_trivial_cwd_pattern(p)),
            "/args/url" => c.url_pattern_regex.is_some() || c.endpoints.is_some(),
            ptr @ ("/args/src" | "/args/dst" | "/args/dist") => {
                let field = &ptr["/args/".len()..];
                let value = inner.get(field).and_then(Value::as_str).unwrap_or("");
                if value.starts_with("s3://") {
                    c.buckets.is_some()
                } else {
                    LOCAL_OPERAND_OPS
                        .iter()
                        .any(|(p, o, fs)| *p == primitive && *o == operation && fs.contains(&field))
                        && c.local_roots.as_ref().is_some_and(|r| !r.is_empty())
                }
            }
            ptr => match argv_index(ptr) {
                Some(i) => c.args_constraints.as_ref().is_some_and(|tpls| {
                    let matching: Vec<_> = tpls
                        .iter()
                        .filter(|t| argv_matches_template(&argv, t))
                        .collect();
                    !matching.is_empty() && matching.iter().all(|t| t.allowed[i] != "*")
                }),
                None => false,
            },
        };
        if !bounded {
            return Err(unbounded());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trivial_cwd_patterns() {
        for p in [".*", "^.*$", "^/.*", "/(.*)", "(/.*)?|.*"] {
            assert!(is_trivial_cwd_pattern(p), "{p}");
        }
        assert!(!is_trivial_cwd_pattern("^/kvd-sentinel/ws(/.*)?$"));
    }

    #[test]
    fn interpreters() {
        assert!(is_interpreter("/bin/bash", &[]));
        assert!(is_interpreter("python3.12", &[]));
        assert!(is_interpreter(
            "git",
            &["-c", "core.sshCommand=x", "status"]
        ));
        assert!(!is_interpreter("git", &["status"]));
        assert!(!is_interpreter("ls", &[]));
    }
}
