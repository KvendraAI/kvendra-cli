//! Runtime enforcer — given a parsed `ProfileSpec`, check whether a
//! `(primitive, operation, args)` tuple is authorized.
//!
//! Returns `Ok(())` on allow, `Err(KvendraError::AllowlistViolation)` on
//! deny (REQ-KVD-002 AC-PRIM-2). Expired profiles return `ProfileExpired`
//! before any other check (AC-ALLOW-3).
//!
//! # Argument shape (D8 contract)
//!
//! The `args` value passed in is the **MCP canonical envelope**, exactly as
//! delivered to `tools/call`:
//!
//! ```json
//! { "profile_id": "...", "operation": "...", "args": { ...primitive args... } }
//! ```
//!
//! All field constraints declared in the YAML allowlist DSL apply to the
//! **inner `args.args` payload** (the primitive's own args), NOT to the
//! envelope. Reading constraints from the envelope's top-level (the bug fixed
//! in v0.1.0-alpha.10) is incorrect — only `profile_id` and `operation` live
//! there. Tests MUST drive this function with the canonical envelope shape;
//! "flat" fixtures that put `repo`/`method`/`bucket`/etc. at the top level
//! are inaccurate (PAT-KVD-004 reaffirmed).
//!
//! # Decision register (D1..D8)
//!
//! - **D1** `repo` (singular) is an alias for `repos` and unions with it
//!   (any-match semantics across both lists, glob-style).
//! - **D2** `args_constraints` is an array of allowed argv templates; the
//!   call's argv must match at least one template (any-match). Each template
//!   token may use the same minimalist `*` glob/regex semantics.
//! - **D3** `forbidden_env_export_to_agent` is enforced pre-exec (defense-in-
//!   depth doubled with the layer that scrubs env going OUT to the agent).
//! - **D4** `forbidden_methods` is checked AND'ed with `methods` (denylist
//!   beats allowlist; fail-closed).
//! - **D5** `buckets` extracts the bucket name from the leading
//!   `s3://NAME/...` URI in the call.
//! - **D6** `endpoints` is a literal exact-match alias for HTTP requests
//!   that union with `url_pattern_regex` (any-match).
//! - **D7** `accept_broad_scope` is checked at validator time (NOT here).
//! - **D8** Order of checks: `is_expired → primitive lookup → operation
//!   lookup → forbidden-first denylists → allow-list constraints`.

use crate::allowlist::dsl::{ArgvConstraint, OperationConstraints, ProfileSpec};
use crate::allowlist::validator::is_expired;
use crate::error::{KvendraError, KvendraResult};
use regex::Regex;
use serde_json::Value;

/// Authorize a call against a profile's allowlist.
pub fn check(
    spec: &ProfileSpec,
    primitive: &str,
    operation: &str,
    args: &Value,
) -> KvendraResult<()> {
    if is_expired(spec) {
        return Err(KvendraError::ProfileExpired);
    }
    let prim = spec
        .allowlist
        .primitives
        .iter()
        .find(|p| p.name == primitive)
        .ok_or_else(|| {
            KvendraError::AllowlistViolation(format!("primitive '{primitive}' not allowed"))
        })?;

    // Escape hatch is checked by the primitive itself.
    if primitive == "kvendra.unsafe.raw_token" {
        if !prim.unsafe_raw_token_allowed {
            return Err(KvendraError::UnsafeNotEnabled);
        }
        return Ok(());
    }

    // Operation must appear in the per-primitive list.
    let constraints = prim
        .operations
        .iter()
        .flat_map(|m| m.iter())
        .find(|(name, _)| name.as_str() == operation)
        .map(|(_, c)| c)
        .ok_or_else(|| {
            KvendraError::AllowlistViolation(format!(
                "operation '{primitive}.{operation}' not in allowlist"
            ))
        })?;

    check_args(primitive, operation, constraints, args)
}

/// Inner-payload accessor.
///
/// The MCP canonical envelope is `{profile_id, operation, args:{...}}`. All
/// per-primitive constraints below read from the inner `args` object
/// (D8/PAT-KVD-004). If the envelope lacks a nested `args`, we fall back to
/// `Value::Null` so every `inner.get(...)` returns `None` and the check is a
/// no-op for that field — meaning a malformed call simply fails to satisfy
/// any constraint.
fn inner_args(envelope: &Value) -> Value {
    envelope.get("args").cloned().unwrap_or(Value::Null)
}

fn check_args(
    primitive: &str,
    operation: &str,
    c: &OperationConstraints,
    envelope: &Value,
) -> KvendraResult<()> {
    let inner = inner_args(envelope);

    // ---------------------------------------------------------------------
    // TIER 1 — security-critical denylists FIRST (D4 + D8 fail-closed).
    // ---------------------------------------------------------------------

    // forbidden_args (e.g. --force on git push).
    if let Some(forbidden) = &c.forbidden_args
        && let Some(argv) = inner.get("argv").and_then(Value::as_array)
    {
        for a in argv {
            if let Some(s) = a.as_str()
                && forbidden.iter().any(|f| f == s)
            {
                return Err(KvendraError::AllowlistViolation(format!(
                    "{primitive}.{operation}: forbidden arg '{s}'"
                )));
            }
        }
    }

    // forbidden_methods (D4 — denylist beats allowlist).
    if let Some(forbidden) = &c.forbidden_methods
        && let Some(m) = inner.get("method").and_then(Value::as_str)
        && forbidden
            .iter()
            .any(|denied| denied.eq_ignore_ascii_case(m))
    {
        return Err(KvendraError::AllowlistViolation(format!(
            "{primitive}.{operation}: forbidden method '{m}'"
        )));
    }

    // forbidden_fields — the inner args object MUST NOT contain any of these
    // keys. Used to ban specific GitHub API fields, etc.
    if let Some(forbidden) = &c.forbidden_fields
        && let Some(map) = inner.as_object()
    {
        for f in forbidden {
            if map.contains_key(f) {
                return Err(KvendraError::AllowlistViolation(format!(
                    "{primitive}.{operation}: forbidden field '{f}'"
                )));
            }
        }
    }

    // forbidden_env_export_to_agent (D3 — enforced pre-exec).
    if let Some(forbidden) = &c.forbidden_env_export_to_agent
        && let Some(env) = inner.get("env").and_then(Value::as_object)
    {
        for k in env.keys() {
            if forbidden.iter().any(|f| f == k) {
                return Err(KvendraError::AllowlistViolation(format!(
                    "{primitive}.{operation}: forbidden env export to agent '{k}'"
                )));
            }
        }
    }

    // ---------------------------------------------------------------------
    // TIER 1 — allow-list URL / endpoint / method constraints.
    // ---------------------------------------------------------------------

    // url_pattern_regex (TIER 1 — HTTP url anchor) UNION with `endpoints`
    // (D6: literal exact-match alias). Any match across the two lists allows.
    let url_input = inner.get("url").and_then(Value::as_str);
    if (c.url_pattern_regex.is_some() || c.endpoints.is_some())
        && let Some(url) = url_input
    {
        let regex_ok = c
            .url_pattern_regex
            .as_ref()
            .is_some_and(|patterns| patterns.iter().any(|p| regex_match_url(p, url)));
        let endpoint_ok = c
            .endpoints
            .as_ref()
            .is_some_and(|eps| eps.iter().any(|e| e == url));
        if !regex_ok && !endpoint_ok {
            return Err(KvendraError::AllowlistViolation(format!(
                "{primitive}.{operation}: url '{url}' not allowed"
            )));
        }
    }

    // methods (HTTP allowed method list).
    if let Some(methods) = &c.methods
        && let Some(m) = inner.get("method").and_then(Value::as_str)
        && !methods
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(m))
    {
        return Err(KvendraError::AllowlistViolation(format!(
            "{primitive}.{operation}: method '{m}' not allowed"
        )));
    }

    // buckets (D5 — extract bucket from `s3://NAME/...` URIs).
    if let Some(buckets) = &c.buckets {
        // Multiple shapes accepted:
        // - `bucket` field — bare bucket name (always validated).
        // - `src` / `dst` fields — only validated when they look like s3
        //   URIs (`s3://...`). A local path like `./build` is NOT a bucket
        //   reference and is left to the primitive layer.
        if let Some(bare) = inner.get("bucket").and_then(Value::as_str)
            && !buckets.iter().any(|pat| glob_match(pat, bare))
        {
            return Err(KvendraError::AllowlistViolation(format!(
                "{primitive}.{operation}: bucket '{bare}' not allowed"
            )));
        }
        for key in ["src", "dst"] {
            if let Some(cand) = inner.get(key).and_then(Value::as_str)
                && let Some(name) = extract_bucket_from_s3_uri(cand)
                && !buckets.iter().any(|pat| glob_match(pat, name))
            {
                return Err(KvendraError::AllowlistViolation(format!(
                    "{primitive}.{operation}: bucket '{name}' not allowed"
                )));
            }
        }
    }

    // ---------------------------------------------------------------------
    // TIER 2 — resource allow-lists.
    // ---------------------------------------------------------------------

    // distributions (CloudFront).
    if let Some(allowed) = &c.distributions
        && let Some(id) = inner.get("distribution_id").and_then(Value::as_str)
        && !allowed.iter().any(|pat| glob_match(pat, id))
    {
        return Err(KvendraError::AllowlistViolation(format!(
            "{primitive}.{operation}: distribution '{id}' not allowed"
        )));
    }

    // functions (Lambda).
    if let Some(allowed) = &c.functions
        && let Some(name) = inner.get("function_name").and_then(Value::as_str)
        && !allowed.iter().any(|pat| glob_match(pat, name))
    {
        return Err(KvendraError::AllowlistViolation(format!(
            "{primitive}.{operation}: function '{name}' not allowed"
        )));
    }

    // binaries (shell). Reads the SAME wire key the shell primitive emits
    // (`crate::primitives::shell::BINARY_FIELD` == "binary"). Pre-0.6.4 this
    // read `"bin"`, which the primitive never sends, so the constraint was
    // inert and any binary ran (audit finding C2 / PAT-KVD-CLI-1A99C5).
    //
    // Fail-closed on shape mismatch: when a `binaries:` constraint is declared
    // but the payload carries no `binary` field the enforcer can inspect, we
    // DENY rather than fall through (permissive-on-absence, PAT-KVD-CLI-003).
    if let Some(allowed) = &c.binaries {
        match inner
            .get(crate::primitives::shell::BINARY_FIELD)
            .and_then(Value::as_str)
        {
            Some(bin) => {
                if !allowed.iter().any(|pat| pat == bin) {
                    return Err(KvendraError::AllowlistViolation(format!(
                        "{primitive}.{operation}: binary '{bin}' not allowed"
                    )));
                }
            }
            None => {
                return Err(KvendraError::AllowlistViolation(format!(
                    "{primitive}.{operation}: `binaries` constraint declared but no `{}` field \
                     in the call payload — refusing (fail-closed on shape mismatch)",
                    crate::primitives::shell::BINARY_FIELD
                )));
            }
        }
    }

    // packages (npm/pypi package name).
    if let Some(allowed) = &c.packages
        && let Some(pkg) = inner.get("package").and_then(Value::as_str)
        && !allowed.iter().any(|pat| glob_match(pat, pkg))
    {
        return Err(KvendraError::AllowlistViolation(format!(
            "{primitive}.{operation}: package '{pkg}' not allowed"
        )));
    }

    // projects (e.g. pypi project, gcp project, etc.).
    if let Some(allowed) = &c.projects
        && let Some(proj) = inner.get("project").and_then(Value::as_str)
        && !allowed.iter().any(|pat| glob_match(pat, proj))
    {
        return Err(KvendraError::AllowlistViolation(format!(
            "{primitive}.{operation}: project '{proj}' not allowed"
        )));
    }

    // refs (git refs — push targets).
    if let Some(allowed) = &c.refs
        && let Some(r) = inner.get("ref").and_then(Value::as_str)
        && !allowed.iter().any(|pat| glob_match(pat, r))
    {
        return Err(KvendraError::AllowlistViolation(format!(
            "{primitive}.{operation}: ref '{r}' not allowed"
        )));
    }

    // tag_pattern (git tag — regex full-match against `tag` field).
    if let Some(patterns) = &c.tag_pattern
        && let Some(tag) = inner.get("tag").and_then(Value::as_str)
        && !patterns.iter().any(|p| regex_full_match(p, tag))
    {
        return Err(KvendraError::AllowlistViolation(format!(
            "{primitive}.{operation}: tag '{tag}' not allowed"
        )));
    }

    // ---------------------------------------------------------------------
    // TIER 3 — content / scope allow-lists.
    // ---------------------------------------------------------------------

    // fields_allowed — inner args object's keys MUST be a subset of the list.
    // Only enforced when explicitly declared (allow-list style). The two
    // envelope-meta fields (`profile_id`, `operation`) live one level up so
    // they never leak in here.
    if let Some(allowed) = &c.fields_allowed
        && let Some(map) = inner.as_object()
    {
        for k in map.keys() {
            if !allowed.iter().any(|f| f == k) {
                return Err(KvendraError::AllowlistViolation(format!(
                    "{primitive}.{operation}: field '{k}' not allowed"
                )));
            }
        }
    }

    // org (GitHub organization scope).
    if let Some(allowed) = &c.org {
        // Resolve from `owner` directly or by extracting from `repo`.
        let owner = inner
            .get("owner")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                inner
                    .get("repo")
                    .and_then(Value::as_str)
                    .and_then(extract_owner_from_repo)
                    .map(str::to_string)
            });
        if let Some(o) = owner.as_deref()
            && !allowed.iter().any(|pat| glob_match(pat, o))
        {
            return Err(KvendraError::AllowlistViolation(format!(
                "{primitive}.{operation}: org '{o}' not allowed"
            )));
        }
    }

    // repos UNION repo (D1 — any-match across both lists).
    //
    // For `kvendra.github` the target is `args.repo` (or `args.url`). For
    // `kvendra.git` push/pull/tag/commit there is NO `repo`/`url` field — the
    // target is the `remote` (a URL, or a name resolved from the `cwd`'s git
    // config). ISSUE-KVD-CLI-B78ED5 finding **N7**: the enforcer only looked at
    // `repo`/`url`, so for git ops the `repos` constraint was silently SKIPPED
    // (a false-green suite hid it by injecting a synthetic `repo` field that the
    // real `kvendra.git` primitive never sends). An agent could therefore push
    // any local checkout to any repository — or, with `remote` set to an
    // attacker URL, exfiltrate code and the credential — with the owner's token.
    let is_git = primitive == "kvendra.git";
    let repo_input: Option<String> = if is_git {
        git_target_repo(&inner, operation == "push")
    } else {
        inner
            .get("repo")
            .or_else(|| inner.get("url"))
            .and_then(Value::as_str)
            .map(extract_repo_canonical)
    };
    if c.repos.is_some() || c.repo.is_some() {
        let Some(repo) = repo_input.as_deref() else {
            // Fail closed for git: a `repos` constraint with an undeterminable
            // target is a deny, never a skip (N7). Non-git callers always carry
            // the repo, so absence there keeps the prior semantics.
            if is_git {
                return Err(KvendraError::AllowlistViolation(format!(
                    "{primitive}.{operation}: cannot determine the target repository \
                     (no url and no resolvable remote in cwd) — refusing (fail-closed)"
                )));
            }
            return Ok(());
        };
        // Host-normalize so `Owner/Name` patterns compare against a URL-derived
        // `host/Owner/Name` for git (and keep the host in the comparison so an
        // attacker-host repo does not match a github.com pattern).
        let cand = if is_git {
            normalize_repo_host(repo)
        } else {
            repo.to_string()
        };
        let matches_pat = |pats: &Option<Vec<String>>| {
            pats.as_ref().is_some_and(|ps| {
                ps.iter().any(|p| {
                    let pat = if is_git { normalize_repo_host(p) } else { p.clone() };
                    glob_match(&pat, &cand)
                })
            })
        };
        if !matches_pat(&c.repos) && !matches_pat(&c.repo) {
            return Err(KvendraError::AllowlistViolation(format!(
                "{primitive}.{operation}: repo '{repo}' not allowed"
            )));
        }
    }

    // cwd_pattern (regex full-match against `cwd` for shell ops).
    if let Some(pat) = &c.cwd_pattern
        && let Some(cwd) = inner.get("cwd").and_then(Value::as_str)
        && !regex_full_match(pat, cwd)
    {
        return Err(KvendraError::AllowlistViolation(format!(
            "{primitive}.{operation}: cwd '{cwd}' not allowed"
        )));
    }

    // ---------------------------------------------------------------------
    // TIER 4 — argv templates + env injection.
    // ---------------------------------------------------------------------

    // args_constraints (D2 — array-of-allowed-templates, any-match, regex
    // tokens). Applies to inner `argv`.
    if let Some(constraints) = &c.args_constraints
        && let Some(argv) = inner.get("argv").and_then(Value::as_array)
    {
        let argv_strs: Vec<&str> = argv.iter().filter_map(Value::as_str).collect();
        let any_match = constraints
            .iter()
            .any(|tpl| argv_matches_template(&argv_strs, tpl));
        if !any_match {
            return Err(KvendraError::AllowlistViolation(format!(
                "{primitive}.{operation}: argv does not match any allowed template"
            )));
        }
    }

    // env_vars_to_inject — every key requested by the call's `env` map must
    // be in the allow-list. Defense-in-depth for env injection scope.
    if let Some(allowed) = &c.env_vars_to_inject
        && let Some(env) = inner.get("env").and_then(Value::as_object)
    {
        for k in env.keys() {
            if !allowed.iter().any(|f| f == k) {
                return Err(KvendraError::AllowlistViolation(format!(
                    "{primitive}.{operation}: env var '{k}' not allowed for injection"
                )));
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Single-segment glob matcher: `*` matches any run of characters that
/// does NOT cross `/`, in any position of the pattern. Other characters
/// are matched literally (regex metacharacters are escaped). The match
/// is anchored full-string (`^...$`). Aligns with the semantics
/// documented in TEST-KVD-CLI-097 flow B2b.
///
/// Examples:
/// - `refs/tags/v*`     matches `refs/tags/v0.4.0-alpha.3`
/// - `refs/heads/r/*`   matches `refs/heads/r/v1`  but NOT `refs/heads/r/v1/sub`
/// - `kvendra-*-prod`   matches `kvendra-com-prod`
/// - `release.v*`       matches `release.v1`       but NOT `releaseXv1`
/// - `KvendraAI/*`      matches `KvendraAI/foo`    but NOT `OrgX/KvendraAI/foo`
fn glob_match(pattern: &str, candidate: &str) -> bool {
    let mut re = String::with_capacity(pattern.len() * 2 + 2);
    re.push('^');
    for ch in pattern.chars() {
        match ch {
            '*' => re.push_str("[^/]*"),
            '.' | '+' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$' | '\\' => {
                re.push('\\');
                re.push(ch);
            }
            _ => re.push(ch),
        }
    }
    re.push('$');
    Regex::new(&re).is_ok_and(|r| r.is_match(candidate))
}

/// Start-anchored regex match for URL allowlisting (`url_pattern_regex`).
///
/// Pre-0.6.4 `url_pattern_regex` used bare `Regex::is_match`, a SUBSTRING
/// match: a pattern meant to pin the host, e.g. `https://api\.github\.com/`,
/// also matched a hostile URL that merely *contained* it, e.g.
/// `https://evil.example/?x=https://api.github.com/` — sending the profile's
/// Bearer token to `evil.example` (audit finding: "regex de URL sin anclar").
///
/// We anchor every URL pattern at the START of the candidate. A pattern that
/// already begins with `^` is used as-is; otherwise we prepend `^`. This does
/// NOT anchor the end (URL paths legitimately vary), but binding the scheme +
/// host prefix is what closes the exfiltration bypass. Every production
/// profile already writes `^https://…`, so this is a no-op for well-formed
/// allowlists and a hard deny for the bypass shape.
pub(crate) fn regex_match_url(pattern: &str, candidate: &str) -> bool {
    let anchored = if pattern.starts_with('^') {
        pattern.to_string()
    } else {
        format!("^(?:{pattern})")
    };
    Regex::new(&anchored).is_ok_and(|re| re.is_match(candidate))
}

/// Full-string regex match (auto-wraps the pattern with `^...$` if the user
/// did not). Intended for `tag_pattern` and `cwd_pattern`.
fn regex_full_match(pattern: &str, candidate: &str) -> bool {
    let normalized = if pattern.starts_with('^') && pattern.ends_with('$') {
        pattern.to_string()
    } else {
        let p = pattern.trim_start_matches('^').trim_end_matches('$');
        format!("^(?:{p})$")
    };
    Regex::new(&normalized).is_ok_and(|re| re.is_match(candidate))
}

/// Extract the bucket name from an `s3://NAME/...` URI. Returns `None` for
/// any other shape (caller may treat the input as a bare bucket name).
fn extract_bucket_from_s3_uri(uri: &str) -> Option<&str> {
    let rest = uri.strip_prefix("s3://")?;
    let end = rest.find('/').unwrap_or(rest.len());
    if end == 0 { None } else { Some(&rest[..end]) }
}

/// Extract the owner segment from `<host>/<owner>/<repo>` strings, e.g.
/// `github.com/KvendraAI/kvendra-cli` → `Some("KvendraAI")`.
fn extract_owner_from_repo(repo: &str) -> Option<&str> {
    let mut parts = repo.split('/');
    let _host = parts.next()?;
    parts.next()
}

/// Normalize a git URL or repo identifier to its canonical
/// `host/owner/name` form for matching against `repos: [...]` allowlist
/// patterns.
///
/// Accepts:
/// - `https://github.com/Org/Repo`        → `github.com/Org/Repo`
/// - `https://github.com/Org/Repo.git`    → `github.com/Org/Repo`
/// - `git@github.com:Org/Repo.git`        → `github.com/Org/Repo`
/// - `github.com/Org/Repo`                → `github.com/Org/Repo` (passthrough)
///
/// Pattern parallel to `extract_bucket_from_s3_uri` above. Closes the
/// permissive-on-absence gap where `clone` calls with `args.url` bypassed
/// the `repos:` constraint (ISSUE-KVD-CLI-043).
fn extract_repo_canonical(input: &str) -> String {
    let s = input.trim();
    // Strip http(s):// scheme.
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    // Convert SSH form `git@host:owner/name(.git)?` → `host/owner/name`.
    if let Some(rest) = s.strip_prefix("git@")
        && let Some((host, path)) = rest.split_once(':')
    {
        let path = path.strip_suffix(".git").unwrap_or(path);
        return format!("{host}/{path}");
    }
    // Strip trailing `.git`.
    s.strip_suffix(".git").unwrap_or(s).to_string()
}

/// Does `s` look like a git remote URL (scheme, `git@`, or `user@host:` scp
/// form) rather than a bare remote NAME like `origin`? Used to decide whether
/// a git `remote` argument is itself the target or a name to resolve from the
/// repo's config. Misclassification is safe: a URL treated as a name fails to
/// resolve (deny), and a name treated as a URL canonicalizes to a
/// non-matching repo (deny) — both fail closed.
fn looks_like_git_url(s: &str) -> bool {
    s.contains("://") || s.starts_with("git@") || (s.contains('@') && s.contains(':'))
}

/// Resolve a git remote NAME to its URL by reading `<cwd>/.git/config`.
/// For a push we honour `pushurl` (which overrides `url` for pushes) before
/// `url`. Returns `None` if the config, the section, or the field is absent —
/// which the caller turns into a fail-closed deny (ISSUE-KVD-CLI-B78ED5 N7).
fn git_config_remote_url(cwd: &str, remote: &str, prefer_pushurl: bool) -> Option<String> {
    let path = std::path::Path::new(cwd).join(".git").join("config");
    let content = std::fs::read_to_string(path).ok()?;
    let header = format!("[remote \"{remote}\"]");
    let mut in_section = false;
    let mut url = None;
    let mut pushurl = None;
    for line in content.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_section = t.eq_ignore_ascii_case(&header);
            continue;
        }
        if in_section && let Some((k, v)) = t.split_once('=') {
            match k.trim().to_ascii_lowercase().as_str() {
                "url" => url = Some(v.trim().to_string()),
                "pushurl" => pushurl = Some(v.trim().to_string()),
                _ => {}
            }
        }
    }
    if prefer_pushurl { pushurl.or(url) } else { url }
}

/// Determine the ACTUAL repository a `kvendra.git` operation targets, so the
/// `repos` allowlist can be enforced against it. `git push`/`pull`/`tag`/
/// `commit` carry no `repo`/`url` field — the target lives in the `remote`
/// (which may be a URL or a name) resolved against the `cwd`'s git config.
/// Pre-fix, the enforcer only looked at `repo`/`url`, so for these ops the
/// `repos` constraint was silently skipped and an agent could push to any
/// repository with the owner's credential (ISSUE-KVD-CLI-B78ED5 N7).
fn git_target_repo(inner: &Value, prefer_pushurl: bool) -> Option<String> {
    // An explicit url/repo (clone, or any caller that passes it) wins.
    if let Some(r) = inner
        .get("repo")
        .or_else(|| inner.get("url"))
        .and_then(Value::as_str)
    {
        return Some(extract_repo_canonical(r));
    }
    // Otherwise the target is the `remote` (default `origin`).
    let remote = inner
        .get("remote")
        .and_then(Value::as_str)
        .unwrap_or("origin");
    if looks_like_git_url(remote) {
        return Some(extract_repo_canonical(remote));
    }
    // `remote` is a NAME → resolve it to a URL via the repo's own config.
    let cwd = inner.get("cwd").and_then(Value::as_str)?;
    git_config_remote_url(cwd, remote, prefer_pushurl)
        .map(|u| extract_repo_canonical(&u))
}

/// Normalize a canonical repo (`host/owner/name` or `owner/name`) so a
/// host-less allowlist pattern (`Owner/Name`) and a URL-derived repo
/// (`github.com/Owner/Name`) compare on equal footing. A host-less value
/// defaults to `github.com/…`; this keeps the host in the comparison, so a
/// same-owner/name repo on an ATTACKER host (`evil.com/Owner/Name`) does NOT
/// match a `github.com` pattern (would otherwise leak the credential).
fn normalize_repo_host(s: &str) -> String {
    match s.split_once('/') {
        Some((first, _)) if first.contains('.') => s.to_string(),
        _ => format!("github.com/{s}"),
    }
}

/// Compare a call's argv against a template. The template's tokens may use:
/// - exact-string match (literal token);
/// - the same `prefix/*` glob suffix used for repos;
/// - a special `*` wildcard token that matches any single argv slot.
///
/// The argv must have **the same length** as the template (D2 — strict).
fn argv_matches_template(argv: &[&str], tpl: &ArgvConstraint) -> bool {
    if argv.len() != tpl.allowed.len() {
        return false;
    }
    argv.iter().zip(tpl.allowed.iter()).all(|(a, t)| {
        if t == "*" {
            true
        } else if let Some(prefix) = t.strip_suffix("/*") {
            a.starts_with(prefix) && a.len() > prefix.len()
        } else {
            t == *a
        }
    })
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_with(yaml: &str) -> ProfileSpec {
        ProfileSpec::from_yaml(yaml).unwrap()
    }

    /// Build the canonical MCP envelope `{profile_id, operation, args}`.
    fn env_args(args: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "profile_id": "x",
            "operation": "op",
            "args": args,
        })
    }

    // -----------------------------------------------------------------
    // BLOQUE A — regression for the 3 fields previously enforced, but
    // updated to the canonical MCP envelope shape (PAT-KVD-004 reaffirmed).
    // -----------------------------------------------------------------

    #[test]
    fn allow_listed_op_passes() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - push:
            repos: ["github.com/Foo/*"]
"#,
        );
        let args = env_args(serde_json::json!({ "repo": "github.com/Foo/bar" }));
        assert!(check(&s, "kvendra.git", "push", &args).is_ok());
    }

    #[test]
    fn forbidden_arg_blocks() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - push:
            repos: ["github.com/Foo/*"]
            forbidden_args: ["--force"]
"#,
        );
        let args = env_args(serde_json::json!({
            "repo": "github.com/Foo/bar",
            "argv": ["push", "--force"]
        }));
        assert!(check(&s, "kvendra.git", "push", &args).is_err());
    }

    #[test]
    fn unknown_primitive_violates() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - push:
            repos: ["github.com/Foo/*"]
"#,
        );
        assert!(
            check(
                &s,
                "kvendra.aws",
                "s3_sync",
                &env_args(serde_json::json!({}))
            )
            .is_err()
        );
    }

    #[test]
    fn flat_shape_top_level_repo_is_invisible() {
        // PAT-KVD-004 reaffirmed: a "flat" envelope (legacy buggy fixture
        // shape) is invisible to the enforcer — it now reads strictly from
        // `args.args`. Critically, this means an attacker who places fields
        // at the TOP level cannot use them to satisfy ANY constraint. We
        // demonstrate that with a `forbidden_args` constraint that the
        // attacker tries to dodge by hoisting `argv` to the top level.
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - push:
            repos: ["github.com/Foo/*"]
            forbidden_args: ["--force"]
"#,
        );

        // Inner-args shape: forbidden arg is detected and rejected.
        let inner_force = env_args(serde_json::json!({
            "repo": "github.com/Foo/bar",
            "argv": ["push", "--force"]
        }));
        assert!(check(&s, "kvendra.git", "push", &inner_force).is_err());

        // Flat shape: top-level fields are not visible to the enforcer (they
        // live under `args`). Pre-N7 this was permissively ALLOWED, which was
        // the bug — a git push whose target the enforcer cannot see must not
        // slip through. With a `repos` constraint declared, an undeterminable
        // target now fails closed. (`kvendra.git` N7 fix.)
        let flat = serde_json::json!({
            "repo": "github.com/Foo/bar",
            "argv": ["push", "--force"]
        });
        assert!(check(&s, "kvendra.git", "push", &flat).is_err());
    }

    #[test]
    fn forbidden_arg_blocks_with_envelope() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - push:
            repos: ["github.com/Foo/*"]
            forbidden_args: ["--force-with-lease"]
"#,
        );
        let args = env_args(serde_json::json!({
            "repo": "github.com/Foo/bar",
            "argv": ["push", "--force-with-lease"]
        }));
        let err = check(&s, "kvendra.git", "push", &args).unwrap_err();
        assert!(matches!(err, KvendraError::AllowlistViolation(_)));
    }

    #[test]
    fn methods_envelope_allows_get() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.http
      operations:
        - request:
            methods: ["GET"]
"#,
        );
        let args = env_args(serde_json::json!({ "method": "GET" }));
        assert!(check(&s, "kvendra.http", "request", &args).is_ok());
    }

    #[test]
    fn methods_envelope_blocks_post() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.http
      operations:
        - request:
            methods: ["GET"]
"#,
        );
        let args = env_args(serde_json::json!({ "method": "POST" }));
        let err = check(&s, "kvendra.http", "request", &args).unwrap_err();
        assert!(matches!(err, KvendraError::AllowlistViolation(_)));
    }

    // -----------------------------------------------------------------
    // BLOQUE B — happy + violation per new field (TIER 1..4).
    // -----------------------------------------------------------------

    // ---- TIER 1 ------------------------------------------------------

    fn aws_s3_sync_with_buckets(buckets: &[&str]) -> ProfileSpec {
        let list = buckets
            .iter()
            .map(|b| format!("\"{b}\""))
            .collect::<Vec<_>>()
            .join(",");
        spec_with(&format!(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.aws
      operations:
        - s3_sync:
            buckets: [{list}]
            accept_destructive: true
"#
        ))
    }

    #[test]
    fn buckets_happy_s3_uri() {
        let s = aws_s3_sync_with_buckets(&["kvendra-com-prod"]);
        let args =
            env_args(serde_json::json!({ "src": "./build", "dst": "s3://kvendra-com-prod/site" }));
        assert!(check(&s, "kvendra.aws", "s3_sync", &args).is_ok());
    }

    #[test]
    fn buckets_blocks_other_bucket() {
        // CANONICAL REGRESSION TEST — AC-M2-6 (ISSUE-KVD-CLI-031).
        let s = aws_s3_sync_with_buckets(&["kvendra-com-prod"]);
        let args =
            env_args(serde_json::json!({ "src": "./build", "dst": "s3://attacker-bucket/x" }));
        let err = check(&s, "kvendra.aws", "s3_sync", &args).unwrap_err();
        assert!(matches!(err, KvendraError::AllowlistViolation(_)));
    }

    #[test]
    fn buckets_blocks_bare_name() {
        let s = aws_s3_sync_with_buckets(&["kvendra-com-prod"]);
        let args = env_args(serde_json::json!({ "bucket": "elsewhere" }));
        let err = check(&s, "kvendra.aws", "s3_sync", &args).unwrap_err();
        assert!(matches!(err, KvendraError::AllowlistViolation(_)));
    }

    #[test]
    fn forbidden_methods_blocks_delete() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.http
      operations:
        - request:
            methods: ["GET","DELETE"]
            forbidden_methods: ["DELETE"]
"#,
        );
        let args = env_args(serde_json::json!({ "method": "DELETE" }));
        let err = check(&s, "kvendra.http", "request", &args).unwrap_err();
        assert!(matches!(err, KvendraError::AllowlistViolation(_)));
    }

    #[test]
    fn forbidden_methods_allows_get() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.http
      operations:
        - request:
            methods: ["GET","DELETE"]
            forbidden_methods: ["DELETE"]
"#,
        );
        let args = env_args(serde_json::json!({ "method": "GET" }));
        assert!(check(&s, "kvendra.http", "request", &args).is_ok());
    }

    #[test]
    fn forbidden_fields_blocks_token() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - update_repo:
            forbidden_fields: ["token"]
"#,
        );
        let args =
            env_args(serde_json::json!({ "owner": "Foo", "repo": "bar", "token": "leaked" }));
        let err = check(&s, "kvendra.github", "update_repo", &args).unwrap_err();
        assert!(matches!(err, KvendraError::AllowlistViolation(_)));
    }

    #[test]
    fn forbidden_fields_passes_when_absent() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - update_repo:
            forbidden_fields: ["token"]
"#,
        );
        let args = env_args(serde_json::json!({ "owner": "Foo", "repo": "bar" }));
        assert!(check(&s, "kvendra.github", "update_repo", &args).is_ok());
    }

    #[test]
    fn forbidden_env_export_blocks_aws_key() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.shell
      operations:
        - run:
            forbidden_env_export_to_agent: ["AWS_SECRET_ACCESS_KEY"]
"#,
        );
        let args = env_args(serde_json::json!({
            "env": { "AWS_SECRET_ACCESS_KEY": "leaked" }
        }));
        let err = check(&s, "kvendra.shell", "run", &args).unwrap_err();
        assert!(matches!(err, KvendraError::AllowlistViolation(_)));
    }

    #[test]
    fn forbidden_env_export_passes_for_path() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.shell
      operations:
        - run:
            forbidden_env_export_to_agent: ["AWS_SECRET_ACCESS_KEY"]
"#,
        );
        let args = env_args(serde_json::json!({
            "env": { "PATH": "/usr/bin" }
        }));
        assert!(check(&s, "kvendra.shell", "run", &args).is_ok());
    }

    #[test]
    fn url_pattern_regex_happy() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.http
      operations:
        - request:
            url_pattern_regex: ['^https://api\.example\.com/.*']
"#,
        );
        let args = env_args(serde_json::json!({ "url": "https://api.example.com/foo" }));
        assert!(check(&s, "kvendra.http", "request", &args).is_ok());
    }

    #[test]
    fn url_pattern_regex_blocks_other_host() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.http
      operations:
        - request:
            url_pattern_regex: ['^https://api\.example\.com/.*']
"#,
        );
        let args = env_args(serde_json::json!({ "url": "https://evil.com/x" }));
        let err = check(&s, "kvendra.http", "request", &args).unwrap_err();
        assert!(matches!(err, KvendraError::AllowlistViolation(_)));
    }

    #[test]
    fn endpoints_alias_unions_with_url_pattern_regex() {
        // D6 — `endpoints` provides literal exact-match alongside regex.
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.http
      operations:
        - request:
            endpoints: ["https://special.example.com/health"]
"#,
        );
        let ok = env_args(serde_json::json!({ "url": "https://special.example.com/health" }));
        assert!(check(&s, "kvendra.http", "request", &ok).is_ok());

        let bad = env_args(serde_json::json!({ "url": "https://special.example.com/admin" }));
        assert!(check(&s, "kvendra.http", "request", &bad).is_err());
    }

    // ---- TIER 2 ------------------------------------------------------

    #[test]
    fn distributions_happy() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.aws
      operations:
        - cloudfront_invalidate:
            distributions: ["E2MSK8NR0QTV9W"]
"#,
        );
        let args = env_args(serde_json::json!({ "distribution_id": "E2MSK8NR0QTV9W" }));
        assert!(check(&s, "kvendra.aws", "cloudfront_invalidate", &args).is_ok());
    }

    #[test]
    fn distributions_blocks_other() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.aws
      operations:
        - cloudfront_invalidate:
            distributions: ["E2MSK8NR0QTV9W"]
"#,
        );
        let args = env_args(serde_json::json!({ "distribution_id": "E0FAKE0FAKE" }));
        assert!(check(&s, "kvendra.aws", "cloudfront_invalidate", &args).is_err());
    }

    #[test]
    fn functions_happy() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.aws
      operations:
        - lambda_invoke:
            functions: ["kvendra-build-trigger"]
"#,
        );
        let args = env_args(serde_json::json!({ "function_name": "kvendra-build-trigger" }));
        assert!(check(&s, "kvendra.aws", "lambda_invoke", &args).is_ok());
    }

    #[test]
    fn functions_blocks_other() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.aws
      operations:
        - lambda_invoke:
            functions: ["kvendra-build-trigger"]
"#,
        );
        let args = env_args(serde_json::json!({ "function_name": "evil-function" }));
        assert!(check(&s, "kvendra.aws", "lambda_invoke", &args).is_err());
    }

    // NOTE: these tests drive the enforcer with the EXACT wire field the
    // shell primitive emits (`binary`), not the historical `bin` typo. Using
    // `bin` here is what let audit finding C2 pass CI while production was
    // unprotected — the fixtures were complicit in the bug
    // (PAT-KVD-CLI-1A99C5). See `binaries_missing_field_fails_closed` for the
    // fail-closed-on-shape-mismatch guard.
    #[test]
    fn binaries_happy() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.shell
      operations:
        - run:
            binaries: ["npm"]
"#,
        );
        let args = env_args(serde_json::json!({ "binary": "npm" }));
        assert!(check(&s, "kvendra.shell", "run", &args).is_ok());
    }

    #[test]
    fn binaries_blocks_other() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.shell
      operations:
        - run:
            binaries: ["npm"]
"#,
        );
        let args = env_args(serde_json::json!({ "binary": "rm" }));
        let err = check(&s, "kvendra.shell", "run", &args)
            .expect_err("binary outside allowlist must be denied");
        assert!(
            matches!(err, KvendraError::AllowlistViolation(ref m) if m.contains("'rm'")),
            "got: {err:?}"
        );
    }

    /// C2 regression — a `binaries:` constraint with NO `binary` field in the
    /// payload must FAIL CLOSED, not fall through as allowed. Guards against
    /// permissive-on-absence resurfacing via a field rename.
    #[test]
    fn binaries_missing_field_fails_closed() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.shell
      operations:
        - run:
            binaries: ["npm"]
"#,
        );
        // Historical wrong key — enforcer must NOT be fooled into allowing.
        let args = env_args(serde_json::json!({ "bin": "rm" }));
        assert!(
            check(&s, "kvendra.shell", "run", &args).is_err(),
            "a payload with no `binary` field but a `binaries` constraint must be denied"
        );
        // Empty payload — same fail-closed outcome.
        let empty = env_args(serde_json::json!({}));
        assert!(check(&s, "kvendra.shell", "run", &empty).is_err());
    }

    #[test]
    fn packages_happy() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.npm
      operations:
        - publish:
            packages: ["@kvendra/*"]
            accept_destructive: true
"#,
        );
        let args = env_args(serde_json::json!({ "package": "@kvendra/cli" }));
        assert!(check(&s, "kvendra.npm", "publish", &args).is_ok());
    }

    #[test]
    fn packages_blocks_other_scope() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.npm
      operations:
        - publish:
            packages: ["@kvendra/*"]
            accept_destructive: true
"#,
        );
        let args = env_args(serde_json::json!({ "package": "@evil/typosquat" }));
        assert!(check(&s, "kvendra.npm", "publish", &args).is_err());
    }

    #[test]
    fn projects_happy() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.pypi
      operations:
        - publish:
            projects: ["kvendra"]
            accept_destructive: true
"#,
        );
        let args = env_args(serde_json::json!({ "project": "kvendra" }));
        assert!(check(&s, "kvendra.pypi", "publish", &args).is_ok());
    }

    #[test]
    fn projects_blocks_other() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.pypi
      operations:
        - publish:
            projects: ["kvendra"]
            accept_destructive: true
"#,
        );
        let args = env_args(serde_json::json!({ "project": "evil-typosquat" }));
        assert!(check(&s, "kvendra.pypi", "publish", &args).is_err());
    }

    #[test]
    fn refs_happy() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - push:
            repos: ["github.com/Foo/*"]
            refs: ["refs/heads/main"]
            accept_destructive: true
"#,
        );
        let args = env_args(serde_json::json!({
            "repo": "github.com/Foo/bar",
            "ref": "refs/heads/main"
        }));
        assert!(check(&s, "kvendra.git", "push", &args).is_ok());
    }

    #[test]
    fn refs_blocks_release_branch() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - push:
            repos: ["github.com/Foo/*"]
            refs: ["refs/heads/main"]
            accept_destructive: true
"#,
        );
        let args = env_args(serde_json::json!({
            "repo": "github.com/Foo/bar",
            "ref": "refs/heads/release/1.0"
        }));
        assert!(check(&s, "kvendra.git", "push", &args).is_err());
    }

    #[test]
    fn tag_pattern_happy() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - tag:
            tag_pattern: ['v\d+\.\d+\.\d+']
            accept_destructive: true
"#,
        );
        let args = env_args(serde_json::json!({ "tag": "v1.2.3" }));
        assert!(check(&s, "kvendra.git", "tag", &args).is_ok());
    }

    #[test]
    fn tag_pattern_blocks_freeform() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - tag:
            tag_pattern: ['v\d+\.\d+\.\d+']
            accept_destructive: true
"#,
        );
        let args = env_args(serde_json::json!({ "tag": "evil-tag" }));
        assert!(check(&s, "kvendra.git", "tag", &args).is_err());
    }

    // ---- TIER 3 ------------------------------------------------------

    #[test]
    fn fields_allowed_happy() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - update_repo:
            fields_allowed: ["owner","repo","description"]
"#,
        );
        let args =
            env_args(serde_json::json!({ "owner": "Foo", "repo": "bar", "description": "ok" }));
        assert!(check(&s, "kvendra.github", "update_repo", &args).is_ok());
    }

    #[test]
    fn fields_allowed_blocks_unknown_field() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - update_repo:
            fields_allowed: ["owner","repo","description"]
"#,
        );
        let args = env_args(serde_json::json!({
            "owner": "Foo", "repo": "bar", "homepage": "evil"
        }));
        assert!(check(&s, "kvendra.github", "update_repo", &args).is_err());
    }

    #[test]
    fn org_happy_owner_field() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - update_repo:
            org: ["KvendraAI"]
"#,
        );
        let args = env_args(serde_json::json!({ "owner": "KvendraAI", "repo": "kvendra-cli" }));
        assert!(check(&s, "kvendra.github", "update_repo", &args).is_ok());
    }

    #[test]
    fn org_extracted_from_repo_url_blocks_other() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - update_repo:
            org: ["KvendraAI"]
"#,
        );
        let args = env_args(serde_json::json!({ "repo": "github.com/EvilCorp/x" }));
        assert!(check(&s, "kvendra.github", "update_repo", &args).is_err());
    }

    #[test]
    fn repo_alias_unions_with_repos_happy() {
        // D1 — `repo` (singular) alias unions with `repos`.
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - clone:
            repo: ["github.com/Foo/legacy"]
            repos: ["github.com/Foo/*"]
"#,
        );
        let ok_repos = env_args(serde_json::json!({ "repo": "github.com/Foo/bar" }));
        assert!(check(&s, "kvendra.git", "clone", &ok_repos).is_ok());

        let ok_alias = env_args(serde_json::json!({ "repo": "github.com/Foo/legacy" }));
        assert!(check(&s, "kvendra.git", "clone", &ok_alias).is_ok());
    }

    #[test]
    fn repo_alias_blocks_when_neither_matches() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - clone:
            repo: ["github.com/Foo/legacy"]
            repos: ["github.com/Foo/*"]
"#,
        );
        let bad = env_args(serde_json::json!({ "repo": "github.com/EvilCorp/x" }));
        assert!(check(&s, "kvendra.git", "clone", &bad).is_err());
    }

    // -----------------------------------------------------------------
    // ISSUE-KVD-CLI-043 — args.url canonicalization closes the
    // permissive-on-absence gap. `clone` callers may pass
    // `args.url` (canonical) instead of `args.repo`; the enforcer must
    // match either against `repos: [...]`.
    // -----------------------------------------------------------------

    #[test]
    fn clone_with_args_url_matches_repos_pattern_happy() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - clone:
            repos: ["github.com/KvendraAI/*"]
"#,
        );
        let ok = env_args(serde_json::json!({
            "url": "https://github.com/KvendraAI/kvendra-cli"
        }));
        assert!(check(&s, "kvendra.git", "clone", &ok).is_ok());

        let ok_dotgit = env_args(serde_json::json!({
            "url": "https://github.com/KvendraAI/kvendra-cli.git"
        }));
        assert!(check(&s, "kvendra.git", "clone", &ok_dotgit).is_ok());
    }

    #[test]
    fn clone_with_args_url_violates_repos_pattern_rejection() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - clone:
            repos: ["github.com/KvendraAI/*"]
"#,
        );
        let bad = env_args(serde_json::json!({
            "url": "https://github.com/EvilCorp/malware"
        }));
        assert!(check(&s, "kvendra.git", "clone", &bad).is_err());
    }

    #[test]
    fn extract_repo_canonical_handles_https() {
        assert_eq!(
            extract_repo_canonical("https://github.com/Foo/Bar"),
            "github.com/Foo/Bar"
        );
        assert_eq!(
            extract_repo_canonical("https://github.com/Foo/Bar.git"),
            "github.com/Foo/Bar"
        );
        assert_eq!(
            extract_repo_canonical("http://github.com/Foo/Bar.git"),
            "github.com/Foo/Bar"
        );
    }

    #[test]
    fn extract_repo_canonical_handles_git_at() {
        assert_eq!(
            extract_repo_canonical("git@github.com:Foo/Bar.git"),
            "github.com/Foo/Bar"
        );
        assert_eq!(
            extract_repo_canonical("git@github.com:Foo/Bar"),
            "github.com/Foo/Bar"
        );
    }

    #[test]
    fn extract_repo_canonical_handles_passthrough() {
        assert_eq!(
            extract_repo_canonical("github.com/Foo/Bar"),
            "github.com/Foo/Bar"
        );
        assert_eq!(
            extract_repo_canonical("  github.com/Foo/Bar  "),
            "github.com/Foo/Bar"
        );
    }

    #[test]
    fn cwd_pattern_happy() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.shell
      operations:
        - run:
            cwd_pattern: '^/Users/[^/]+/Develop/Kvendra/.*'
"#,
        );
        let args = env_args(serde_json::json!({
            "cwd": "/Users/jp/Develop/Kvendra/kvendra-cli"
        }));
        assert!(check(&s, "kvendra.shell", "run", &args).is_ok());
    }

    #[test]
    fn cwd_pattern_blocks_outside() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.shell
      operations:
        - run:
            cwd_pattern: '^/Users/[^/]+/Develop/Kvendra/.*'
"#,
        );
        let args = env_args(serde_json::json!({ "cwd": "/etc" }));
        assert!(check(&s, "kvendra.shell", "run", &args).is_err());
    }

    // ---- TIER 4 ------------------------------------------------------

    #[test]
    fn args_constraints_happy_match() {
        // D2 — argv must match at least one template; templates strict-length.
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.shell
      operations:
        - run:
            args_constraints:
              - allowed: ["build"]
              - allowed: ["test","--coverage"]
"#,
        );
        let ok1 = env_args(serde_json::json!({ "argv": ["build"] }));
        assert!(check(&s, "kvendra.shell", "run", &ok1).is_ok());
        let ok2 = env_args(serde_json::json!({ "argv": ["test","--coverage"] }));
        assert!(check(&s, "kvendra.shell", "run", &ok2).is_ok());
    }

    #[test]
    fn args_constraints_blocks_no_match() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.shell
      operations:
        - run:
            args_constraints:
              - allowed: ["build"]
"#,
        );
        let bad = env_args(serde_json::json!({ "argv": ["evil","--rm-rf"] }));
        assert!(check(&s, "kvendra.shell", "run", &bad).is_err());
    }

    #[test]
    fn args_constraints_supports_wildcard_token() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.shell
      operations:
        - run:
            args_constraints:
              - allowed: ["test","*"]
"#,
        );
        let ok = env_args(serde_json::json!({ "argv": ["test","--filter=foo"] }));
        assert!(check(&s, "kvendra.shell", "run", &ok).is_ok());
    }

    #[test]
    fn env_vars_to_inject_happy() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.shell
      operations:
        - run:
            env_vars_to_inject: ["PATH","NODE_ENV"]
"#,
        );
        let args = env_args(serde_json::json!({
            "env": { "PATH": "/usr/bin", "NODE_ENV": "production" }
        }));
        assert!(check(&s, "kvendra.shell", "run", &args).is_ok());
    }

    #[test]
    fn env_vars_to_inject_blocks_unknown_key() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.shell
      operations:
        - run:
            env_vars_to_inject: ["PATH"]
"#,
        );
        let args = env_args(serde_json::json!({
            "env": { "AWS_SECRET_ACCESS_KEY": "leaked" }
        }));
        assert!(check(&s, "kvendra.shell", "run", &args).is_err());
    }

    // -----------------------------------------------------------------
    // BLOQUE D — defense-in-depth edge cases.
    // -----------------------------------------------------------------

    #[test]
    fn missing_inner_args_passes_with_no_constraints() {
        // No constraints declared → empty inner is fine.
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - clone: {}
"#,
        );
        let args = serde_json::json!({ "profile_id": "x", "operation": "clone" });
        assert!(check(&s, "kvendra.git", "clone", &args).is_ok());
    }

    #[test]
    fn empty_inner_args_blocks_when_field_required() {
        // A `kvendra.git` op with a `repos` constraint but no determinable
        // target (no url, no resolvable remote in cwd) now FAILS CLOSED
        // (ISSUE-KVD-CLI-B78ED5 N7). This corrects the previous permissive-on-
        // absence semantics (PAT-KVD-CLI-003 anti-pattern) that let the repo
        // constraint be skipped whenever the enforcer could not see a repo.
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - clone:
            repos: ["github.com/Foo/*"]
"#,
        );
        let args = env_args(serde_json::json!({}));
        // Fail-closed: no target repo to validate ⇒ deny, not allow.
        assert!(check(&s, "kvendra.git", "clone", &args).is_err());
    }

    // ---- N7: repo enforcement on the REAL git push shape {cwd, remote, ref} --
    // These use no synthetic `repo` field (which the real kvendra.git primitive
    // never sends), so they exercise the production path the old tests missed.

    fn n7_git_spec() -> ProfileSpec {
        spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - push:
            repos: ["KvendraAI/kvendra-cli"]
            refs: ["refs/heads/main"]
            accept_destructive: true
"#,
        )
    }

    fn tmp_git_repo(origin_url: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("kvendra-n7-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::write(
            dir.join(".git").join("config"),
            format!("[remote \"origin\"]\n\turl = {origin_url}\n"),
        )
        .unwrap();
        dir
    }

    #[test]
    fn n7_push_with_attacker_url_remote_is_denied() {
        // remote = an attacker URL. Pre-N7 the enforcer saw no `repo`/`url`
        // field and SKIPPED the repos check → push allowed. Now the URL is the
        // target and does not match the allowlist → deny.
        let s = n7_git_spec();
        let args = env_args(serde_json::json!({
            "cwd": "/tmp/whatever",
            "remote": "https://github.com/attacker/evil.git",
            "ref": "refs/heads/main"
        }));
        assert!(check(&s, "kvendra.git", "push", &args).is_err());
    }

    #[test]
    fn n7_push_to_attacker_host_same_name_is_denied() {
        // Credential-exfil shape: same owner/name but an attacker HOST. The
        // host stays in the comparison, so this must NOT match a github.com
        // pattern.
        let s = n7_git_spec();
        let args = env_args(serde_json::json!({
            "cwd": "/tmp/whatever",
            "remote": "https://evil.com/KvendraAI/kvendra-cli.git",
            "ref": "refs/heads/main"
        }));
        assert!(check(&s, "kvendra.git", "push", &args).is_err());
    }

    #[test]
    fn n7_push_origin_resolves_from_cwd_config_and_matches_allowlist() {
        // The legitimate flow: remote = "origin", resolved from the cwd's git
        // config to an allowlisted repo → allowed. (This is the owner's own
        // push path; the fix must not break it.)
        let s = n7_git_spec();
        let dir = tmp_git_repo("git@github.com:KvendraAI/kvendra-cli.git");
        let args = env_args(serde_json::json!({
            "cwd": dir.to_str().unwrap(),
            "remote": "origin",
            "ref": "refs/heads/main"
        }));
        let res = check(&s, "kvendra.git", "push", &args);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(res.is_ok(), "legit origin push must be allowed: {res:?}");
    }

    #[test]
    fn n7_push_origin_pointing_at_disallowed_repo_is_denied() {
        // remote = "origin" but the cwd's origin is a NON-allowlisted repo →
        // deny (an agent cannot smuggle a push by choosing a checkout).
        let s = n7_git_spec();
        let dir = tmp_git_repo("git@github.com:attacker/evil.git");
        let args = env_args(serde_json::json!({
            "cwd": dir.to_str().unwrap(),
            "remote": "origin",
            "ref": "refs/heads/main"
        }));
        let res = check(&s, "kvendra.git", "push", &args);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(res.is_err(), "push to a disallowed origin must be denied");
    }

    #[test]
    fn n7_push_unresolvable_remote_fails_closed() {
        // remote = a name with no cwd config to resolve → cannot determine the
        // target → fail closed.
        let s = n7_git_spec();
        let args = env_args(serde_json::json!({
            "cwd": "/tmp/not-a-git-repo-xyz",
            "remote": "origin",
            "ref": "refs/heads/main"
        }));
        assert!(check(&s, "kvendra.git", "push", &args).is_err());
    }

    #[test]
    fn forbidden_methods_runs_before_methods_allow_list() {
        // D4 — denylist beats allowlist (fail-closed).
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.http
      operations:
        - request:
            methods: ["GET","DELETE"]
            forbidden_methods: ["DELETE"]
"#,
        );
        let args = env_args(serde_json::json!({ "method": "DELETE" }));
        let err = check(&s, "kvendra.http", "request", &args).unwrap_err();
        match err {
            KvendraError::AllowlistViolation(msg) => {
                assert!(msg.contains("forbidden method"));
            }
            other => panic!("expected AllowlistViolation, got {other:?}"),
        }
    }

    #[test]
    fn buckets_handles_s3_uri_with_no_path() {
        let s = aws_s3_sync_with_buckets(&["kvendra-com-prod"]);
        let args = env_args(serde_json::json!({ "dst": "s3://kvendra-com-prod" }));
        assert!(check(&s, "kvendra.aws", "s3_sync", &args).is_ok());
    }

    #[test]
    fn url_pattern_invalid_regex_blocks() {
        // Defensive: a malformed regex must not silently allow.
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.http
      operations:
        - request:
            url_pattern_regex: ["[invalid("]
"#,
        );
        let args = env_args(serde_json::json!({ "url": "https://anything" }));
        assert!(check(&s, "kvendra.http", "request", &args).is_err());
    }

    #[test]
    fn fields_allowed_envelope_keys_not_visible() {
        // Envelope-level `profile_id`/`operation` must NOT trip
        // `fields_allowed` because they live one level up.
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - update_repo:
            fields_allowed: ["owner","repo"]
"#,
        );
        let args = serde_json::json!({
            "profile_id": "x",
            "operation": "update_repo",
            "args": { "owner": "Foo", "repo": "bar" }
        });
        assert!(check(&s, "kvendra.github", "update_repo", &args).is_ok());
    }

    #[test]
    fn argv_template_strict_length() {
        // D2 — strict length: shorter argv than template is a no-match.
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.shell
      operations:
        - run:
            args_constraints:
              - allowed: ["build","--release"]
"#,
        );
        let bad = env_args(serde_json::json!({ "argv": ["build"] }));
        assert!(check(&s, "kvendra.shell", "run", &bad).is_err());
    }

    // -----------------------------------------------------------------
    // BLOQUE — glob_match single-segment wildcard (REQ-KVD-CLI-E0C962).
    // Cubre AC-GLOB-1..AC-GLOB-7. Ejercita `glob_match` indirectamente
    // a través de `check()` (helper privado, no expuesto pub(super)).
    // -----------------------------------------------------------------

    #[test]
    fn glob_star_matches_versioned_tag() {
        // AC-GLOB-1: `refs/tags/v*` matchea `refs/tags/v0.4.0-alpha.3`.
        // Reproduce el caso del ISSUE-KVD-CLI-280B87.
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - push:
            repos: ["github.com/Foo/*"]
            refs: ["refs/tags/v*"]
            accept_destructive: true
"#,
        );
        let args = env_args(serde_json::json!({
            "repo": "github.com/Foo/bar",
            "ref": "refs/tags/v0.4.0-alpha.3"
        }));
        assert!(check(&s, "kvendra.git", "push", &args).is_ok());
    }

    #[test]
    fn glob_star_release_branch_no_cross_slash() {
        // AC-GLOB-2 positivo: `refs/heads/release/*` matchea `refs/heads/release/v1`.
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - push:
            repos: ["github.com/Foo/*"]
            refs: ["refs/heads/release/*"]
            accept_destructive: true
"#,
        );
        let args = env_args(serde_json::json!({
            "repo": "github.com/Foo/bar",
            "ref": "refs/heads/release/v1"
        }));
        assert!(check(&s, "kvendra.git", "push", &args).is_ok());
    }

    #[test]
    fn glob_star_rejects_cross_slash() {
        // AC-GLOB-2 negativo (D8 boundary): `refs/heads/release/*` NO matchea
        // `refs/heads/release/v1/sub`. El matcher previo PERMITÍA este caso
        // (bug latente alineado con TEST-KVD-CLI-097 B2b).
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - push:
            repos: ["github.com/Foo/*"]
            refs: ["refs/heads/release/*"]
            accept_destructive: true
"#,
        );
        let args = env_args(serde_json::json!({
            "repo": "github.com/Foo/bar",
            "ref": "refs/heads/release/v1/sub"
        }));
        let err = check(&s, "kvendra.git", "push", &args).unwrap_err();
        assert!(matches!(err, KvendraError::AllowlistViolation(_)));
    }

    #[test]
    fn glob_star_at_middle_bucket() {
        // AC-GLOB-3: `*` puede aparecer en mitad del pattern.
        // `kvendra-*-prod` matchea `kvendra-com-prod`.
        let s = aws_s3_sync_with_buckets(&["kvendra-*-prod"]);
        let args =
            env_args(serde_json::json!({ "src": "./build", "dst": "s3://kvendra-com-prod/foo" }));
        assert!(check(&s, "kvendra.aws", "s3_sync", &args).is_ok());
    }

    #[test]
    fn glob_special_chars_treated_as_literal() {
        // AC-GLOB-4: `.` en el pattern se trata literalmente, NO como
        // regex any-char. `release.v*` matchea `release.v1` pero NO `releaseXv1`.
        let s = aws_s3_sync_with_buckets(&["release.v*"]);
        let ok_args =
            env_args(serde_json::json!({ "src": "./build", "dst": "s3://release.v1/foo" }));
        assert!(check(&s, "kvendra.aws", "s3_sync", &ok_args).is_ok());
        let bad_args =
            env_args(serde_json::json!({ "src": "./build", "dst": "s3://releaseXv1/foo" }));
        let err = check(&s, "kvendra.aws", "s3_sync", &bad_args).unwrap_err();
        assert!(matches!(err, KvendraError::AllowlistViolation(_)));
    }

    #[test]
    fn glob_full_match_anchored_repos() {
        // AC-GLOB-5: el match está anclado full-string (^...$). El pattern
        // `github.com/KvendraAI/*` no debe matchear un repo arbitrario donde
        // `KvendraAI` aparece en medio (post `extract_repo_canonical`).
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - push:
            repos: ["github.com/KvendraAI/*"]
            accept_destructive: true
"#,
        );
        let args = env_args(serde_json::json!({
            "repo": "github.com/OrgX/KvendraAI-evil",
            "ref": "refs/heads/main"
        }));
        let err = check(&s, "kvendra.git", "push", &args).unwrap_err();
        assert!(matches!(err, KvendraError::AllowlistViolation(_)));
    }

    #[test]
    fn glob_no_permissive_on_absence_via_unmatched_pattern() {
        // AC-GLOB-7: cuando `refs` está declarado con un pattern que NO
        // matchea el ref del call, el enforcer rechaza. Confirma que el
        // matcher no introduce permissive-on-absence (PAT-KVD-CLI-003)
        // — la lógica `if let Some(allowed) && !any(match)` sigue
        // retornando Err si no hay match.
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - push:
            repos: ["github.com/Foo/*"]
            refs: ["never-matches-this-literal-xyz"]
            accept_destructive: true
"#,
        );
        let args = env_args(serde_json::json!({
            "repo": "github.com/Foo/bar",
            "ref": "refs/heads/main"
        }));
        let err = check(&s, "kvendra.git", "push", &args).unwrap_err();
        assert!(matches!(err, KvendraError::AllowlistViolation(_)));
    }

    #[test]
    fn create_issue_passes_with_allowlisted_repo() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - create_issue:
            repos: ["KvendraAI/kvendra-cli"]
            accept_destructive: true
"#,
        );
        let args = env_args(serde_json::json!({
            "repo": "KvendraAI/kvendra-cli",
            "title": "hello"
        }));
        assert!(check(&s, "kvendra.github", "create_issue", &args).is_ok());
    }

    #[test]
    fn create_issue_blocked_when_repo_not_in_allowlist() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - create_issue:
            repos: ["KvendraAI/kvendra-cli"]
            accept_destructive: true
"#,
        );
        let args = env_args(serde_json::json!({
            "repo": "EvilCorp/other",
            "title": "hello"
        }));
        let err = check(&s, "kvendra.github", "create_issue", &args).unwrap_err();
        assert!(matches!(err, KvendraError::AllowlistViolation(_)));
    }

    #[test]
    fn list_issues_passes_read_only() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - list_issues:
            repos: ["KvendraAI/kvendra-cli"]
"#,
        );
        let args = env_args(serde_json::json!({
            "repo": "KvendraAI/kvendra-cli"
        }));
        assert!(check(&s, "kvendra.github", "list_issues", &args).is_ok());
    }

    #[test]
    fn create_issue_not_declared_in_yaml_is_violation() {
        let s = spec_with(
            r#"
profile_id: x
secret:
  type: t
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - read_repo:
            repos: ["KvendraAI/kvendra-cli"]
"#,
        );
        let args = env_args(serde_json::json!({
            "repo": "KvendraAI/kvendra-cli",
            "title": "hello"
        }));
        let err = check(&s, "kvendra.github", "create_issue", &args).unwrap_err();
        assert!(matches!(err, KvendraError::AllowlistViolation(_)));
    }
}
