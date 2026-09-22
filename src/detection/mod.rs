//! Detection layer (REQ-KVD-002 Bloque 7).
//!
//! - Pre-compiled `RegexSet` of 7 provider patterns + AWS secret-key env form
//!   (cached in a `OnceLock`).
//! - Shannon-entropy filter drops obvious lorem-ipsum false positives.
//! - Severity (`warn | error | block`) is configurable via [`Config`].
//! - Activation hook in [`crate::mcp::server`] inspects `tools/call`
//!   `arguments` BEFORE dispatch.

pub mod patterns;

use crate::config::DetectionSeverity;
use regex::{Regex, RegexSet};
use std::collections::HashSet;
use std::sync::OnceLock;

/// Severity decision for a detected token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Warn,
    Error,
    Block,
}

impl Decision {
    pub fn from_severity(sev: DetectionSeverity) -> Self {
        match sev {
            DetectionSeverity::Warn => Decision::Warn,
            DetectionSeverity::Error => Decision::Error,
            DetectionSeverity::Block => Decision::Block,
        }
    }
}

/// Match result.
#[derive(Debug, Clone)]
pub struct DetectionMatch {
    pub provider: String,
    pub matched_text: String,
    pub entropy_bits_per_char: f64,
}

/// Lazily-compiled set + per-provider regexes.
struct CompiledPatterns {
    set: RegexSet,
    individual: Vec<Regex>,
    providers: Vec<&'static str>,
}

static PATTERNS: OnceLock<CompiledPatterns> = OnceLock::new();

fn compiled() -> &'static CompiledPatterns {
    PATTERNS.get_or_init(|| {
        let providers: Vec<&'static str> = patterns::PROVIDER_PATTERNS
            .iter()
            .map(|(p, _)| *p)
            .collect();
        let regexes: Vec<&str> = patterns::PROVIDER_PATTERNS
            .iter()
            .map(|(_, r)| *r)
            .collect();
        let set = RegexSet::new(&regexes).expect("compile detection RegexSet");
        let individual: Vec<Regex> = regexes
            .iter()
            .map(|r| Regex::new(r).expect("compile detection regex"))
            .collect();
        CompiledPatterns {
            set,
            individual,
            providers,
        }
    })
}

/// Shannon entropy in bits/char of a byte slice (printable ASCII assumed).
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let total = s.len() as f64;
    let mut h = 0.0_f64;
    for c in counts.iter() {
        if *c == 0 {
            continue;
        }
        let p = *c as f64 / total;
        h -= p * p.log2();
    }
    h
}

/// Threshold separating real high-entropy tokens from human-readable strings
/// like `"ghp_lorem_ipsum_dolor_sit_amet_..."`.
pub const ENTROPY_THRESHOLD: f64 = 3.5;

/// One regex hit that passed the entropy gate, with its span in the haystack.
/// Private: the plaintext never leaves this module.
struct RawMatch {
    start: usize,
    end: usize,
    text: String,
    entropy: f64,
}

/// THE shared selector behind the decider ([`detect`]) and the executor
/// ([`sanitize_output`]) — one canonicaliser per operand, per
/// PAT-KVD-CLI-C18A74.
///
/// Returns EVERY match of provider `idx` in `haystack` that passes the entropy
/// gate, in order. The gate is applied per match: a low-entropy decoy of the
/// right shape must never disqualify the provider for the whole payload
/// (ISSUE-KVD-CLI-8F501A).
fn matches_above_threshold(idx: usize, haystack: &str) -> Vec<RawMatch> {
    let cp = compiled();
    let provider = cp.providers[idx];
    let always = patterns::ALWAYS_REDACT_PROVIDERS.contains(&provider);
    cp.individual[idx]
        .find_iter(haystack)
        .filter_map(|m| {
            let text = m.as_str().to_string();
            let entropy = shannon_entropy(&text);
            (always || entropy >= ENTROPY_THRESHOLD).then(|| RawMatch {
                start: m.start(),
                end: m.end(),
                text,
                entropy,
            })
        })
        .collect()
}

/// Run the regex set against `haystack`. Returns matches that pass the
/// entropy filter.
pub fn detect(haystack: &str) -> Vec<DetectionMatch> {
    let cp = compiled();
    let hits = cp.set.matches(haystack);
    let mut out = Vec::new();
    let mut seen: HashSet<(usize, String)> = HashSet::new();
    for idx in hits.iter() {
        let provider = cp.providers[idx];
        // Redact-only providers (JWT, Google OAuth) are commonly legitimate
        // inbound arguments; do not let them block/quarantine a call.
        if patterns::REDACT_ONLY_PROVIDERS.contains(&provider) {
            continue;
        }
        for m in matches_above_threshold(idx, haystack) {
            // Identical repeats of the same secret are ONE finding; distinct
            // secrets of the same provider are each reported.
            if !seen.insert((idx, m.text.clone())) {
                continue;
            }
            out.push(DetectionMatch {
                provider: provider.to_string(),
                matched_text: m.text,
                entropy_bits_per_char: m.entropy,
            });
        }
    }
    out
}

/// Redact EXACT known secret values (and nothing else) from `text`. Pattern
/// detection only catches recognized token *shapes*; the broker holds the exact
/// plaintext it injected, so an opaque/unrecognized credential reflected back by
/// an endpoint can be scrubbed by literal value here. Empty/very short values
/// are ignored to avoid mangling unrelated output.
pub fn redact_values(text: &str, values: &[String]) -> String {
    let mut out = text.to_string();
    for v in values {
        if v.len() >= 8 {
            out = out.replace(v.as_str(), "<redacted:secret-value>");
        }
    }
    out
}

/// Sanitize an output string by replacing detected tokens with a redaction
/// marker. Used by primitive response sanitizers.
pub fn sanitize_output(s: &str) -> String {
    let cp = compiled();
    let mut out = s.to_string();
    let hits = cp.set.matches(&out);
    if !hits.matched_any() {
        return out;
    }
    // Same selector as `detect`, applied sequentially per provider on the
    // CURRENT `out` — byte-identical to the previous per-provider
    // `replace_all` chain, including how a later provider sees the text an
    // earlier one already rewrote.
    for idx in hits.iter() {
        let provider = cp.providers[idx];
        let marks = matches_above_threshold(idx, &out);
        if marks.is_empty() {
            continue;
        }
        let mut next = String::with_capacity(out.len());
        let mut cursor = 0usize;
        for m in &marks {
            next.push_str(&out[cursor..m.start]);
            next.push_str(&format!("<redacted:{provider}>"));
            cursor = m.end;
        }
        next.push_str(&out[cursor..]);
        out = next;
    }
    out
}

/// Recursively sanitize every `String` leaf inside a `serde_json::Value`,
/// replacing detected tokens with redaction markers. Used to sanitize the
/// MCP `structuredContent` and `error.message`/`error.data` fields before
/// emitting them on the wire (REQ-KVD-002 AC-MCP-3).
pub fn sanitize_value(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::String(s) => {
            let cleaned = sanitize_output(s);
            if cleaned != *s {
                *s = cleaned;
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                sanitize_value(item);
            }
        }
        serde_json::Value::Object(map) => {
            for (_k, val) in map.iter_mut() {
                sanitize_value(val);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_low_for_repeated_chars() {
        assert!(shannon_entropy("aaaaaaaa") < 1.0);
    }

    #[test]
    fn entropy_high_for_random_like() {
        let s = "ghp_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJ";
        let h = shannon_entropy(s);
        assert!(h >= ENTROPY_THRESHOLD, "got {h}");
    }

    #[test]
    fn detects_github_pat_classic() {
        let s = "leaked: ghp_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaaaa";
        let hits = detect(s);
        assert!(hits.iter().any(|h| h.provider == "github_pat_classic"));
    }

    #[test]
    fn jwt_is_redact_only_not_inbound_blocked() {
        // A JWT is commonly a legitimate inbound argument (Authorization bearer),
        // so detect() must NOT flag it (no block/quarantine in severity=block),
        // but sanitize_output MUST still redact it so it is never echoed back.
        let s = "auth: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                 eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.\
                 dQw4w9WgXcQ_abc123XYZ_signature_bits";
        assert!(
            !detect(s).iter().any(|h| h.provider == "jwt"),
            "jwt must not block inbound"
        );
        assert!(
            sanitize_output(s).contains("<redacted:jwt>"),
            "jwt must be redacted in output"
        );
    }

    #[test]
    fn google_oauth_is_redact_only_not_inbound_blocked() {
        let s = "token ya29.a0AfH6SMBx7yQk9vL2mNpQrStUvWxYz0123456789";
        assert!(!detect(s).iter().any(|h| h.provider == "google_oauth_token"));
        assert!(sanitize_output(s).contains("<redacted:google_oauth_token>"));
    }

    #[test]
    fn private_key_redacted_even_without_end_marker() {
        // A truncated key (BEGIN + body, no END) must still be redacted to EOF.
        let s = "log:\n-----BEGIN OPENSSH PRIVATE KEY-----\n\
                 b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAA\n\
                 AAtzc2gtZWQyNTUxOQAAACD9aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJqWxY";
        let out = sanitize_output(s);
        assert!(out.contains("<redacted:private_key_pem>"), "got: {out}");
        assert!(
            !out.contains("b3BlbnNzaC1rZXktdjEA"),
            "key body leaked: {out}"
        );
    }

    #[test]
    fn redact_values_scrubs_exact_opaque_secret() {
        // An opaque credential (no recognized shape) reflected back is scrubbed
        // by exact value.
        let secret = "Zx9Qw-opaque-42kLmNoPqRs".to_string();
        let reflected = format!("resp: {{\"echoed\":\"{secret}\"}}");
        let out = redact_values(&reflected, std::slice::from_ref(&secret));
        assert!(out.contains("<redacted:secret-value>"));
        assert!(!out.contains(&secret));
    }

    #[test]
    fn sanitize_redacts_whole_private_key_block() {
        // The WHOLE block must be redacted, not just the header — otherwise the
        // high-entropy key body would leak (finding: detection completeness).
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
                   b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAA\n\
                   AAtzc2gtZWQyNTUxOQAAACD9aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJqWxY\n\
                   -----END OPENSSH PRIVATE KEY-----";
        let s = format!("here is a key:\n{key}\ndone");
        let out = sanitize_output(&s);
        assert!(out.contains("<redacted:private_key_pem>"), "got: {out}");
        assert!(
            !out.contains("b3BlbnNzaC1rZXktdjEA"),
            "private key body leaked: {out}"
        );
    }

    #[test]
    fn detects_npm_token() {
        let s = "npm_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaaaa";
        let hits = detect(s);
        assert!(hits.iter().any(|h| h.provider == "npm_token"));
    }

    #[test]
    fn detects_pypi_token() {
        let s = "pypi-AgEIcHlwaS5vcmcCJDgyZWUxMTk5LTRkMzAtNGE5MS04YzVjLTk2ZjQ4YzI3ZDViYwACKlszLCJlMmU3MWMxMy01YjQ2LTRkOTMtYjMyOC1lY2EyZWVjZDQ3M2YiXQAABiBp";
        let hits = detect(s);
        assert!(hits.iter().any(|h| h.provider == "pypi_token"));
    }

    #[test]
    fn detects_hf_token() {
        let s = "hf_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaa";
        let hits = detect(s);
        assert!(hits.iter().any(|h| h.provider == "hf_token"));
    }

    #[test]
    fn detects_aws_akid() {
        let s = "AKIAIOSFODNN7EXAMPLE";
        let hits = detect(s);
        assert!(hits.iter().any(|h| h.provider == "aws_akid"));
    }

    #[test]
    fn detects_aws_secret_env() {
        let s = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let hits = detect(s);
        assert!(hits.iter().any(|h| h.provider == "aws_secret_env"));
    }

    #[test]
    fn detects_anthropic_key() {
        let s = "sk-ant-aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJ";
        let hits = detect(s);
        assert!(hits.iter().any(|h| h.provider == "anthropic_key"));
    }

    #[test]
    fn detects_openai_key() {
        let s = "sk-aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJ";
        let hits = detect(s);
        assert!(hits.iter().any(|h| h.provider == "openai_key"));
    }

    #[test]
    fn entropy_filter_drops_lorem_ipsum() {
        // A string that matches the regex shape but is repetitive ASCII.
        // ghp_ followed by 36 of the same char would still be detected unless
        // entropy filter kicks in. We craft a low-entropy string of correct length:
        let s = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let hits = detect(s);
        // Either suppressed by entropy filter (preferred) or has very low entropy.
        for h in &hits {
            assert!(
                h.entropy_bits_per_char >= ENTROPY_THRESHOLD,
                "false positive should have been filtered: {h:?}"
            );
        }
    }

    #[test]
    fn sanitize_replaces_detected_token() {
        let s = "log line with token ghp_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaaaa here";
        let out = sanitize_output(s);
        assert!(out.contains("<redacted:github_pat_classic>"), "got: {out}");
        assert!(!out.contains("ghp_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaaaa"));
    }

    #[test]
    fn sanitize_passes_through_safe_text() {
        let s = "totally safe log message with no secrets";
        assert_eq!(sanitize_output(s), s);
    }

    #[test]
    fn sanitize_structured_content_redacts_github_pat() {
        let mut v = serde_json::json!({
            "stdout": "exporting GITHUB_TOKEN=ghp_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaaaa",
            "exit_code": 0
        });
        sanitize_value(&mut v);
        let s = serde_json::to_string(&v).unwrap();
        assert!(
            !s.contains("ghp_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaaaa"),
            "leaked GitHub PAT in: {s}"
        );
        assert!(s.contains("<redacted:github_pat_classic>"), "got: {s}");
    }

    #[test]
    fn sanitize_structured_content_redacts_aws_keys_env() {
        let mut v = serde_json::json!({
            "headers": {
                "X-Aws-Akid": "AKIAIOSFODNN7EXAMPLE",
                "X-Aws-Secret": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            }
        });
        sanitize_value(&mut v);
        let s = serde_json::to_string(&v).unwrap();
        assert!(!s.contains("AKIAIOSFODNN7EXAMPLE"), "AKID leaked: {s}");
        assert!(
            !s.contains("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            "AWS secret leaked: {s}"
        );
    }

    #[test]
    fn sanitize_structured_content_redacts_recursively_in_arrays_and_nested_objects() {
        let mut v = serde_json::json!({
            "events": [
                {"line": "ghp_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaaaa happened"},
                {"line": "no secret here"},
                {"nested": {"deep": [{"token": "npm_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaaaa"}]}}
            ]
        });
        sanitize_value(&mut v);
        let s = serde_json::to_string(&v).unwrap();
        assert!(
            !s.contains("ghp_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaaaa"),
            "leaked GitHub PAT in array: {s}"
        );
        assert!(
            !s.contains("npm_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaaaa"),
            "leaked npm token deep nested: {s}"
        );
        assert!(s.contains("no secret here"), "lost safe data: {s}");
    }

    // ═══════════════════════════════════════════════════════════════════
    // SA8 — ISSUE-KVD-CLI-8F501A: the entropy gate belongs PER MATCH, not
    // on the leftmost sample of a provider.
    // ═══════════════════════════════════════════════════════════════════

    /// `ghp_` + 36 identical chars — matches the pattern exactly, 0.669 b/char.
    const DECOY_GHP: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    /// A real-shaped GitHub PAT, 5.03 b/char.
    const REAL_GHP: &str = "ghp_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaaaa";
    /// A *different* real-shaped GitHub PAT, 5.17 b/char.
    const REAL_GHP_2: &str = "ghp_Zq7Wm2Xv8Nb4Kc6Rt9Yh3Jd5Fg1Ls0PuAe0x";
    /// `npm_` + 36 identical chars, 0.669 b/char.
    const DECOY_NPM: &str = "npm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    /// A real-shaped npm token, 4.98 b/char.
    const REAL_NPM: &str = "npm_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaaaa";

    #[test]
    fn decoy_does_not_mask_real_token_of_same_provider() {
        // Before the fix `detect` took the LEFTMOST match only, so the decoy
        // decided the whole provider and this returned [].
        let s = format!("{DECOY_GHP} {REAL_GHP}");
        let hits = detect(&s);
        assert_eq!(
            hits.len(),
            1,
            "exactly the real token must be reported; got {hits:?}"
        );
        assert_eq!(hits[0].provider, "github_pat_classic");
        assert_eq!(hits[0].matched_text, REAL_GHP);
    }

    #[test]
    fn decoy_alone_is_still_not_detected() {
        // Guard: the fix must not degenerate into "drop the entropy filter".
        assert!(
            detect(DECOY_GHP).is_empty(),
            "a low-entropy string alone must not be reported"
        );
        assert_eq!(
            sanitize_output(DECOY_GHP),
            DECOY_GHP,
            "and it must survive the redactor verbatim"
        );
    }

    #[test]
    fn two_real_tokens_of_same_provider_are_both_reported() {
        let s = format!("primary={REAL_GHP} backup={REAL_GHP_2}");
        let hits = detect(&s);
        assert_eq!(
            hits.len(),
            2,
            "both distinct secrets must surface: {hits:?}"
        );
        let texts: Vec<&str> = hits.iter().map(|h| h.matched_text.as_str()).collect();
        assert!(
            texts.contains(&REAL_GHP) && texts.contains(&REAL_GHP_2),
            "got {texts:?}"
        );
    }

    #[test]
    fn identical_repeats_are_deduplicated_but_still_detected() {
        let s = format!("{REAL_GHP} {REAL_GHP} {REAL_GHP}");
        let hits = detect(&s);
        assert_eq!(
            hits.len(),
            1,
            "the same secret repeated is ONE finding (and never zero): {hits:?}"
        );
        assert_eq!(hits[0].matched_text, REAL_GHP);
    }

    #[test]
    fn multi_provider_mix_decoy_and_real_tokens() {
        let s = format!("{DECOY_GHP} {DECOY_NPM} {REAL_GHP} {REAL_NPM}");
        let hits = detect(&s);
        assert_eq!(hits.len(), 2, "one real token per provider: {hits:?}");
        let gh = hits
            .iter()
            .find(|h| h.provider == "github_pat_classic")
            .unwrap_or_else(|| panic!("github token masked by its decoy: {hits:?}"));
        assert_eq!(gh.matched_text, REAL_GHP);
        let npm = hits
            .iter()
            .find(|h| h.provider == "npm_token")
            .unwrap_or_else(|| panic!("npm token masked by its decoy: {hits:?}"));
        assert_eq!(npm.matched_text, REAL_NPM);
    }

    #[test]
    fn inbound_and_outbound_agree_on_same_input() {
        // The decider and the executor are driven by the SAME selector, so no
        // value may be reported inbound and yet echoed back outbound.
        let s = format!("{DECOY_GHP} {REAL_GHP} {REAL_NPM}");
        let out = sanitize_output(&s);
        for h in detect(&s) {
            assert!(
                !out.contains(&h.matched_text),
                "detected {} survived the redactor: {out}",
                h.provider
            );
        }
        assert!(
            out.contains(DECOY_GHP),
            "the low-entropy decoy must survive verbatim: {out}"
        );
        assert!(out.contains("<redacted:github_pat_classic>"), "got: {out}");
        assert!(out.contains("<redacted:npm_token>"), "got: {out}");
    }

    #[test]
    fn exemptions_survive_the_per_match_gate() {
        // REDACT_ONLY providers stay non-blocking inbound, and ALWAYS_REDACT
        // providers still ignore the entropy threshold (a low-entropy PEM
        // block is reported, twice-distinct blocks are both reported).
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ_abc123XYZ";
        let s = format!("{jwt} ya29.a0AfH6SMBx7yQk9vL2mNpQrStUvWxYz0123456789");
        assert!(
            detect(&s).is_empty(),
            "redact-only providers must not block inbound"
        );
        let body = "a".repeat(64);
        let pem_a =
            format!("-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----");
        let pem_b = format!("-----BEGIN EC PRIVATE KEY-----\n{body}\n-----END EC PRIVATE KEY-----");
        assert!(shannon_entropy(&pem_a) < ENTROPY_THRESHOLD);
        let hits = detect(&format!("{pem_a}\n{pem_b}"));
        assert_eq!(hits.len(), 2, "every PEM block is reported: {hits:?}");
        assert!(hits.iter().all(|h| h.provider == "private_key_pem"));
    }

    /// Verbatim copy of the pre-SA8 `sanitize_output` (per-provider
    /// `replace_all` with the entropy test inside the closure). Kept in the
    /// test module only, as the reference for the differential test below.
    fn legacy_sanitize_output(s: &str) -> String {
        let cp = compiled();
        let mut out = s.to_string();
        let hits = cp.set.matches(&out);
        if !hits.matched_any() {
            return out;
        }
        for idx in hits.iter() {
            let re = &cp.individual[idx];
            let provider = cp.providers[idx];
            let always = patterns::ALWAYS_REDACT_PROVIDERS.contains(&provider);
            out = re
                .replace_all(&out, |caps: &regex::Captures| {
                    let m = caps.get(0).unwrap().as_str();
                    if always || shannon_entropy(m) >= ENTROPY_THRESHOLD {
                        format!("<redacted:{provider}>")
                    } else {
                        m.to_string()
                    }
                })
                .into_owned();
        }
        out
    }

    #[test]
    fn sanitize_output_is_byte_identical_to_the_previous_replace_all() {
        // SA8 changes the DECIDER, never the outbound bytes: the new splice
        // must reproduce `replace_all` exactly, including cross-provider order.
        const POOL: &[&str] = &[
            DECOY_GHP,
            REAL_GHP,
            REAL_GHP_2,
            DECOY_NPM,
            REAL_NPM,
            "AKIAIOSFODNN7EXAMPLE",
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ_abc123XYZ",
            "sk-aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJ",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----",
            "just a plain log line",
            "",
        ];
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..4000 {
            let mut hay = String::new();
            let parts = next() % 6 + 1;
            for _ in 0..parts {
                let r = next();
                hay.push_str(POOL[(r % POOL.len() as u64) as usize]);
                // `.is_multiple_of` (not `% 2 == 0`) — clippy::manual_is_multiple_of.
                if r.is_multiple_of(2) {
                    hay.push(' ');
                } else {
                    hay.push_str("\n| ");
                }
            }
            assert_eq!(
                sanitize_output(&hay),
                legacy_sanitize_output(&hay),
                "outbound bytes diverged on: {hay:?}"
            );
        }
    }
}
