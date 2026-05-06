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

/// Run the regex set against `haystack`. Returns matches that pass the
/// entropy filter.
pub fn detect(haystack: &str) -> Vec<DetectionMatch> {
    let cp = compiled();
    let hits = cp.set.matches(haystack);
    let mut out = Vec::new();
    for idx in hits.iter() {
        let provider = cp.providers[idx];
        if let Some(m) = cp.individual[idx].find(haystack) {
            let matched = m.as_str().to_string();
            let h = shannon_entropy(&matched);
            if h >= ENTROPY_THRESHOLD {
                out.push(DetectionMatch {
                    provider: provider.to_string(),
                    matched_text: matched,
                    entropy_bits_per_char: h,
                });
            }
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
    for idx in hits.iter() {
        let re = &cp.individual[idx];
        let provider = cp.providers[idx];
        // Replace each match if entropy passes the filter.
        let replaced = re
            .replace_all(&out, |caps: &regex::Captures| {
                let m = caps.get(0).unwrap().as_str();
                if shannon_entropy(m) >= ENTROPY_THRESHOLD {
                    format!("<redacted:{provider}>")
                } else {
                    m.to_string()
                }
            })
            .into_owned();
        out = replaced;
    }
    out
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
}
