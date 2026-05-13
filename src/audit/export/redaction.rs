//! Privacy redaction — substituye patrones de tokens conocidos por marcadores
//! `[REDACTED:*]`. Implementa AC-EXPORT-6.

use regex::Regex;
use std::sync::OnceLock;

fn gh_token_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"gh[opst]_[A-Za-z0-9_]{36,255}").expect("valid regex"))
}

fn gh_pat_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"github_pat_[A-Za-z0-9_]{82,}").expect("valid regex"))
}

fn akid_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"AKIA[0-9A-Z]{16}").expect("valid regex"))
}

fn jwt_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"eyJ[A-Za-z0-9_=\-]+\.[A-Za-z0-9_=\-]+\.[A-Za-z0-9_.+/=\-]+")
            .expect("valid regex")
    })
}

/// Apply the redaction pipeline to a free-form text fragment.
pub fn redact_text(s: &str) -> String {
    let mut out = gh_token_re()
        .replace_all(s, "[REDACTED:gh-token]")
        .into_owned();
    out = gh_pat_re()
        .replace_all(&out, "[REDACTED:gh-fine-grained]")
        .into_owned();
    out = akid_re()
        .replace_all(&out, "[REDACTED:aws-akid]")
        .into_owned();
    out = jwt_re().replace_all(&out, "[REDACTED:jwt]").into_owned();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_gh_token() {
        let input = "Using token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab in args";
        let out = redact_text(input);
        assert!(out.contains("[REDACTED:gh-token]"));
        assert!(!out.contains("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"));
    }

    #[test]
    fn redacts_aws_akid() {
        let input = "AKIAABCDEFGHIJKLMNOP and trailing data";
        let out = redact_text(input);
        assert!(out.contains("[REDACTED:aws-akid]"));
    }

    #[test]
    fn redacts_jwt() {
        let input = "eyJabc.eyJpc3MiOiJrIn0.signature_blob_part";
        let out = redact_text(input);
        assert!(out.contains("[REDACTED:jwt]"));
    }

    #[test]
    fn leaves_innocent_text_alone() {
        let input = "plain string with no secrets";
        assert_eq!(redact_text(input), input);
    }
}
