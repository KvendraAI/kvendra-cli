//! Reference parser — Rust port of the core namespace grammar
//! (`packages/core/src/kb/private-refs.ts`, REQ-KVD-11F906 F1). Verified
//! against the SAME conformance vectors, copied byte for byte under
//! `tests/fixtures/local-refs.vectors.json` with their sha256.
//!
//! Grammar: `(\\?)\{\{(lvr|cfg):([a-z0-9][a-z0-9._-]{0,127})\}\}`. One
//! backslash right before the braces escapes the reference (it is a mention,
//! never substituted and never unescaped). No nesting: a single left-to-right
//! pass, and a substituted value is never re-scanned.

use regex::Regex;
use std::sync::OnceLock;

/// Namespace of a reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ns {
    Cfg,
    Lvr,
}

impl Ns {
    pub fn as_str(&self) -> &'static str {
        match self {
            Ns::Cfg => "cfg",
            Ns::Lvr => "lvr",
        }
    }
}

/// One match in a text. `start..end` covers the braces (not the escaping
/// backslash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefHit {
    pub start: usize,
    pub end: usize,
    pub ns: Ns,
    pub key: String,
    pub escaped: bool,
}

fn re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(\\?)\{\{(lvr|cfg):([a-z0-9][a-z0-9._-]{0,127})\}\}").expect("static regex")
    })
}

/// Every reference of both namespaces, escaped or not, in order.
pub fn find_all(text: &str) -> Vec<RefHit> {
    re().captures_iter(text)
        .map(|c| {
            let whole = c.get(0).expect("group 0");
            let escaped = !c.get(1).expect("group 1").as_str().is_empty();
            let start = if escaped {
                whole.start() + 1
            } else {
                whole.start()
            };
            RefHit {
                start,
                end: whole.end(),
                ns: if &c[2] == "lvr" { Ns::Lvr } else { Ns::Cfg },
                key: c[3].to_string(),
                escaped,
            }
        })
        .collect()
}

/// References of `ns` (escaped or not).
pub fn find_refs(text: &str, ns: Ns) -> Vec<RefHit> {
    find_all(text).into_iter().filter(|h| h.ns == ns).collect()
}

/// Distinct UNESCAPED keys of `ns`, in order of first appearance (the vector
/// contract).
pub fn keys(text: &str, ns: Ns) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for h in find_refs(text, ns) {
        if !h.escaped && !out.contains(&h.key) {
            out.push(h.key);
        }
    }
    out
}

/// Cheap pre-filter: can `text` contain any reference at all?
pub fn may_contain_ref(text: &str) -> bool {
    text.contains("{{lvr:") || text.contains("{{cfg:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaped_and_plain() {
        let hits = find_all("a \\{{lvr:x}} b {{lvr:y}} {{cfg:z}}");
        assert_eq!(hits.len(), 3);
        assert!(hits[0].escaped && hits[0].key == "x");
        assert!(!hits[1].escaped && hits[1].ns == Ns::Lvr);
        assert_eq!(hits[2].ns, Ns::Cfg);
        assert_eq!(keys("{{lvr:a}}{{lvr:a}}{{lvr:b}}", Ns::Lvr), vec!["a", "b"]);
    }
}
