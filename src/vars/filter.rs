//! Output filter — the broker's single egress point for local values
//! (REQ-KVD-11F906 D5, RF-CLI-8, AC-LVR-1).
//!
//! Every occurrence of a known local value in a JSON-RPC response (result,
//! `error.message`, `error.data`) or in an audit `error_message` is
//! re-symbolized as `{{lvr:<key>}}` (O4), matching the longest value first.
//! Values of type `port` and values shorter than 4 chars are NOT masked (O2:
//! they would mask half of every payload).
//!
//! # Scope of the guarantee (N2)
//!
//! The filter matches LITERAL occurrences of a value, including inside JSON
//! text (validated values carry no character JSON would escape). Encoded
//! forms — percent-encoding (`%2F`), base64, doubled escapes, case changes,
//! a value split across fields — are NOT masked. It is a guarantee for the
//! literal value and only a brake for anything a primitive re-encodes.

use super::{VarType, VarsDoc};
use serde_json::Value;
use zeroize::Zeroizing;

/// Minimum value length the filter masks (O2).
pub const MIN_MASKED_LEN: usize = 4;

/// The maskable values of a `VarsDoc`, longest first.
#[derive(Default)]
pub struct KnownValues(Vec<(String, Zeroizing<String>)>);

impl KnownValues {
    pub fn from_doc(doc: &VarsDoc) -> Self {
        let mut v: Vec<(String, Zeroizing<String>)> = doc
            .vars
            .iter()
            .filter(|(_, lv)| lv.var_type != VarType::Port && lv.value.len() >= MIN_MASKED_LEN)
            .map(|(k, lv)| (k.clone(), lv.value.clone()))
            .collect();
        v.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));
        Self(v)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Single left-to-right pass; at each position the longest matching
    /// value wins. Calls `on_hit(index)` per match; returns the rebuilt text
    /// when `rebuild`.
    fn scan(&self, s: &str, rebuild: bool, mut on_hit: impl FnMut(usize)) -> Option<String> {
        let mut out = if rebuild {
            Some(String::with_capacity(s.len()))
        } else {
            None
        };
        let mut i = 0;
        while i < s.len() {
            let rest = &s[i..];
            if let Some((idx, (key, val))) = self
                .0
                .iter()
                .enumerate()
                .find(|(_, (_, val))| rest.starts_with(val.as_str()))
            {
                on_hit(idx);
                if let Some(o) = out.as_mut() {
                    o.push_str("{{lvr:");
                    o.push_str(key);
                    o.push_str("}}");
                }
                i += val.len();
            } else {
                let ch = rest.chars().next().expect("non-empty rest");
                if let Some(o) = out.as_mut() {
                    o.push(ch);
                }
                i += ch.len_utf8();
            }
        }
        out
    }

    /// Mask every known value in `s`. Returns the masked text and the number
    /// of replacements.
    pub fn scrub_str(&self, s: &str) -> (String, usize) {
        if self.0.is_empty() {
            return (s.to_string(), 0);
        }
        let mut n = 0;
        let out = self.scan(s, true, |_| n += 1).expect("rebuild");
        (out, n)
    }

    /// Recursively mask every string (and object key) of `v`. Returns the
    /// number of replacements.
    pub fn scrub_value(&self, v: &mut Value) -> usize {
        if self.0.is_empty() {
            return 0;
        }
        match v {
            Value::String(s) => {
                let (out, n) = self.scrub_str(s);
                if n > 0 {
                    *s = out;
                }
                n
            }
            Value::Array(a) => a.iter_mut().map(|x| self.scrub_value(x)).sum(),
            Value::Object(m) => {
                let mut n = 0;
                let old = std::mem::take(m);
                for (k, mut val) in old {
                    let (nk, kn) = self.scrub_str(&k);
                    n += kn + self.scrub_value(&mut val);
                    m.insert(nk, val);
                }
                n
            }
            _ => 0,
        }
    }

    /// `(key, count)` of every known value present in `s` (no positions —
    /// O7). Sorted by key.
    pub fn contains_any(&self, s: &str) -> Vec<(String, usize)> {
        if self.0.is_empty() {
            return Vec::new();
        }
        let mut counts = vec![0usize; self.0.len()];
        self.scan(s, false, |idx| counts[idx] += 1);
        let mut out: Vec<(String, usize)> = self
            .0
            .iter()
            .zip(counts)
            .filter(|(_, c)| *c > 0)
            .map(|((k, _), c)| (k.clone(), c))
            .collect();
        out.sort();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vars::{LocalVar, VarOrigin};

    fn doc(entries: &[(&str, VarType, &str)]) -> VarsDoc {
        let mut d = VarsDoc::default();
        for (k, t, v) in entries {
            d.vars.insert(
                (*k).into(),
                LocalVar {
                    value: Zeroizing::new((*v).into()),
                    var_type: *t,
                    verified: true,
                    updated_at: String::new(),
                    verified_at: None,
                    origin: VarOrigin::Set,
                },
            );
        }
        d
    }

    #[test]
    fn longest_first_and_counts() {
        let kv = KnownValues::from_doc(&doc(&[
            ("short", VarType::Path, "/kvd-sentinel"),
            ("long", VarType::Path, "/kvd-sentinel/deeper"),
            ("port", VarType::Port, "8443"),
            ("tiny", VarType::String, "ab"),
        ]));
        let (out, n) = kv.scrub_str("cd /kvd-sentinel/deeper && ls /kvd-sentinel :8443 ab");
        assert_eq!(n, 2);
        assert_eq!(out, "cd {{lvr:long}} && ls {{lvr:short}} :8443 ab");
        let hits = kv.contains_any("/kvd-sentinel/deeper /kvd-sentinel/deeper /kvd-sentinel");
        assert_eq!(hits, vec![("long".into(), 2), ("short".into(), 1)]);
    }

    #[test]
    fn scrub_value_recurses_keys_and_values() {
        let kv = KnownValues::from_doc(&doc(&[("ws", VarType::Path, "/kvd-sentinel-ws")]));
        let mut v = serde_json::json!({
            "a": ["x /kvd-sentinel-ws y", {"/kvd-sentinel-ws": "z"}],
            "n": 1
        });
        assert_eq!(kv.scrub_value(&mut v), 2);
        assert!(!v.to_string().contains("/kvd-sentinel-ws"));
    }
}
