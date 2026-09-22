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
    windows: Vec<Option<usize>>,
    shapes: Vec<PatternShape>,
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
        let windows: Vec<Option<usize>> = providers
            .iter()
            .map(|p| {
                patterns::ENTROPY_WINDOWS
                    .iter()
                    .find(|(q, _)| q == p)
                    .map(|(_, w)| *w)
            })
            .collect();
        let shapes: Vec<PatternShape> = regexes
            .iter()
            .map(|r| PatternShape::of(r).unwrap_or_else(PatternShape::opaque))
            .collect();
        CompiledPatterns {
            set,
            individual,
            providers,
            windows,
            shapes,
        }
    })
}

/// Shannon entropy in bits/char of a byte slice (printable ASCII assumed).
pub fn shannon_entropy(s: &str) -> f64 {
    bytes_entropy(s.as_bytes())
}

fn bytes_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in bytes {
        counts[*b as usize] += 1;
    }
    let total = bytes.len() as f64;
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

/// Scan budget of one selector run over an UNBOUNDED pattern, as a multiple of
/// the haystack length (plus [`SCAN_BUDGET_FLOOR`]). Retrying at the next
/// character after a match re-runs the regex over overlapping spans; when a
/// match can be arbitrarily long (thousands of prefixes inside one long
/// in-charset run) that is quadratic. Once the budget is spent the selector
/// FAILS CLOSED: every remaining match of that provider is accepted without
/// the entropy gate and widened to the end of the maximal run of its
/// pattern's alphabet ([`PatternShape::alphabet`]) — linear, and never a
/// bypass (see [`select`]). Length-BOUNDED patterns never spend budget: their
/// next-character retry costs at most `len × max_len`.
const SCAN_BUDGET_FACTOR: usize = 8;
const SCAN_BUDGET_FLOOR: usize = 64 * 1024;

/// Largest `max_len` (bytes) for which a pattern is scanned as length-bounded.
/// A longer bound is treated as unbounded, so the uncapped retry of a bounded
/// pattern stays within `len × BOUNDED_MATCH_LIMIT`.
const BOUNDED_MATCH_LIMIT: usize = 256;

/// Static shape of a provider pattern, DERIVED from its regex source by a
/// small conservative analyser (ISSUE-KVD-CLI-8F501A, SA8-F2-bis).
///
/// `max_len` decides how the selector scans the provider; `alphabet` is what
/// makes the post-budget fallback sound. Both are over-approximations: a
/// construct the analyser does not understand yields `None` from
/// [`PatternShape::of`], and the provider falls back to
/// [`PatternShape::opaque`] — unbounded, every byte in the alphabet — which is
/// fail-closed (a post-budget match then extends to the end of the text).
#[derive(Debug, Clone)]
struct PatternShape {
    /// Longest possible match in BYTES; `None` = unbounded or longer than
    /// [`BOUNDED_MATCH_LIMIT`].
    max_len: Option<usize>,
    /// Every byte that can occur inside a match. Bytes >= 0x80 are all-or-
    /// nothing, so a maximal run of alphabet bytes always ends on a char
    /// boundary.
    alphabet: [bool; 256],
}

impl PatternShape {
    fn opaque() -> Self {
        PatternShape {
            max_len: None,
            alphabet: [true; 256],
        }
    }

    fn of(src: &str) -> Option<Self> {
        if !src.is_ascii() {
            return None;
        }
        let mut parser = ShapeParser {
            src: src.as_bytes(),
            pos: 0,
        };
        let piece = parser.alt(&mut ShapeFlags::default())?;
        if parser.pos != parser.src.len() {
            return None;
        }
        Some(PatternShape {
            max_len: piece.max.filter(|m| *m <= BOUNDED_MATCH_LIMIT),
            alphabet: piece.alpha,
        })
    }

    /// End of the maximal run of alphabet bytes starting at `from`.
    fn run_end(&self, bytes: &[u8], from: usize) -> usize {
        bytes[from..]
            .iter()
            .position(|b| !self.alphabet[*b as usize])
            .map_or(bytes.len(), |off| from + off)
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct ShapeFlags {
    case_insensitive: bool,
    dot_all: bool,
}

/// Max length (`None` = unbounded) and alphabet of a sub-expression.
struct ShapePiece {
    max: Option<usize>,
    alpha: [bool; 256],
}

impl ShapePiece {
    fn empty() -> Self {
        ShapePiece {
            max: Some(0),
            alpha: [false; 256],
        }
    }

    /// One character drawn from `set` (ASCII bytes). Case folding and
    /// Unicode-aware classes may match non-ASCII chars (e.g. `(?i)k` matches
    /// U+212A KELVIN SIGN), which then count up to 4 bytes.
    fn class(set: &[bool; 128], non_ascii: bool, flags: ShapeFlags) -> Self {
        let mut alpha = [false; 256];
        let mut wide = non_ascii;
        for (b, on) in set.iter().enumerate() {
            if *on {
                alpha[b] = true;
                if flags.case_insensitive && (b as u8).is_ascii_alphabetic() {
                    alpha[(b as u8 ^ 0x20) as usize] = true;
                    wide = true;
                }
            }
        }
        if wide {
            alpha[128..].fill(true);
        }
        ShapePiece {
            max: Some(if wide { 4 } else { 1 }),
            alpha,
        }
    }

    fn any(flags: ShapeFlags) -> Self {
        let mut alpha = [true; 256];
        if !flags.dot_all {
            alpha[b'\n' as usize] = false;
        }
        ShapePiece {
            max: Some(4),
            alpha,
        }
    }

    fn union_alpha(&mut self, other: &ShapePiece) {
        for (a, b) in self.alpha.iter_mut().zip(other.alpha.iter()) {
            *a |= *b;
        }
    }
}

/// Recursive-descent reader for the regex subset the provider table uses:
/// literals, `\`-escapes, `.`, `[...]` classes, `(...)`/`(?:...)` groups,
/// `(?is)` flags, `|`, and the `? * + {n} {n,} {n,m}` quantifiers (greedy or
/// lazy). Anything else returns `None`.
struct ShapeParser<'a> {
    src: &'a [u8],
    pos: usize,
}

impl ShapeParser<'_> {
    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn alt(&mut self, flags: &mut ShapeFlags) -> Option<ShapePiece> {
        let mut acc = self.seq(flags)?;
        while self.peek() == Some(b'|') {
            self.pos += 1;
            let branch = self.seq(flags)?;
            acc.max = match (acc.max, branch.max) {
                (Some(a), Some(b)) => Some(a.max(b)),
                _ => None,
            };
            acc.union_alpha(&branch);
        }
        Some(acc)
    }

    fn seq(&mut self, flags: &mut ShapeFlags) -> Option<ShapePiece> {
        let mut acc = ShapePiece::empty();
        while !matches!(self.peek(), None | Some(b'|') | Some(b')')) {
            let atom = self.atom(flags)?;
            let piece = self.quantified(atom)?;
            acc.max = match (acc.max, piece.max) {
                (Some(a), Some(b)) => a.checked_add(b),
                _ => None,
            };
            acc.union_alpha(&piece);
        }
        Some(acc)
    }

    fn atom(&mut self, flags: &mut ShapeFlags) -> Option<ShapePiece> {
        match self.bump()? {
            b'(' => self.group(flags),
            b'[' => self.class(*flags),
            b'.' => Some(ShapePiece::any(*flags)),
            b'^' | b'$' => Some(ShapePiece::empty()),
            b'\\' => match self.escape()? {
                Escape::Empty => Some(ShapePiece::empty()),
                Escape::Set(set, non_ascii) => Some(ShapePiece::class(&set, non_ascii, *flags)),
                Escape::Any => Some(ShapePiece::any(ShapeFlags {
                    dot_all: true,
                    ..*flags
                })),
            },
            b'*' | b'+' | b'?' | b'{' | b')' | b'|' | b']' | b'}' => None,
            b => Some(ShapePiece::class(&single(b), false, *flags)),
        }
    }

    fn group(&mut self, flags: &mut ShapeFlags) -> Option<ShapePiece> {
        let mut inner = *flags;
        if self.peek() == Some(b'?') {
            self.pos += 1;
            let mut on = true;
            loop {
                match self.bump()? {
                    b'i' if on => inner.case_insensitive = true,
                    b's' if on => inner.dot_all = true,
                    b'i' | b's' | b'm' | b'u' | b'U' => {}
                    b'-' => on = false,
                    b')' => {
                        *flags = inner;
                        return Some(ShapePiece::empty());
                    }
                    b':' => break,
                    _ => return None,
                }
            }
        }
        let piece = self.alt(&mut inner)?;
        (self.bump()? == b')').then_some(piece)
    }

    fn class(&mut self, flags: ShapeFlags) -> Option<ShapePiece> {
        if self.peek() == Some(b'^') {
            return Some(ShapePiece::any(ShapeFlags {
                dot_all: true,
                ..flags
            }));
        }
        let mut set = [false; 128];
        let mut non_ascii = false;
        let mut first = true;
        loop {
            let b = self.bump()?;
            let lo = match b {
                b']' if !first => break,
                b'[' => return None,
                b'&' | b'~' | b'-' if self.peek() == Some(b) && !first => return None,
                b'\\' => match self.escape()? {
                    Escape::Set(s, wide) if s.iter().filter(|x| **x).count() == 1 && !wide => {
                        s.iter().position(|x| *x)? as u8
                    }
                    Escape::Set(s, wide) => {
                        for (dst, src) in set.iter_mut().zip(s.iter()) {
                            *dst |= *src;
                        }
                        non_ascii |= wide;
                        first = false;
                        continue;
                    }
                    Escape::Any => {
                        return Some(ShapePiece::any(ShapeFlags {
                            dot_all: true,
                            ..flags
                        }));
                    }
                    Escape::Empty => return None,
                },
                b => b,
            };
            first = false;
            let hi = if self.peek() == Some(b'-') && self.src.get(self.pos + 1) != Some(&b']') {
                self.pos += 1;
                match self.bump()? {
                    b'\\' => match self.escape()? {
                        Escape::Set(s, false) if s.iter().filter(|x| **x).count() == 1 => {
                            s.iter().position(|x| *x)? as u8
                        }
                        _ => return None,
                    },
                    b'[' | b']' => return None,
                    h => h,
                }
            } else {
                lo
            };
            if hi < lo {
                return None;
            }
            for c in lo..=hi {
                set[c as usize] = true;
            }
        }
        Some(ShapePiece::class(&set, non_ascii, flags))
    }

    fn escape(&mut self) -> Option<Escape> {
        let b = self.bump()?;
        let ascii = |f: fn(&u8) -> bool| {
            let mut set = [false; 128];
            for c in 0u8..128 {
                set[c as usize] = f(&c);
            }
            set
        };
        Some(match b {
            b'A' | b'z' | b'b' | b'B' => Escape::Empty,
            b's' => Escape::Set(ascii(|c| b"\t\n\x0b\x0c\r ".contains(c)), true),
            b'd' => Escape::Set(ascii(u8::is_ascii_digit), true),
            b'w' => Escape::Set(ascii(|c| c.is_ascii_alphanumeric() || *c == b'_'), true),
            b'S' | b'D' | b'W' => Escape::Any,
            b'n' => Escape::Set(single(b'\n'), false),
            b't' => Escape::Set(single(b'\t'), false),
            b'r' => Escape::Set(single(b'\r'), false),
            b if b.is_ascii_punctuation() || b == b' ' => Escape::Set(single(b), false),
            _ => return None,
        })
    }

    fn quantified(&mut self, atom: ShapePiece) -> Option<ShapePiece> {
        let unbounded = |atom: ShapePiece| ShapePiece {
            max: if atom.max == Some(0) { Some(0) } else { None },
            alpha: atom.alpha,
        };
        let piece = match self.peek() {
            Some(b'?') => {
                self.pos += 1;
                atom
            }
            Some(b'*') | Some(b'+') => {
                self.pos += 1;
                unbounded(atom)
            }
            Some(b'{') => {
                self.pos += 1;
                let min = self.number()?;
                let upper = match self.bump()? {
                    b'}' => Some(min),
                    b',' if self.peek() == Some(b'}') => {
                        self.pos += 1;
                        None
                    }
                    b',' => {
                        let max = self.number()?;
                        (self.bump()? == b'}' && max >= min).then_some(())?;
                        Some(max)
                    }
                    _ => return None,
                };
                match upper {
                    None => unbounded(atom),
                    Some(n) => ShapePiece {
                        max: atom.max.and_then(|m| m.checked_mul(n)),
                        alpha: atom.alpha,
                    },
                }
            }
            _ => return Some(atom),
        };
        if self.peek() == Some(b'?') {
            self.pos += 1;
        }
        if matches!(self.peek(), Some(b'?' | b'*' | b'+' | b'{')) {
            return None;
        }
        Some(piece)
    }

    fn number(&mut self) -> Option<usize> {
        let start = self.pos;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.pos += 1;
        }
        std::str::from_utf8(&self.src[start..self.pos])
            .ok()?
            .parse()
            .ok()
    }
}

enum Escape {
    /// Zero-width assertion (`\A`, `\z`, `\b`, `\B`).
    Empty,
    /// A set of ASCII bytes; `true` when the escape may also match non-ASCII.
    Set([bool; 128], bool),
    /// A negated class — any char.
    Any,
}

fn single(b: u8) -> [bool; 128] {
    let mut set = [false; 128];
    set[b as usize] = true;
    set
}

/// Entropy the gate compares against [`ENTROPY_THRESHOLD`]: the whole-match
/// entropy (the historical measure, reported unchanged whenever it passes)
/// or, for a provider with an [`patterns::ENTROPY_WINDOWS`] entry, the best
/// window of the pattern's minimum length — so low-entropy padding in the
/// pattern's own charset cannot dilute a real key below the threshold.
fn gate_entropy(text: &str, window: Option<usize>) -> f64 {
    let whole = shannon_entropy(text);
    match window {
        Some(w) if whole < ENTROPY_THRESHOLD && w > 0 && text.len() > w => {
            max_window_entropy(text.as_bytes(), w).max(whole)
        }
        _ => whole,
    }
}

/// Maximum Shannon entropy over every `w`-byte window of `bytes`, in one
/// sliding pass (O(len)). Stops at the first window that reaches the
/// threshold, confirmed by an exact recomputation of that window.
fn max_window_entropy(bytes: &[u8], w: usize) -> f64 {
    // H(window) = log2(w) − Σ c·log2(c) / w, maintained incrementally.
    let f: Vec<f64> = (0..=w)
        .map(|c| {
            if c == 0 {
                0.0
            } else {
                c as f64 * (c as f64).log2()
            }
        })
        .collect();
    let log_w = (w as f64).log2();
    let mut counts = [0usize; 256];
    let mut sum = 0.0_f64;
    for b in &bytes[..w] {
        let c = &mut counts[*b as usize];
        sum += f[*c + 1] - f[*c];
        *c += 1;
    }
    let mut best = 0.0_f64;
    let mut start = 0usize;
    loop {
        let approx = log_w - sum / w as f64;
        if approx >= ENTROPY_THRESHOLD - 1e-6 {
            let exact = bytes_entropy(&bytes[start..start + w]);
            if exact >= ENTROPY_THRESHOLD {
                return exact;
            }
        }
        best = best.max(approx);
        if start + w >= bytes.len() {
            return best.min(ENTROPY_THRESHOLD - f64::EPSILON);
        }
        let out = &mut counts[bytes[start] as usize];
        sum += f[*out - 1] - f[*out];
        *out -= 1;
        let inc = &mut counts[bytes[start + w] as usize];
        sum += f[*inc + 1] - f[*inc];
        *inc += 1;
        start += 1;
    }
}

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
/// gate, ordered by start; matches MAY OVERLAP. The gate is applied per match:
/// a low-entropy decoy of the right shape must never disqualify the provider
/// for the whole payload (ISSUE-KVD-CLI-8F501A). Further rules close SA8-F1,
/// SA8-F2 and SA8-F2-bis:
///
/// - the gate scores a bounded window as well as the whole match
///   ([`gate_entropy`]), so in-charset padding cannot dilute a real key;
/// - NO match is consumed, accepted or rejected: scanning resumes at its next
///   character, so a decoy whose tail swallows a real token's prefix cannot
///   hide it — whether the decoy is low-entropy (rejected, SA8-F1) or
///   high-entropy (accepted, SA8-F2). Callers merge overlapping spans.
///
/// See [`select`] for the work cap.
fn matches_above_threshold(idx: usize, haystack: &str) -> Vec<RawMatch> {
    let budget = haystack
        .len()
        .saturating_mul(SCAN_BUDGET_FACTOR)
        .saturating_add(SCAN_BUDGET_FLOOR);
    select(idx, haystack, budget)
}

/// [`matches_above_threshold`] with an explicit work budget.
///
/// A length-BOUNDED pattern ([`PatternShape::max_len`]) is never capped: the
/// next-character retry costs at most `len × max_len`, so its semantics hold
/// on every input (SA8-F2-bis: consuming bounded matches past a cap let a
/// filler + decoy swallow a real token's prefix and leak its body).
///
/// An UNBOUNDED pattern spends `budget`; once it is exhausted every remaining
/// match is accepted without the gate and its span is WIDENED to the end of
/// the maximal run of the pattern's alphabet, where scanning resumes. Sound
/// for any pattern: no match starts before the accepted one (leftmost
/// search), and a match starting inside the widened span consists only of
/// alphabet bytes, so it cannot cross the run's end — it is covered. Linear:
/// every step advances past the widened end.
fn select(idx: usize, haystack: &str, mut budget: usize) -> Vec<RawMatch> {
    let cp = compiled();
    let provider = cp.providers[idx];
    let always = patterns::ALWAYS_REDACT_PROVIDERS.contains(&provider);
    let window = cp.windows[idx];
    let shape = &cp.shapes[idx];
    let bounded = shape.max_len.is_some();
    let re = &cp.individual[idx];
    let mut fail_closed = false;
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos <= haystack.len() {
        let Some(m) = re.find_at(haystack, pos) else {
            break;
        };
        let next_char = m.start()
            + haystack[m.start()..]
                .chars()
                .next()
                .map_or(1, char::len_utf8);
        if !bounded && !fail_closed {
            let cost = (m.end() - pos) + m.len();
            match budget.checked_sub(cost) {
                Some(left) => budget = left,
                None => fail_closed = true,
            }
        }
        if fail_closed {
            let end = shape.run_end(haystack.as_bytes(), m.end());
            let text = &haystack[m.start()..end];
            out.push(RawMatch {
                start: m.start(),
                end,
                text: text.to_string(),
                entropy: shannon_entropy(text),
            });
            pos = end.max(next_char);
            continue;
        }
        let text = m.as_str();
        let entropy = if always {
            shannon_entropy(text)
        } else {
            gate_entropy(text, window)
        };
        if always || entropy >= ENTROPY_THRESHOLD {
            out.push(RawMatch {
                start: m.start(),
                end: m.end(),
                text: text.to_string(),
                entropy,
            });
        }
        pos = next_char;
    }
    out
}

/// Providers whose matches have a bounded length, with that bound in bytes
/// (derived from each pattern in [`patterns::PROVIDER_PATTERNS`]). These are
/// scanned exhaustively on every input; every other provider is subject to
/// the fail-closed work cap.
pub fn bounded_providers() -> Vec<(&'static str, usize)> {
    let cp = compiled();
    cp.providers
        .iter()
        .zip(cp.shapes.iter())
        .filter_map(|(p, s)| s.max_len.map(|m| (*p, m)))
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
///
/// Every provider's accepted spans are collected against the ORIGINAL string
/// (the same selector as [`detect`]), overlapping spans are merged, and the
/// text is spliced once — so no span [`detect`] accepts can survive, whatever
/// other span it overlaps (SA8-F2). Only strictly overlapping spans merge;
/// adjacent tokens keep one marker each. A merged span is labelled with the
/// provider of its earliest-starting span (ties: the longer span, then pattern
/// order in [`patterns::PROVIDER_PATTERNS`]) — deterministic, and on inputs
/// without overlap identical to the historical per-provider replacement.
pub fn sanitize_output(s: &str) -> String {
    let cp = compiled();
    let hits = cp.set.matches(s);
    if !hits.matched_any() {
        return s.to_string();
    }
    let mut spans: Vec<(usize, usize, usize)> = Vec::new();
    for idx in hits.iter() {
        spans.extend(
            matches_above_threshold(idx, s)
                .into_iter()
                .map(|m| (m.start, m.end, idx)),
        );
    }
    if spans.is_empty() {
        return s.to_string();
    }
    spans.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)).then(a.2.cmp(&b.2)));
    let mut out = String::with_capacity(s.len());
    let mut cursor = 0usize;
    let mut i = 0usize;
    while i < spans.len() {
        let (start, mut end, idx) = spans[i];
        i += 1;
        while i < spans.len() && spans[i].0 < end {
            end = end.max(spans[i].1);
            i += 1;
        }
        out.push_str(&s[cursor..start]);
        out.push_str("<redacted:");
        out.push_str(cp.providers[idx]);
        out.push('>');
        cursor = end;
    }
    out.push_str(&s[cursor..]);
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

    /// Accepted spans of every non-exempt provider against `s`, and whether
    /// any two of them overlap — the precondition under which the single
    /// splice may legitimately differ from the legacy chain.
    fn has_overlapping_spans(s: &str) -> bool {
        let cp = compiled();
        let mut spans: Vec<(usize, usize)> = cp
            .set
            .matches(s)
            .iter()
            .flat_map(|idx| matches_above_threshold(idx, s))
            .map(|m| (m.start, m.end))
            .collect();
        spans.sort_unstable();
        spans.windows(2).any(|w| w[1].0 < w[0].1)
    }

    const DIFF_POOL: &[&str] = &[
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

    fn xorshift(seed: u64) -> impl FnMut() -> u64 {
        let mut state = seed;
        move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        }
    }

    #[test]
    fn sanitize_output_is_byte_identical_to_the_previous_replace_all() {
        // Separated tokens never overlap, so the single splice must reproduce
        // the legacy per-provider `replace_all` chain exactly, including the
        // cross-provider label. The overlap/dilution shapes are where SA8-F1
        // and SA8-F2 DELIBERATELY diverge — see `sa8_f*` below.
        let mut next = xorshift(0x2545_f491_4f6c_dd1d);
        for _ in 0..4000 {
            let mut hay = String::new();
            let parts = next() % 6 + 1;
            for _ in 0..parts {
                let r = next();
                hay.push_str(DIFF_POOL[(r % DIFF_POOL.len() as u64) as usize]);
                // `.is_multiple_of` (not `% 2 == 0`) — clippy::manual_is_multiple_of.
                if r.is_multiple_of(2) {
                    hay.push(' ');
                } else {
                    hay.push_str("\n| ");
                }
            }
            assert!(
                !has_overlapping_spans(&hay),
                "separated input overlaps: {hay:?}"
            );
            assert_eq!(
                sanitize_output(&hay),
                legacy_sanitize_output(&hay),
                "outbound bytes diverged on: {hay:?}"
            );
        }
    }

    #[test]
    fn glued_tokens_match_legacy_exactly_when_no_accepted_spans_overlap() {
        // Same pool, NO separators: tokens glue into each other. Identity with
        // the legacy chain is required exactly when no two accepted spans
        // overlap; where they do (e.g. an `sk-` body swallowing `AKIA…`) the
        // bytes may differ and the parity property is asserted instead.
        let mut next = xorshift(0x51f1_5eed_c0ff_ee01);
        let (mut identical, mut overlapping) = (0usize, 0usize);
        for _ in 0..4000 {
            let mut hay = String::new();
            for _ in 0..next() % 6 + 1 {
                hay.push_str(DIFF_POOL[(next() % DIFF_POOL.len() as u64) as usize]);
            }
            let out = sanitize_output(&hay);
            if has_overlapping_spans(&hay) {
                overlapping += 1;
                for h in detect(&hay) {
                    assert!(!out.contains(&h.matched_text), "leak on {hay:?}: {out}");
                }
            } else {
                identical += 1;
                assert_eq!(out, legacy_sanitize_output(&hay), "diverged on: {hay:?}");
            }
        }
        assert!(
            identical > 1000 && overlapping > 100,
            "generator lost coverage: {identical} identical, {overlapping} overlapping"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // SA8-F1 — the per-match gate was still bypassable by OVERLAP (a decoy
    // whose tail swallows the real token's prefix) and by DILUTION (in-charset
    // low-entropy padding glued to a real key under an unbounded quantifier).
    // ═══════════════════════════════════════════════════════════════════

    /// (provider, real-shaped token, decoy prefix, overlap pad length, pad char)
    const F1_CASES: &[(&str, &str, &str, usize, char)] = &[
        (
            "anthropic_key",
            "sk-ant-api03-Zq7Wm2Xv8Nb4Kc6Rt9Yh3Jd5Fg1Ls0PuAeB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJ_x-QwErTyUiOp",
            "sk-ant-",
            60,
            'a',
        ),
        (
            "pypi_token",
            "pypi-AgEIcHlwaS5vcmcCJDgyZWUxMTk5LTRkMzAtNGE5MS04YzVjLTk2ZjQ4YzI3ZDViYwACKlszLCJlMmU3MWMxMy01YjQ2LTRkOTMtYjMyOC1lY2EyZWVjZDQ3M2YiXQAABiBp",
            "pypi-AgEI",
            30,
            'a',
        ),
        (
            "slack_token",
            "xoxb-1234567890-9876543210123-aB3kP9zX1mQ7rL5tY2vN4wE6",
            "xoxb-",
            10,
            'a',
        ),
        (
            "gitlab_pat",
            "glpat-aB3kP9zX1mQ7rL5tY2vN",
            "glpat-",
            20,
            'a',
        ),
        (
            "stripe_secret_key",
            "sk_live_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0",
            "sk_live_",
            24,
            'a',
        ),
        (
            "openai_key",
            "sk-aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJ",
            "sk-",
            48,
            'a',
        ),
        ("aws_akid", "AKIAIOSFODNN7EXAMPLE", "AKIA", 12, 'A'),
        ("github_pat_classic", REAL_GHP, "ghp_", 33, 'a'),
    ];

    /// Every probe shape the validator used, per provider.
    fn f1_probes(prefix: &str, real: &str, k: usize, pad: char) -> Vec<(&'static str, String)> {
        let p = |n: usize| pad.to_string().repeat(n);
        vec![
            ("overlap", format!("{prefix}{}{real}", p(k))),
            ("dilution", format!("{real}{}", p(2000))),
            ("pre-dilution", format!("{prefix}{}{real}", p(2000))),
            ("sandwich", format!("x {prefix}{}{real}{} y", p(k), p(2000))),
        ]
    }

    #[test]
    fn sa8_f1_every_overlap_and_dilution_probe_is_caught_both_ways() {
        for (provider, real, prefix, k, pad) in F1_CASES {
            for (shape, hay) in f1_probes(prefix, real, *k, *pad) {
                let hits = detect(&hay);
                assert!(
                    hits.iter()
                        .any(|h| h.provider == *provider && h.matched_text.contains(real)),
                    "{provider}/{shape}: inbound missed the real token; got {:?}",
                    hits.iter().map(|h| &h.provider).collect::<Vec<_>>()
                );
                let out = sanitize_output(&hay);
                assert!(
                    !out.contains(real),
                    "{provider}/{shape}: real token survived outbound redaction"
                );
                assert!(
                    out.contains(&format!("<redacted:{provider}>")),
                    "{provider}/{shape}: no redaction marker"
                );
                for h in &hits {
                    assert!(
                        !out.contains(&h.matched_text),
                        "{provider}/{shape}: detected text echoed back"
                    );
                }
            }
        }
    }

    #[test]
    fn sa8_f1_the_legacy_redactor_leaked_these_and_the_selector_does_not() {
        // The honest counterpart of the byte-identity test: on these shapes
        // the outbound bytes CHANGE, and they change from leaking to redacted.
        let mut diverged = 0;
        for (provider, real, prefix, k, pad) in F1_CASES {
            for (shape, hay) in f1_probes(prefix, real, *k, *pad) {
                let new = sanitize_output(&hay);
                assert!(!new.contains(real), "{provider}/{shape} leaks: {new}");
                if legacy_sanitize_output(&hay).contains(real) {
                    diverged += 1;
                }
            }
        }
        // Validator shapes: 6 dilution + 5 overlap leaks at 23347f5, plus the
        // pre-dilution and sandwich variants of the unbounded providers.
        assert!(
            diverged >= 11,
            "expected the legacy redactor to leak on >= 11 probes, got {diverged}"
        );
    }

    #[test]
    fn sa8_f1_lone_low_entropy_decoys_of_unbounded_patterns_stay_undetected() {
        // Guard: the window gate must not flag a decoy that is low-entropy
        // EVERYWHERE, however long.
        for (provider, _real, prefix, _k, pad) in F1_CASES {
            for n in [16usize, 60, 500, 5000] {
                let decoy = format!("{prefix}{}", pad.to_string().repeat(n));
                assert!(
                    detect(&decoy).is_empty(),
                    "{provider}: lone decoy of {n} pad chars reported"
                );
                assert_eq!(sanitize_output(&decoy), decoy, "{provider}: decoy mangled");
            }
        }
    }

    #[test]
    fn entropy_windows_are_the_patterns_minimum_length() {
        // A minimal accepted string per windowed provider: it must match the
        // pattern exactly, have the declared length, and stop matching once
        // its last character is dropped.
        let minimal: &[(&str, String)] = &[
            ("pypi_token", format!("pypi-AgEI{}", "x".repeat(30))),
            (
                "aws_secret_env",
                format!("aws_secret_access_key={}", "x".repeat(40)),
            ),
            ("anthropic_key", format!("sk-ant-{}", "x".repeat(60))),
            ("openai_key", format!("sk-{}", "x".repeat(48))),
            ("slack_token", format!("xoxb-{}", "x".repeat(10))),
            ("stripe_secret_key", format!("sk_live_{}", "x".repeat(24))),
            ("gitlab_pat", format!("glpat-{}", "x".repeat(20))),
            ("google_oauth_token", format!("ya29.{}", "x".repeat(20))),
            ("jwt", format!("eyJ{0}.{0}.{0}", "x".repeat(8))),
        ];
        assert_eq!(minimal.len(), patterns::ENTROPY_WINDOWS.len());
        for (provider, w) in patterns::ENTROPY_WINDOWS {
            let (_, src) = patterns::PROVIDER_PATTERNS
                .iter()
                .find(|(p, _)| p == provider)
                .unwrap_or_else(|| panic!("window for unknown provider {provider}"));
            let full = Regex::new(&format!("^(?:{src})$")).unwrap();
            let (_, example) = minimal.iter().find(|(p, _)| p == provider).unwrap();
            assert_eq!(example.len(), *w, "{provider}: window != minimum length");
            assert!(
                full.is_match(example),
                "{provider}: minimal example rejected"
            );
            assert!(
                !full.is_match(&example[..example.len() - 1]),
                "{provider}: a shorter string still matches — window too large"
            );
        }
    }

    #[test]
    fn every_unbounded_pattern_has_an_entropy_window() {
        for (provider, src) in patterns::PROVIDER_PATTERNS {
            if patterns::ALWAYS_REDACT_PROVIDERS.contains(provider) {
                continue;
            }
            let unbounded = PatternShape::of(src)
                .unwrap_or_else(|| panic!("{provider}: pattern not analysable"))
                .max_len
                .is_none();
            let windowed = patterns::ENTROPY_WINDOWS.iter().any(|(p, _)| p == provider);
            assert_eq!(
                unbounded, windowed,
                "{provider}: unbounded quantifier <=> ENTROPY_WINDOWS entry"
            );
        }
    }

    #[test]
    fn max_window_entropy_agrees_with_brute_force() {
        let alphabet = b"aaaaaaaaaaaabbbbcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123456789-_";
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..500 {
            let w = (next() % 60 + 8) as usize;
            let len = w + (next() % 200) as usize + 1;
            let span = match next() % 4 {
                0 => alphabet.len(),
                s => 4 + s as usize * 4,
            };
            let bytes: Vec<u8> = (0..len).map(|_| alphabet[next() as usize % span]).collect();
            let brute = (0..=len - w)
                .map(|i| bytes_entropy(&bytes[i..i + w]))
                .fold(0.0_f64, f64::max);
            let got = max_window_entropy(&bytes, w);
            assert_eq!(
                got >= ENTROPY_THRESHOLD,
                brute >= ENTROPY_THRESHOLD,
                "gate decision diverged: got {got} brute {brute}"
            );
            if brute < ENTROPY_THRESHOLD {
                assert!((got - brute).abs() < 1e-6, "got {got} brute {brute}");
            }
        }
    }

    #[test]
    fn scan_budget_exhaustion_fails_closed_and_stays_fast() {
        // Thousands of anthropic prefixes inside ONE long low-entropy run: the
        // next-char retry would re-scan the run from every prefix. The budget
        // stops that and the selector fails CLOSED — a real key appended
        // after the pathological region is still redacted.
        let real = F1_CASES[0].1;
        let hay = format!("{} {real} tail", "sk-ant-".repeat(40_000));
        let t = std::time::Instant::now();
        let hits = detect(&hay);
        let out = sanitize_output(&hay);
        assert!(
            t.elapsed() < std::time::Duration::from_secs(20),
            "selector went quadratic: {:?}",
            t.elapsed()
        );
        assert!(hits.iter().any(|h| h.matched_text.contains(real)));
        assert!(!out.contains(real), "real key leaked past the budget");
        assert!(out.ends_with(" tail"), "text outside matches mangled");
    }

    #[test]
    fn large_benign_input_is_not_flagged_by_the_budget() {
        let hay = "the quick brown fox jumps over the lazy dog sk- xoxb ".repeat(20_000);
        assert!(detect(&hay).is_empty());
        assert_eq!(sanitize_output(&hay), hay);
    }

    // ═══════════════════════════════════════════════════════════════════
    // SA8-F2 — a HIGH-entropy decoy whose tail swallows the real token's
    // prefix was accepted and consumed, so the real token (and, across
    // providers, the sequential splice) leaked its body.
    // ═══════════════════════════════════════════════════════════════════

    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const UPPER_NUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    /// Uppercase/digits without `A`, `I`, `K`: cannot form a stray `AKIA`.
    const UPPER_NO_AKIA: &[u8] = b"QWERTYUPSDFGHJLZXCVBNM0123456789";

    /// `n` pseudo-random chars of `charset` — high entropy for n >= 16.
    fn hi(next: &mut impl FnMut() -> u64, charset: &[u8], n: usize) -> String {
        (0..n)
            .map(|_| charset[(next() % charset.len() as u64) as usize] as char)
            .collect()
    }

    struct F2Case {
        provider: &'static str,
        prefix: &'static str,
        /// Decoy body length (the quantifier's minimum for unbounded ones).
        body: usize,
        charset: &'static [u8],
        real: String,
        /// Bytes of `real` the decoy body can swallow (its in-charset head).
        max_swallow: usize,
    }

    fn f2_cases() -> Vec<F2Case> {
        let body36 = "aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJqWxY";
        let c = |provider, prefix, body, charset, real: String, max_swallow| F2Case {
            provider,
            prefix,
            body,
            charset,
            real,
            max_swallow,
        };
        vec![
            c(
                "github_pat_classic",
                "ghp_",
                36,
                ALNUM,
                format!("ghp_{body36}"),
                3,
            ),
            c(
                "github_oauth",
                "gho_",
                36,
                ALNUM,
                format!("gho_{body36}"),
                3,
            ),
            c(
                "github_app_server",
                "ghs_",
                36,
                ALNUM,
                format!("ghs_{body36}"),
                3,
            ),
            c(
                "github_user_to_server",
                "ghu_",
                36,
                ALNUM,
                format!("ghu_{body36}"),
                3,
            ),
            c("npm_token", "npm_", 36, ALNUM, format!("npm_{body36}"), 3),
            c(
                "hf_token",
                "hf_",
                34,
                ALNUM,
                format!("hf_{}", &body36[..34]),
                2,
            ),
            c(
                "aws_akid",
                "AKIA",
                16,
                UPPER_NO_AKIA,
                "AKIAIOSFODNN7EXAMPLE".into(),
                3,
            ),
            c(
                "openai_key",
                "sk-",
                48,
                ALNUM,
                format!("sk-{body36}Zq7Wm2Xv8Nb4Kc"),
                2,
            ),
            c(
                "stripe_secret_key",
                "sk_live_",
                24,
                ALNUM,
                "sk_live_aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0".into(),
                2,
            ),
            c(
                "aws_secret_env",
                "aws_secret_access_key=",
                40,
                ALNUM,
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
                3,
            ),
            c(
                "google_oauth_token",
                "ya29.",
                20,
                ALNUM,
                "ya29.a0AfH6SMBx7yQk9vL2mNpQrStUvWxYz0123456789".into(),
                4,
            ),
            c(
                "google_api_key",
                "AIza",
                35,
                ALNUM,
                "AIzaSyAaB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJ".into(),
                3,
            ),
            c(
                "anthropic_key",
                "sk-ant-",
                60,
                ALNUM,
                F1_CASES[0].1.into(),
                6,
            ),
            c(
                "gitlab_pat",
                "glpat-",
                20,
                ALNUM,
                "glpat-aB3kP9zX1mQ7rL5tY2vN".into(),
                5,
            ),
            c(
                "slack_token",
                "xoxb-",
                10,
                ALNUM,
                "xoxb-1234567890-9876543210123-aB3kP9zX1mQ7rL5tY2vN4wE6".into(),
                4,
            ),
        ]
    }

    const SWALLOW_ALL: &[&str] = &["anthropic_key", "gitlab_pat", "slack_token"];

    #[test]
    fn sa8_f2_high_entropy_decoy_overlap_is_redacted_whole_both_ways() {
        let mut next = xorshift(0xf2f2_0000_dead_beef);
        let (mut legacy_leaks, mut probes) = (0usize, 0usize);
        for c in f2_cases() {
            let real_body = &c.real[c.real.len() - 16..];
            for j in 1..=c.max_swallow {
                for _ in 0..8 {
                    // `x <prefix><hi><real> y`: the decoy body swallows
                    // exactly `j` bytes of `real`, and the decoy itself passes
                    // the entropy gate (a HIGH-entropy decoy — the SA8-F2
                    // shape). SWALLOW_ALL decoys run to the end of `real`, so
                    // their own head need not pass.
                    let decoy_body = loop {
                        let b = hi(&mut next, c.charset, c.body - j);
                        let decoy = format!("{}{b}{}", c.prefix, &c.real[..j]);
                        if SWALLOW_ALL.contains(&c.provider)
                            || shannon_entropy(&decoy) >= ENTROPY_THRESHOLD
                        {
                            break b;
                        }
                    };
                    let hay = format!("x {}{decoy_body}{} y", c.prefix, c.real);
                    probes += 1;
                    let out = sanitize_output(&hay);
                    assert_eq!(
                        out,
                        format!("x <redacted:{}> y", c.provider),
                        "{}/j={j}: decoy+real must collapse to ONE marker: {hay}",
                        c.provider
                    );
                    assert!(
                        !out.contains(real_body),
                        "{}/j={j}: body leaked",
                        c.provider
                    );
                    // Where the body charset also holds the real token's
                    // separator (`-`), the decoy swallows the WHOLE real token
                    // and even the legacy chain redacted it; everywhere else
                    // the legacy chain leaked the body.
                    if legacy_sanitize_output(&hay).contains(real_body) {
                        legacy_leaks += 1;
                    } else {
                        assert!(
                            SWALLOW_ALL.contains(&c.provider),
                            "{}: no legacy leak",
                            c.provider
                        );
                        probes -= 1;
                    }
                    let hits = detect(&hay);
                    if patterns::REDACT_ONLY_PROVIDERS.contains(&c.provider) {
                        assert!(hits.is_empty(), "{}: redact-only blocked", c.provider);
                        continue;
                    }
                    assert!(
                        hits.iter()
                            .any(|h| h.provider == c.provider && h.matched_text == c.real),
                        "{}/j={j}: inbound missed the real token behind an accepted \
                         decoy; got {:?}",
                        c.provider,
                        hits.iter().map(|h| &h.matched_text).collect::<Vec<_>>()
                    );
                }
            }
        }
        // The legacy chain (like the iteration-2 selector) consumed the
        // accepted decoy and leaked the body on every other probe.
        assert_eq!(legacy_leaks, probes);
        assert!(
            legacy_leaks >= 8 * 30,
            "coverage: {legacy_leaks} legacy leaks"
        );
    }

    #[test]
    fn sa8_f2_cross_provider_overlap_ghp_then_akid() {
        let mut next = xorshift(0xa1a1_2b2b_3c3c_4d4d);
        let akid = "AKIAIOSFODNN7EXAMPLE";
        for j in 1..=4 {
            let hay = format!("ghp_{}{akid}", hi(&mut next, ALNUM, 36 - j));
            let hits = detect(&hay);
            assert!(
                hits.iter()
                    .any(|h| h.provider == "aws_akid" && h.matched_text == akid),
                "j={j}: AKID behind an accepted ghp lost inbound: {hits:?}"
            );
            let out = sanitize_output(&hay);
            assert_eq!(out, "<redacted:github_pat_classic>", "j={j}");
            assert!(!out.contains("IOSFODNN7EXAMPLE"), "j={j}: AKID body leaked");
        }
    }

    #[test]
    fn sa8_f2_cross_provider_akid_then_ghp_and_nested() {
        // `AKIA[0-9A-Z]{16}` cannot swallow a lowercase `ghp_` head, so the
        // AKID-first shapes are: glued right before a ghp (adjacent, NOT
        // merged — two tokens, two markers), NESTED in a ghp body, and an AKID
        // whose tail swallows the head of a second AKID.
        let mut next = xorshift(0x0bad_cafe_1234_5678);
        let akid = "AKIAIOSFODNN7EXAMPLE";
        let ghp = format!("ghp_{}", hi(&mut next, ALNUM, 36));
        let glued = format!("{akid}{ghp}");
        assert_eq!(
            sanitize_output(&glued),
            "<redacted:aws_akid><redacted:github_pat_classic>"
        );
        assert_eq!(detect(&glued).len(), 2);

        let nested = format!(
            "ghp_{}{akid}{}",
            hi(&mut next, ALNUM, 8),
            hi(&mut next, ALNUM, 8)
        );
        assert_eq!(sanitize_output(&nested), "<redacted:github_pat_classic>");
        let hits = detect(&nested);
        assert!(hits.iter().any(|h| h.provider == "aws_akid"), "{hits:?}");
        assert!(hits.iter().any(|h| h.provider == "github_pat_classic"));

        let chain = format!("AKIA{}{akid}", hi(&mut next, UPPER_NO_AKIA, 14));
        assert_eq!(sanitize_output(&chain), "<redacted:aws_akid>");
        assert!(detect(&chain).iter().any(|h| h.matched_text == akid));
    }

    #[test]
    fn sa8_f2_triple_overlap_chains_collapse_to_one_marker() {
        let mut next = xorshift(0x7777_1111_3333_5555);
        let akid = "AKIAIOSFODNN7EXAMPLE";
        for _ in 0..50 {
            // ghp decoy → ghp real → AKID, each swallowing 2 bytes of the next.
            let ghp_real = format!("ghp_{}AK", hi(&mut next, ALNUM, 34));
            let a = format!("ghp_{}{}{}", hi(&mut next, ALNUM, 34), ghp_real, &akid[2..]);
            // openai → ghp → npm, same shape.
            let ghp_mid = format!("ghp_{}np", hi(&mut next, ALNUM, 34));
            let npm = format!("npm_{}", hi(&mut next, ALNUM, 36));
            let b = format!("sk-{}{}{}", hi(&mut next, ALNUM, 46), ghp_mid, &npm[2..]);
            for (name, hay, label, secrets) in [
                (
                    "ghp>ghp>akid",
                    &a,
                    "github_pat_classic",
                    [ghp_real.as_str(), akid],
                ),
                (
                    "sk>ghp>npm",
                    &b,
                    "openai_key",
                    [ghp_mid.as_str(), npm.as_str()],
                ),
            ] {
                assert_eq!(
                    sanitize_output(hay),
                    format!("<redacted:{label}>"),
                    "{name}"
                );
                let hits = detect(hay);
                assert!(hits.len() >= 3, "{name}: every link reported: {hits:?}");
                for s in secrets {
                    assert!(
                        hits.iter().any(|h| h.matched_text == s),
                        "{name}: {s} lost inbound"
                    );
                }
            }
        }
    }

    #[test]
    fn sa8_f2_parity_property_detected_text_never_survives_sanitize() {
        // Seeded fuzz over prefixes, high/low-entropy runs, real tokens and
        // separators glued arbitrarily: whatever `detect` reports must be
        // absent from `sanitize_output` (decider/executor parity).
        const PIECES: &[&str] = &[
            "ghp_",
            "gho_",
            "ghs_",
            "ghu_",
            "npm_",
            "hf_",
            "AKIA",
            "sk-",
            "sk-ant-",
            "sk_live_",
            "rk_live_",
            "aws_secret_access_key=",
            "AWS_SECRET_ACCESS_KEY = ",
            "ya29.",
            "xoxb-",
            "glpat-",
            "AIza",
            "pypi-AgEI",
            "github_pat_",
            "eyJ",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
            " ",
            ".",
            "_",
            "-",
            "/",
            "\n",
            "=",
            "gh",
            "np",
            "sk",
            "AK",
            REAL_GHP,
            REAL_NPM,
            "AKIAIOSFODNN7EXAMPLE",
        ];
        let mut next = xorshift(0x9a41_7e57_0f00_d5ed);
        let mut reported = 0usize;
        for case in 0..20_000 {
            let mut hay = String::new();
            for _ in 0..next() % 12 + 1 {
                match next() % 5 {
                    0 | 1 => hay.push_str(PIECES[(next() % PIECES.len() as u64) as usize]),
                    2 => {
                        let n = (next() % 70 + 1) as usize;
                        hay.push_str(&hi(&mut next, ALNUM, n));
                    }
                    3 => {
                        let n = (next() % 30 + 1) as usize;
                        hay.push_str(&hi(&mut next, UPPER_NUM, n));
                    }
                    _ => hay.push_str(&"a".repeat((next() % 60 + 1) as usize)),
                }
            }
            let out = sanitize_output(&hay);
            for h in detect(&hay) {
                reported += 1;
                assert!(
                    !out.contains(&h.matched_text),
                    "case {case}: {} {:?} survived in {out:?} (input {hay:?})",
                    h.provider,
                    h.matched_text
                );
            }
        }
        assert!(
            reported > 5_000,
            "generator lost coverage: {reported} findings"
        );
    }

    #[test]
    fn sa8_f2_lone_tokens_behave_as_before() {
        // Resuming after an ACCEPTED match changes nothing for a lone token,
        // and a lone low-entropy decoy is still neither reported nor mangled.
        let mut next = xorshift(0x1357_9bdf_2468_ace0);
        let tok = format!("ghp_{}", hi(&mut next, ALNUM, 36));
        assert_eq!(detect(&tok).len(), 1);
        assert_eq!(sanitize_output(&tok), "<redacted:github_pat_classic>");
        assert!(detect(DECOY_GHP).is_empty());
        assert_eq!(sanitize_output(DECOY_GHP), DECOY_GHP);
    }

    // ═══════════════════════════════════════════════════════════════════
    // SA8-F2-bis — past the work cap the selector CONSUMED matches, so a
    // same-provider filler (`AKIA`×10k) + a bounded decoy swallowing the real
    // token's prefix leaked its body. Bounded patterns are now never capped;
    // unbounded ones widen post-cap matches to the end of their alphabet run.
    // ═══════════════════════════════════════════════════════════════════

    /// 92 high-entropy alphanumerics: bodies for synthetic real tokens.
    const HI_BODY: &str = "Zq7Wm2Xv8Nb4Kc6Rt9Yh3Jd5Fg1Ls0PuAeB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJxQwErTyUiOpAsDfGhJkLzXcVbNm";

    fn provider_index(provider: &str) -> usize {
        compiled()
            .providers
            .iter()
            .position(|p| *p == provider)
            .unwrap_or_else(|| panic!("unknown provider {provider}"))
    }

    #[test]
    fn pattern_shapes_are_derived_for_every_provider() {
        let bounded: &[(&str, usize)] = &[
            ("github_pat_classic", 40),
            ("github_oauth", 40),
            ("github_app_server", 40),
            ("github_user_to_server", 40),
            ("github_pat_fine", 93),
            ("npm_token", 40),
            ("hf_token", 37),
            ("aws_akid", 20),
            ("google_api_key", 39),
        ];
        for (provider, src) in patterns::PROVIDER_PATTERNS {
            let shape = PatternShape::of(src)
                .unwrap_or_else(|| panic!("{provider}: the shape analyser rejected {src}"));
            let expected = bounded.iter().find(|(p, _)| p == provider).map(|(_, m)| *m);
            assert_eq!(shape.max_len, expected, "{provider}: max_len");
        }
        let mut got = bounded_providers();
        got.sort();
        let mut want = bounded.to_vec();
        want.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn pattern_shape_alphabet_and_max_len_are_sound() {
        // Every match the real regex finds must fit the derived shape: no
        // byte outside the alphabet, no match longer than max_len.
        const POOL: &[&str] = &[
            "ghp_",
            "gho_",
            "github_pat_",
            "npm_",
            "hf_",
            "AKIA",
            "AIza",
            "sk-",
            "sk-ant-",
            "sk_live_",
            "rk_live_",
            "pypi-AgEI",
            "xoxb-",
            "glpat-",
            "ya29.",
            "eyJ",
            ".",
            "aws_secret_access_key",
            "AWS_SECRET_ACCESS_KEY",
            " = ",
            "=",
            "\t",
            "\n",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
            "/",
            "+",
            "_",
            "-",
            "\u{212a}",
            "\u{17f}",
            "\u{85}",
            "\u{a0}",
            "é",
            "\u{1F511}",
        ];
        let mut next = xorshift(0x5a4e_0f5e_ed00_0001);
        let cp = compiled();
        let mut checked = 0usize;
        for _ in 0..6_000 {
            let mut hay = String::new();
            for _ in 0..next() % 10 + 1 {
                match next() % 3 {
                    0 => hay.push_str(POOL[(next() % POOL.len() as u64) as usize]),
                    1 => {
                        let n = (next() % 90 + 1) as usize;
                        hay.push_str(&hi(&mut next, ALNUM, n));
                    }
                    _ => {
                        let n = (next() % 50 + 1) as usize;
                        hay.push_str(&hi(&mut next, b"Aa0_-/+=. xXkKsS", n));
                    }
                }
            }
            for (idx, re) in cp.individual.iter().enumerate() {
                let shape = &cp.shapes[idx];
                for m in re.find_iter(&hay) {
                    checked += 1;
                    if let Some(max) = shape.max_len {
                        assert!(m.len() <= max, "{}: {:?}", cp.providers[idx], m.as_str());
                    }
                    assert!(
                        m.as_str().bytes().all(|b| shape.alphabet[b as usize]),
                        "{}: byte outside the derived alphabet in {:?}",
                        cp.providers[idx],
                        m.as_str()
                    );
                }
            }
        }
        assert!(checked > 1_000, "generator lost coverage: {checked}");
    }

    #[test]
    fn pattern_shape_analyser_is_fail_closed_on_unknown_syntax() {
        for src in [
            r"(?x)a b",
            r"[[:alpha:]]{3}",
            r"\p{L}{4}",
            r"(?P<n>ab)",
            r"a{2",
            r"[a-z&&[^x]]",
            r"(ab",
        ] {
            assert!(PatternShape::of(src).is_none(), "{src} should be rejected");
        }
        let opaque = PatternShape::opaque();
        assert!(opaque.max_len.is_none());
        assert!(opaque.alphabet.iter().all(|b| *b));
        // Case folding reaches non-ASCII (`(?i)k` matches U+212A) — the
        // alphabet must include it or a post-cap run could stop mid-match.
        let folded = PatternShape::of(r"(?i)k{3}").unwrap();
        assert!(folded.alphabet[b'K' as usize] && folded.alphabet[0xE2]);
        assert_eq!(folded.max_len, Some(12));
        assert_eq!(PatternShape::of(r"a{300}").unwrap().max_len, None);
    }

    /// Every match of provider `idx`, next-character retry, no gate, no cap.
    fn reference_spans(idx: usize, hay: &str) -> Vec<(usize, usize, f64)> {
        let re = &compiled().individual[idx];
        let mut out = Vec::new();
        let mut pos = 0;
        while let Some(m) = re.find_at(hay, pos) {
            out.push((m.start(), m.end(), shannon_entropy(m.as_str())));
            pos = m.start() + hay[m.start()..].chars().next().map_or(1, char::len_utf8);
        }
        out
    }

    #[test]
    fn sa8_f2_bis_post_budget_selector_covers_every_match() {
        // With the budget forced to ZERO every unbounded provider runs in
        // fail-closed mode from its first match: each span the exhaustive
        // scan finds must lie inside ONE selected span. Bounded providers
        // ignore the budget: their selection is exactly the gated exhaustive
        // scan.
        const PIECES: &[&str] = &[
            "ghp_",
            "npm_",
            "hf_",
            "AKIA",
            "AIza",
            "github_pat_",
            "sk-",
            "sk-ant-",
            "sk_live_",
            "pypi-AgEI",
            "xoxb-",
            "glpat-",
            "ya29.",
            "eyJ",
            ".",
            "-",
            "_",
            " ",
            "\n",
            "aws_secret_access_key = ",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
            "-----",
            "\u{212a}",
            "AKIAIOSFODNN7EXAMPLE",
        ];
        let mut next = xorshift(0xb15b_15b1_5b15_b15b);
        let cp = compiled();
        let mut covered = 0usize;
        for case in 0..3_000 {
            let mut hay = String::new();
            for _ in 0..next() % 14 + 1 {
                match next() % 4 {
                    0 | 1 => {
                        let piece = PIECES[(next() % PIECES.len() as u64) as usize];
                        let reps = if next() % 4 == 1 {
                            (next() % 40 + 2) as usize
                        } else {
                            1
                        };
                        hay.push_str(&piece.repeat(reps));
                    }
                    2 => {
                        let n = (next() % 90 + 1) as usize;
                        hay.push_str(&hi(&mut next, ALNUM, n));
                    }
                    _ => hay.push_str(&"A".repeat((next() % 50 + 1) as usize)),
                }
            }
            for idx in 0..cp.providers.len() {
                let selected = select(idx, &hay, 0);
                let reference = reference_spans(idx, &hay);
                if cp.shapes[idx].max_len.is_some() {
                    let full = select(idx, &hay, usize::MAX);
                    let spans =
                        |v: &[RawMatch]| v.iter().map(|m| (m.start, m.end)).collect::<Vec<_>>();
                    assert_eq!(
                        spans(&selected),
                        spans(&full),
                        "case {case}: {}",
                        cp.providers[idx]
                    );
                    let gated: Vec<(usize, usize)> = reference
                        .iter()
                        .filter(|r| r.2 >= ENTROPY_THRESHOLD)
                        .map(|r| (r.0, r.1))
                        .collect();
                    assert_eq!(
                        spans(&selected),
                        gated,
                        "case {case}: {}",
                        cp.providers[idx]
                    );
                    continue;
                }
                for (s, e, _) in &reference {
                    covered += 1;
                    assert!(
                        selected.iter().any(|m| m.start <= *s && *e <= m.end),
                        "case {case}: {} span {s}..{e} {:?} not covered post-cap in {hay:?}",
                        cp.providers[idx],
                        &hay[*s..*e]
                    );
                }
            }
        }
        assert!(covered > 5_000, "generator lost coverage: {covered}");
    }

    #[test]
    fn sa8_f2_bis_bounded_fillers_never_leak() {
        // Table-driven over every bounded provider: a same-prefix filler big
        // enough to exhaust the old cap, then (a) a decoy swallowing j bytes
        // of the real token, (b) the real token glued, (c) after a space.
        for (provider, max_len) in bounded_providers() {
            let src = patterns::PROVIDER_PATTERNS
                .iter()
                .find(|(p, _)| *p == provider)
                .unwrap()
                .1;
            let prefix: String = src
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            let body_len = max_len - prefix.len();
            let body: String = if provider == "aws_akid" {
                "IOSFODNN7EXAMPLE".to_string()
            } else {
                HI_BODY[..body_len].to_string()
            };
            let real = format!("{prefix}{body}");
            assert!(
                Regex::new(&format!("^(?:{src})$")).unwrap().is_match(&real),
                "{provider}: synthetic token {real} does not match"
            );
            let fill = body[..1].to_string();
            let filler = prefix.repeat(40_000 / prefix.len());
            let mut hays = vec![format!("{filler}{real} y"), format!("{filler} {real} y")];
            for j in [1, prefix.len() - 1, prefix.len(), prefix.len() + 3] {
                let decoy = format!("{prefix}{}", fill.repeat(body_len - j));
                hays.push(format!("{filler} x {decoy}{real} y"));
                hays.push(format!("{filler}{decoy}{real} y"));
            }
            for hay in &hays {
                let out = sanitize_output(hay);
                for w in 0..=body.len() - 16 {
                    assert!(
                        !out.contains(&body[w..w + 16]),
                        "{provider}: body leaked: {}",
                        &out[out.len().saturating_sub(200)..]
                    );
                }
                assert!(
                    detect(hay)
                        .iter()
                        .any(|h| h.provider == provider && h.matched_text == real),
                    "{provider}: real token not reported"
                );
            }
        }
    }

    #[test]
    fn sa8_f2_bis_unbounded_post_cap_overlap_is_covered() {
        // Unbounded prefixes that are NOT in their own body charset (`sk-`,
        // `sk_live_`, `ya29.`) — a post-cap match used to end right inside
        // the next real token's prefix. After a cap-exhausting anthropic run
        // the widened span must still cover it.
        let real = F1_CASES[0].1;
        let hay = format!(
            "{}sk-ant-{}{real} tail",
            "sk-ant-".repeat(20_000),
            "a".repeat(58)
        );
        let out = sanitize_output(&hay);
        assert!(!out.contains(&real[7..40]), "anthropic body leaked");
        assert!(out.ends_with(" tail"));
        let idx = provider_index("openai_key");
        let openai = "sk-aB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJaB3kP9zX1mQ7rL5tY2vN4wE6sH8dC0fJ";
        let glued = format!("sk-{}sk{}", "a".repeat(48), &openai[2..]);
        let sel = select(idx, &glued, 0);
        let (s, e) = (glued.len() - openai.len(), glued.len());
        assert!(
            sel.iter().any(|m| m.start <= s && e <= m.end),
            "openai overlap uncovered post-cap"
        );
        // JWT: the real token starts inside the post-cap match's second
        // segment; its signature lies past the match's end (RED at e78ed87).
        let sig = "Sg7Wm2Xv8Nb4Kc6Rt9Yh3Jd5Fg1Ls0Pu";
        let jwt = format!(
            "{}.eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.{sig} end",
            "eyJ".repeat(20_000)
        );
        assert!(!sanitize_output(&jwt).contains(sig), "jwt signature leaked");
        // PEM: the next BEGIN shares the dashes of the post-cap match's END.
        let key = "MIIEowIBAAKCAQEAq7Wm2Xv8Nb4Kc6Rt9Yh3Jd5Fg1Ls0Pu";
        let pem = format!(
            "{}-----END RSA PRIVATE KEY-----BEGIN RSA PRIVATE KEY-----\n{key}\n-----END RSA PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----".repeat(3_000)
        );
        assert!(!sanitize_output(&pem).contains(key), "PEM body leaked");
    }

    #[test]
    fn sa8_f2_bis_parity_with_budget_exhausting_fillers() {
        // The SA8-F2 parity property on inputs that drive unbounded providers
        // past the cap and bounded providers through long filler runs.
        const FILLERS: &[&str] = &[
            "AKIA",
            "AIza",
            "github_pat_",
            "ghp_",
            "hf_",
            "sk-ant-",
            "xoxb-",
            "pypi-AgEI",
            "glpat-",
            "-----BEGIN RSA PRIVATE KEY-----",
        ];
        const TAILS: &[&str] = &[
            REAL_GHP,
            REAL_NPM,
            "AKIAIOSFODNN7EXAMPLE",
            " ",
            ".",
            "-",
            "_",
            "sk-",
            "ya29.",
            "eyJ",
            "\n",
        ];
        let mut next = xorshift(0xf111_e25f_111e_25f1);
        let mut reported = 0usize;
        for case in 0..60 {
            let filler = FILLERS[(next() % FILLERS.len() as u64) as usize];
            let mut hay = filler.repeat((next() % 12_000 + 2_000) as usize);
            for _ in 0..next() % 8 + 1 {
                match next() % 3 {
                    0 => hay.push_str(TAILS[(next() % TAILS.len() as u64) as usize]),
                    1 => hay.push_str(filler),
                    _ => {
                        let n = (next() % 70 + 1) as usize;
                        hay.push_str(&hi(&mut next, ALNUM, n));
                    }
                }
            }
            let out = sanitize_output(&hay);
            for h in detect(&hay) {
                reported += 1;
                assert!(
                    !out.contains(&h.matched_text),
                    "case {case}: {} survived (filler {filler})",
                    h.provider
                );
            }
        }
        assert!(reported > 30, "generator lost coverage: {reported}");
    }

    /// Release-mode perf probe: `cargo test --release --lib -- --ignored
    /// sa8_f2_perf --nocapture`. 5 MiB adversarial inputs, detect + sanitize.
    #[test]
    #[ignore]
    fn sa8_f2_perf_5mb_adversarial() {
        const MB5: usize = 5 * 1024 * 1024;
        let mut next = xorshift(0x5eed_5eed_5eed_5eed);
        let fill = |unit: &str| unit.repeat(MB5 / unit.len());
        let mut chain = |prefix: &str, charset: &[u8], n: usize| {
            let mut s = String::with_capacity(MB5 + 64);
            while s.len() < MB5 {
                s.push_str(prefix);
                s.push_str(&hi(&mut next, charset, n));
            }
            s
        };
        let ghp_chain = chain("ghp_", ALNUM, 34);
        let akid_chain = chain("AKIA", UPPER_NO_AKIA, 14);
        let sk_chain = chain("sk-", ALNUM, 46);
        let random = hi(&mut next, ALNUM, MB5);
        let cases: Vec<(&str, String)> = vec![
            ("ghp_ + 34 hi, every decoy overlapping the next", ghp_chain),
            ("AKIA + 14 hi, chained", akid_chain),
            ("sk- + 46 hi, chained", sk_chain),
            (
                "xoxb- repeated + random tail",
                format!("{}{}", fill("xoxb-"), &random[..4096]),
            ),
            (
                "sk-ant- repeated + real key",
                format!("{}{}", fill("sk-ant-"), F1_CASES[0].1),
            ),
            ("sk- + 5 MiB random alnum", format!("sk-{random}")),
            (
                "PEM BEGIN repeated, no END",
                fill("-----BEGIN RSA PRIVATE KEY-----\n"),
            ),
            (
                "pypi-AgEI repeated + random",
                format!("{}{}", fill("pypi-AgEI"), &random[..4096]),
            ),
            ("random alnum", random.clone()),
            (
                "AKIA x N + decoy swallowing 1 byte + real",
                format!(
                    "{} x AKIA{}AKIAIOSFODNN7EXAMPLE",
                    fill("AKIA"),
                    "I".repeat(15)
                ),
            ),
            (
                "AKIA x N glued to real",
                format!("{}AKIAIOSFODNN7EXAMPLE", fill("AKIA")),
            ),
            (
                "AIza x N glued to real",
                format!("{}AIza{}", fill("AIza"), &HI_BODY[..35]),
            ),
            (
                "github_pat_ x N glued to real",
                format!("{}github_pat_{}", fill("github_pat_"), &HI_BODY[..82]),
            ),
            (
                "ghp_ x N glued to real",
                format!("{}{REAL_GHP}", fill("ghp_")),
            ),
            ("hf_ x N", fill("hf_")),
            (
                "benign prose",
                fill("the quick brown fox jumps over the lazy dog sk- xoxb "),
            ),
        ];
        for (name, hay) in &cases {
            let t = std::time::Instant::now();
            let hits = detect(hay);
            let td = t.elapsed();
            let t = std::time::Instant::now();
            let out = sanitize_output(hay);
            let ts = t.elapsed();
            println!(
                "{name:<48} {:>5} KiB  detect {td:>9.2?}  sanitize {ts:>9.2?}  hits {:>6}  out {:>8} B",
                hay.len() / 1024,
                hits.len(),
                out.len()
            );
            assert!(
                td + ts < std::time::Duration::from_secs(1),
                "{name}: {td:?} + {ts:?}"
            );
        }
    }
}
