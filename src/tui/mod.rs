//! TUI — Pase B placeholder.
//!
//! `kvendra dashboard` and `kvendra audit --watch` live UIs ship in Pase B.
//! This module exists so the feature flag `tui` compiles cleanly when
//! `ratatui` and `crossterm` are pulled in.

pub mod audit_watch;
pub mod dashboard;

/// Render-time escaping for audit fields shown in the TUIs (Iter3 — terminal
/// injection). New refusal rows are stored escaped by the dispatcher, but rows
/// written by older binaries (or other writers) may still carry raw control
/// bytes / bidi overrides. Control characters and Unicode bidi/format
/// controls are rendered as `\u{..}` escapes; everything else is kept.
pub fn display_safe(s: &str) -> std::borrow::Cow<'_, str> {
    fn needs_escape(c: char) -> bool {
        c.is_control()
            || matches!(
                c,
                '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
                    | '\u{FEFF}'
            )
    }
    if !s.chars().any(needs_escape) {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if needs_escape(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    std::borrow::Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::display_safe;

    #[test]
    fn display_safe_escapes_control_and_bidi_only() {
        assert_eq!(display_safe("shell.profile"), "shell.profile");
        assert_eq!(display_safe("café|x"), "café|x");
        let r = display_safe("a\x1b[2J\r\n\u{202e}b");
        assert_eq!(r, "a\\u{1b}[2J\\u{d}\\u{a}\\u{202e}b");
        assert!(!r.chars().any(char::is_control));
    }
}
