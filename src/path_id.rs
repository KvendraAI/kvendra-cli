//! Safe path-component identifiers — THE rule for every untrusted identifier
//! that becomes one component of a filesystem path.
//!
//! Kvendra builds paths out of identifiers it did not choose: the agent picks
//! `profile_id` (`allowlists/<id>.yaml`, `secrets/<id>.blob`,
//! `profiles/<id>.json`) and the BROKER picks `template_id`
//! (`cache/allowlists/<ws>/<id>.yaml`). Both end up interpolated into a path,
//! so both need the same predicate — [`is_safe_path_component`]. Whenever a
//! new untrusted identifier becomes a path component, it validates HERE; do
//! not hand-roll a second charset check somewhere else.
//!
//! Rationale (PAT-KVD-CLI-C18A74 — "ONE shared canonicalizer per operand,
//! used by producer and enforcer alike"): the v0.6.4 audit found the same
//! traversal defect twice because the profile-id rule lived in
//! `primitives::is_valid_profile_id` and the broker-supplied `template_id`
//! never reached it (ISSUE-KVD-CLI-3319F0). A single `pub` predicate makes
//! the rule greppable and makes divergence impossible.
//!
//! The predicate is deliberately *lexical and total*: it never touches the
//! filesystem, never canonicalizes and never resolves symlinks, so it cannot
//! be raced. It is a NECESSARY condition, not a sufficient one — callers that
//! build a path from a validated component must still assert containment with
//! `path.parent() == Some(root)`. (`Path::starts_with` is NOT containment: a
//! `..` segment survives the join lexically and still "starts with" the root.)

/// Maximum length of an untrusted identifier used as one path component.
///
/// 128 bytes: the common filesystem limit is 255 bytes per component and the
/// longest suffix Kvendra appends is `.yaml.etag.tmp.<pid>`, so 128 leaves
/// ample headroom while staying ~5x the longest identifier seen in practice.
pub const MAX_PATH_COMPONENT_ID_LEN: usize = 128;

/// Returns `true` when `id` is safe to interpolate as a SINGLE filesystem path
/// component.
///
/// The rule — non-empty, at most [`MAX_PATH_COMPONENT_ID_LEN`] bytes, no `..`
/// anywhere, no leading `.`, and every character in `[A-Za-z0-9._-]`:
///
/// - the charset rejects `/`, `\`, NUL, newlines, spaces, shell metacharacters
///   and every non-ASCII byte, so the value can never become more than one
///   component and can never be an absolute path (which `Path::join` would
///   silently honour by discarding the base);
/// - the `..` guard rejects parent traversal even in shapes the charset alone
///   would allow (`..`, `a..b` is rejected too — deliberately conservative:
///   over-rejection degrades to a skipped template, under-rejection is a
///   write outside the root);
/// - the leading-`.` guard rejects `.` (which joins to a path whose parent IS
///   the root, so containment alone would not catch it) and keeps hidden-file
///   names out of the cache.
pub fn is_safe_path_component(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_PATH_COMPONENT_ID_LEN
        && !id.contains("..")
        && !id.starts_with('.')
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Returns `true` when `s` is safe to embed in an audit-chain HMAC field.
///
/// ISSUE-KVD-CLI-F4ED93: the audit chain's MAC input is pipe-joined, so an
/// agent-supplied value containing `|` (or a NUL / newline / carriage return,
/// or any other control byte) can re-split the canonical form and make two
/// different rows MAC to the same tag. This is the write-time defence in
/// depth that complements the injective encoding.
///
/// Same shape as [`is_safe_path_component`] minus the path-specific guards:
/// non-empty, at most [`MAX_PATH_COMPONENT_ID_LEN`] bytes, no control
/// characters, no `|`, `\0`, `\n` or `\r`, charset `[A-Za-z0-9._-]`.
pub fn is_safe_audit_field(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_PATH_COMPONENT_ID_LEN
        && !s
            .chars()
            .any(|c| c.is_control() || matches!(c, '|' | '\0' | '\n' | '\r'))
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legit_identifiers_are_accepted() {
        assert!(is_safe_path_component("github-deploy-tmpl-v1"));
        assert!(is_safe_path_component("github.kvendraai.cli-write"));
        assert!(is_safe_path_component("aws.kvendra.staging-deploy"));
        assert!(is_safe_path_component("p1_test-2"));
        assert!(is_safe_path_component("a"));
    }

    #[test]
    fn traversal_and_separator_shapes_are_rejected() {
        assert!(!is_safe_path_component(""));
        assert!(!is_safe_path_component("."));
        assert!(!is_safe_path_component(".."));
        assert!(!is_safe_path_component("../../etc/passwd"));
        assert!(!is_safe_path_component("a/b"));
        assert!(!is_safe_path_component("a\\b"));
        assert!(!is_safe_path_component("/tmp/evil"));
        assert!(!is_safe_path_component("tmpl..v2"));
        assert!(!is_safe_path_component(".hidden"));
    }

    #[test]
    fn control_and_non_ascii_shapes_are_rejected() {
        assert!(!is_safe_path_component("a\0b"));
        assert!(!is_safe_path_component("a b"));
        assert!(!is_safe_path_component("tmpl\n"));
        assert!(!is_safe_path_component("plantillañ"));
        assert!(!is_safe_path_component("p$(id)"));
        assert!(!is_safe_path_component("a|b"));
    }

    #[test]
    fn length_bound_is_inclusive() {
        let ok = "a".repeat(MAX_PATH_COMPONENT_ID_LEN);
        let too_long = "a".repeat(MAX_PATH_COMPONENT_ID_LEN + 1);
        assert!(is_safe_path_component(&ok));
        assert!(!is_safe_path_component(&too_long));
    }

    #[test]
    fn audit_field_rejects_the_canonical_form_separator() {
        assert!(is_safe_audit_field("kvendra.github"));
        assert!(is_safe_audit_field("read_repo"));
        assert!(!is_safe_audit_field(""));
        assert!(!is_safe_audit_field("a|b"));
        assert!(!is_safe_audit_field("a\0b"));
        assert!(!is_safe_audit_field("a\nb"));
        assert!(!is_safe_audit_field("a\rb"));
        assert!(!is_safe_audit_field(
            &"a".repeat(MAX_PATH_COMPONENT_ID_LEN + 1)
        ));
        // Unlike a path component, a leading dot is not a hazard here.
        assert!(is_safe_audit_field(".ok"));
    }
}
