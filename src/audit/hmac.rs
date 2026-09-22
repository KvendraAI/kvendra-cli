//! HMAC-SHA256 chain over audit rows.
//!
//! Four HMAC layouts coexist on disk. The per-row `hmac_version` column picks
//! the layout `verify_chain` recomputes, so historical rows are never
//! rewritten:
//!
//!  - **v1** (alpha.1..0.1.0): commits to
//!    `id | ts | profile_id | primitive | action | args_hash | status |
//!     severity | flags | prev_hmac` (no `remote_audit_id`).
//!  - **v2** (0.3.0-alpha.1+): adds `| remote_audit_id?` at the end, where
//!    `None` canonicalizes to the empty string.
//!  - **v3** (ISSUE-KVD-CLI-6C43AA): adds `| error_code? | error_message?` at
//!    the end (each `None` canonicalizes to the empty string).
//!  - **v4** (ISSUE-KVD-CLI-F4ED93, [`CURRENT_HMAC_LAYOUT`]): every new row.
//!    Injective encoding — a domain-separation tag, the layout number, the two
//!    integers as fixed-width big-endian, every string length-prefixed (u64
//!    BE) and every optional field tagged `0x00` (None) / `0x01` (Some). No
//!    delimiter exists, so no field value can re-split the input, `None` and
//!    `Some("")` are distinct, and a v4 tag can never verify under v1/v2/v3.
//!
//! **Legacy layouts (v1/v2/v3) are frozen byte-for-byte** so every chain
//! written by <= 0.6.4 keeps verifying (golden vectors in the tests below).
//! Their weakness is that the input is pipe-joined and each layout is a pure
//! suffix extension of the previous one: a `|` inside a field can re-split the
//! input and alias another tuple or another layout (the v3→v2 downgrade of
//! ISSUE-KVD-CLI-F4ED93). The legacy builders therefore only emit a legacy tag
//! for **canonical** input — no `|` in any field, except the LAST field of the
//! LONGEST layout (v3 `error_message`), which can never be followed by another
//! field. Over that domain the legacy encoding is injective across all three
//! layouts (the fixed 18-byte `id|ts|` prefix is parsed positionally; the pipe
//! count of the remainder is exactly 7 for v1, exactly 8 for v2 and >= 10 for
//! v3). Non-canonical input gets a tag from a distinct domain that no legacy
//! row carries, and [`compute_for_layout`] refuses it outright — so a relabel
//! of a legacy row (which always needs a planted `|`) fails closed.

use ::hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

/// Layout every new row is written with. Decoupled from the SQLite schema
/// version (`migrations::CURRENT_VERSION`): v4 changes the MAC input only,
/// not the columns.
pub const CURRENT_HMAC_LAYOUT: i64 = 4;

const V4_DOMAIN: &[u8] = b"kvendra.audit.row\0";
const NONCANONICAL_LEGACY_DOMAIN: &[u8] = b"kvendra.audit.noncanonical-legacy\0";

/// The MAC-bound columns of one audit row, borrowed.
#[derive(Debug, Clone, Copy)]
pub struct RowFields<'a> {
    pub id: i64,
    pub ts_unix_ms: i64,
    pub profile_id: &'a str,
    pub primitive: &'a str,
    pub action: &'a str,
    pub args_hash_hex: &'a str,
    pub status: &'a str,
    pub severity: &'a str,
    pub flags: &'a str,
    pub prev_hmac_hex: &'a str,
    pub remote_audit_id: Option<&'a str>,
    pub error_code: Option<&'a str>,
    pub error_message: Option<&'a str>,
}

/// Why a row cannot be MACed under the layout it claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutError {
    /// The `hmac_version` is not a layout this binary knows.
    Unknown(i64),
    /// A legacy (v1/v2/v3) row whose pipe-joined encoding is ambiguous: a
    /// field carries the `|` delimiter where it could re-split the input.
    NonCanonicalLegacy { layout: i64, field: &'static str },
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LayoutError::Unknown(v) => write!(f, "unknown hmac layout version {v}"),
            LayoutError::NonCanonicalLegacy { layout, field } => write!(
                f,
                "legacy layout v{layout} row has a '|' in `{field}` — ambiguous encoding, refused"
            ),
        }
    }
}

/// Compute the tag of `row` under `layout`, failing closed on an unknown
/// layout or a non-canonical legacy row. THE single dispatch point used by
/// the verifier, the writer's re-hash and the export verifier.
pub fn compute_for_layout(
    key: &[u8],
    layout: i64,
    row: &RowFields<'_>,
) -> Result<String, LayoutError> {
    match layout {
        1..=3 => {
            if let Some(field) = legacy_noncanonical_field(layout, row) {
                return Err(LayoutError::NonCanonicalLegacy { layout, field });
            }
            Ok(legacy_mac(key, layout, row))
        }
        4 => Ok(injective_mac(key, V4_DOMAIN, 4, row)),
        other => Err(LayoutError::Unknown(other)),
    }
}

/// First field (in encoding order) whose `|` makes the legacy encoding of
/// `row` under `layout` ambiguous, or `None` when the input is canonical.
fn legacy_noncanonical_field(layout: i64, row: &RowFields<'_>) -> Option<&'static str> {
    let mut fields: Vec<(&'static str, &str)> = vec![
        ("profile_id", row.profile_id),
        ("primitive", row.primitive),
        ("action", row.action),
        ("args_hash_hex", row.args_hash_hex),
        ("status", row.status),
        ("severity", row.severity),
        ("flags", row.flags),
        ("prev_hmac_hex", row.prev_hmac_hex),
    ];
    if layout >= 2 {
        fields.push(("remote_audit_id", row.remote_audit_id.unwrap_or("")));
    }
    if layout >= 3 {
        fields.push(("error_code", row.error_code.unwrap_or("")));
    }
    fields
        .into_iter()
        .find(|(_, v)| v.as_bytes().contains(&b'|'))
        .map(|(name, _)| name)
}

/// The frozen pipe-joined legacy encoding (v1/v2/v3). Caller guarantees
/// `layout` is 1, 2 or 3.
fn legacy_mac(key: &[u8], layout: i64, row: &RowFields<'_>) -> String {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts arbitrary-length keys");
    mac.update(&row.id.to_be_bytes());
    mac.update(b"|");
    mac.update(&row.ts_unix_ms.to_be_bytes());
    mac.update(b"|");
    mac.update(row.profile_id.as_bytes());
    mac.update(b"|");
    mac.update(row.primitive.as_bytes());
    mac.update(b"|");
    mac.update(row.action.as_bytes());
    mac.update(b"|");
    mac.update(row.args_hash_hex.as_bytes());
    mac.update(b"|");
    mac.update(row.status.as_bytes());
    mac.update(b"|");
    mac.update(row.severity.as_bytes());
    mac.update(b"|");
    mac.update(row.flags.as_bytes());
    mac.update(b"|");
    mac.update(row.prev_hmac_hex.as_bytes());
    if layout >= 2 {
        mac.update(b"|");
        mac.update(row.remote_audit_id.unwrap_or("").as_bytes());
    }
    if layout >= 3 {
        mac.update(b"|");
        mac.update(row.error_code.unwrap_or("").as_bytes());
        mac.update(b"|");
        mac.update(row.error_message.unwrap_or("").as_bytes());
    }
    hex::encode(mac.finalize().into_bytes())
}

fn put_str(mac: &mut HmacSha256, s: &str) {
    mac.update(&(s.len() as u64).to_be_bytes());
    mac.update(s.as_bytes());
}

fn put_opt(mac: &mut HmacSha256, o: Option<&str>) {
    match o {
        None => mac.update(&[0u8]),
        Some(s) => {
            mac.update(&[1u8]);
            put_str(mac, s);
        }
    }
}

/// Injective, domain-separated encoding with the layout number bound inside
/// the MAC input.
fn injective_mac(key: &[u8], domain: &[u8], layout: i64, row: &RowFields<'_>) -> String {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts arbitrary-length keys");
    mac.update(domain);
    mac.update(&layout.to_be_bytes());
    mac.update(&row.id.to_be_bytes());
    mac.update(&row.ts_unix_ms.to_be_bytes());
    put_str(&mut mac, row.profile_id);
    put_str(&mut mac, row.primitive);
    put_str(&mut mac, row.action);
    put_str(&mut mac, row.args_hash_hex);
    put_str(&mut mac, row.status);
    put_str(&mut mac, row.severity);
    put_str(&mut mac, row.flags);
    put_str(&mut mac, row.prev_hmac_hex);
    put_opt(&mut mac, row.remote_audit_id);
    put_opt(&mut mac, row.error_code);
    put_opt(&mut mac, row.error_message);
    hex::encode(mac.finalize().into_bytes())
}

/// Legacy builder shared by the three public `compute_hmac_v{1,2,3}`: the
/// frozen legacy tag for canonical input, a tag from a disjoint domain (that
/// no stored legacy row carries) for ambiguous input.
fn legacy_or_noncanonical(key: &[u8], layout: i64, row: &RowFields<'_>) -> String {
    if legacy_noncanonical_field(layout, row).is_some() {
        injective_mac(key, NONCANONICAL_LEGACY_DOMAIN, layout, row)
    } else {
        legacy_mac(key, layout, row)
    }
}

/// Compute the HMAC over a v1 row (no `remote_audit_id`).
#[allow(clippy::too_many_arguments)]
pub fn compute_hmac(
    key: &[u8],
    id: i64,
    ts_unix_ms: i64,
    profile_id: &str,
    primitive: &str,
    action: &str,
    args_hash_hex: &str,
    status: &str,
    severity: &str,
    flags: &str,
    prev_hmac_hex: &str,
) -> String {
    compute_hmac_v1(
        key,
        id,
        ts_unix_ms,
        profile_id,
        primitive,
        action,
        args_hash_hex,
        status,
        severity,
        flags,
        prev_hmac_hex,
    )
}

/// v1 HMAC layout — kept for verifying historical rows post-migration.
#[allow(clippy::too_many_arguments)]
pub fn compute_hmac_v1(
    key: &[u8],
    id: i64,
    ts_unix_ms: i64,
    profile_id: &str,
    primitive: &str,
    action: &str,
    args_hash_hex: &str,
    status: &str,
    severity: &str,
    flags: &str,
    prev_hmac_hex: &str,
) -> String {
    let row = RowFields {
        id,
        ts_unix_ms,
        profile_id,
        primitive,
        action,
        args_hash_hex,
        status,
        severity,
        flags,
        prev_hmac_hex,
        remote_audit_id: None,
        error_code: None,
        error_message: None,
    };
    legacy_or_noncanonical(key, 1, &row)
}

/// v2 HMAC layout — extends v1 with `remote_audit_id` (NULL canonicalized
/// to the empty string). Kept for verifying historical rows.
#[allow(clippy::too_many_arguments)]
pub fn compute_hmac_v2(
    key: &[u8],
    id: i64,
    ts_unix_ms: i64,
    profile_id: &str,
    primitive: &str,
    action: &str,
    args_hash_hex: &str,
    status: &str,
    severity: &str,
    flags: &str,
    prev_hmac_hex: &str,
    remote_audit_id: Option<&str>,
) -> String {
    let row = RowFields {
        id,
        ts_unix_ms,
        profile_id,
        primitive,
        action,
        args_hash_hex,
        status,
        severity,
        flags,
        prev_hmac_hex,
        remote_audit_id,
        error_code: None,
        error_message: None,
    };
    legacy_or_noncanonical(key, 2, &row)
}

/// v3 HMAC layout — extends v2 with `error_code` + `error_message` (each NULL
/// canonicalized to the empty string). Kept for verifying historical rows.
#[allow(clippy::too_many_arguments)]
pub fn compute_hmac_v3(
    key: &[u8],
    id: i64,
    ts_unix_ms: i64,
    profile_id: &str,
    primitive: &str,
    action: &str,
    args_hash_hex: &str,
    status: &str,
    severity: &str,
    flags: &str,
    prev_hmac_hex: &str,
    remote_audit_id: Option<&str>,
    error_code: Option<&str>,
    error_message: Option<&str>,
) -> String {
    let row = RowFields {
        id,
        ts_unix_ms,
        profile_id,
        primitive,
        action,
        args_hash_hex,
        status,
        severity,
        flags,
        prev_hmac_hex,
        remote_audit_id,
        error_code,
        error_message,
    };
    legacy_or_noncanonical(key, 3, &row)
}

/// v4 HMAC layout ([`CURRENT_HMAC_LAYOUT`]) — same columns as v3, injective
/// domain-separated encoding with the layout number bound in the MAC input.
#[allow(clippy::too_many_arguments)]
pub fn compute_hmac_v4(
    key: &[u8],
    id: i64,
    ts_unix_ms: i64,
    profile_id: &str,
    primitive: &str,
    action: &str,
    args_hash_hex: &str,
    status: &str,
    severity: &str,
    flags: &str,
    prev_hmac_hex: &str,
    remote_audit_id: Option<&str>,
    error_code: Option<&str>,
    error_message: Option<&str>,
) -> String {
    let row = RowFields {
        id,
        ts_unix_ms,
        profile_id,
        primitive,
        action,
        args_hash_hex,
        status,
        severity,
        flags,
        prev_hmac_hex,
        remote_audit_id,
        error_code,
        error_message,
    };
    injective_mac(key, V4_DOMAIN, 4, &row)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(prev: &str, action: &str) -> String {
        compute_hmac(
            b"key",
            1,
            1_700_000_000_000,
            "p",
            "kvendra.git",
            action,
            "deadbeef",
            "ok",
            "info",
            "",
            prev,
        )
    }

    #[test]
    fn chain_is_deterministic() {
        let a = h("", "push");
        let b = h("", "push");
        assert_eq!(a, b);
    }

    #[test]
    fn tampering_action_breaks_chain() {
        let a = h("", "push");
        let b = h("", "force-push");
        assert_ne!(a, b);
    }

    #[test]
    fn prev_chains_propagate() {
        let a = h("", "push");
        let b = h(&a, "push");
        let c = h("", "push");
        // Same payload, different prev_hmac → different hmac.
        assert_ne!(a, b);
        assert_eq!(a, c);
    }

    /// HMAC-versioning: a v2 row with `remote_audit_id == None` must NOT
    /// equal the same row computed under v1 — even though both reduce to
    /// "no extra field", v2 always appends the trailing `|""` separator so
    /// the inputs differ in length. We rely on `hmac_version` per row to
    /// pick the right function on verify (`verify_chain`).
    #[test]
    fn v1_and_v2_disagree_even_with_null_remote_audit() {
        let v1 = compute_hmac_v1(b"key", 1, 0, "p", "x", "y", "z", "ok", "info", "", "");
        let v2 = compute_hmac_v2(b"key", 1, 0, "p", "x", "y", "z", "ok", "info", "", "", None);
        assert_ne!(v1, v2);
    }

    /// A v2 row with `remote_audit_id = Some("01H...")` differs from a v2
    /// row with `None`: the remote correlation id is bound to the chain.
    #[test]
    fn v2_remote_audit_id_changes_hmac() {
        let none = compute_hmac_v2(b"key", 1, 0, "p", "x", "y", "z", "ok", "info", "", "", None);
        let some = compute_hmac_v2(
            b"key",
            1,
            0,
            "p",
            "x",
            "y",
            "z",
            "ok",
            "info",
            "",
            "",
            Some("01H1234567890ABCDEFGH"),
        );
        assert_ne!(none, some);
    }

    /// A v3 row with both error fields `None` must NOT equal the equivalent v2
    /// row — v3 always appends the trailing `|""|""` separators, so the inputs
    /// differ in length. Per-row `hmac_version` picks the right function.
    #[test]
    fn v2_and_v3_disagree_even_with_null_errors() {
        let v2 = compute_hmac_v2(
            b"key", 1, 0, "p", "x", "y", "z", "error", "warn", "", "", None,
        );
        let v3 = compute_hmac_v3(
            b"key", 1, 0, "p", "x", "y", "z", "error", "warn", "", "", None, None, None,
        );
        assert_ne!(v2, v3);
    }

    /// The error diagnostics are bound to the chain: changing `error_code` or
    /// `error_message` changes the HMAC, so a tamperer cannot rewrite a
    /// failure row's reason without detection.
    #[test]
    fn v3_error_fields_change_hmac() {
        let base = compute_hmac_v3(
            b"key", 1, 0, "p", "x", "y", "z", "error", "warn", "", "", None, None, None,
        );
        let with_code = compute_hmac_v3(
            b"key",
            1,
            0,
            "p",
            "x",
            "y",
            "z",
            "error",
            "warn",
            "",
            "",
            None,
            Some("ALLOWLIST_VIOLATION"),
            None,
        );
        let with_msg = compute_hmac_v3(
            b"key",
            1,
            0,
            "p",
            "x",
            "y",
            "z",
            "error",
            "warn",
            "",
            "",
            None,
            Some("ALLOWLIST_VIOLATION"),
            Some("ref 'HEAD' not allowed"),
        );
        assert_ne!(base, with_code);
        assert_ne!(with_code, with_msg);
    }

    // ─── ISSUE-KVD-CLI-F4ED93 ─────────────────────────────────────────────

    const GK: &[u8] = b"kvendra-golden-key";

    fn golden_row() -> RowFields<'static> {
        RowFields {
            id: 42,
            ts_unix_ms: 1_700_000_000_123,
            profile_id: "github.kvendraai.cli-write",
            primitive: "kvendra.git",
            action: "push",
            args_hash_hex: "deadbeef",
            status: "ok",
            severity: "info",
            flags: "approval_src_signed",
            prev_hmac_hex: "00ff",
            remote_audit_id: None,
            error_code: None,
            error_message: None,
        }
    }

    /// FROZEN golden vectors captured from the v0.6.4 (`1217350`) builders.
    /// If any of these change, every chain already written on disk stops
    /// verifying — never "update" them to make a refactor pass.
    #[test]
    fn legacy_layouts_are_frozen_golden_vectors() {
        let r = golden_row();
        assert_eq!(
            compute_hmac_v1(
                GK,
                r.id,
                r.ts_unix_ms,
                r.profile_id,
                r.primitive,
                r.action,
                r.args_hash_hex,
                r.status,
                r.severity,
                r.flags,
                r.prev_hmac_hex,
            ),
            "6c608df645f6b1b02387745456882d1a216062432e22a189a4b8d81de3d951fc"
        );
        assert_eq!(
            compute_hmac_v2(
                GK,
                r.id,
                r.ts_unix_ms,
                r.profile_id,
                r.primitive,
                r.action,
                r.args_hash_hex,
                r.status,
                r.severity,
                r.flags,
                r.prev_hmac_hex,
                None,
            ),
            "f907d01bb67f2d7b655936c451639b6043a095e3be3f9de973c6b488ca88759f"
        );
        assert_eq!(
            compute_hmac_v2(
                GK,
                r.id,
                r.ts_unix_ms,
                r.profile_id,
                r.primitive,
                r.action,
                r.args_hash_hex,
                r.status,
                r.severity,
                r.flags,
                r.prev_hmac_hex,
                Some("01H1234567890ABCDEFGHJKMNP"),
            ),
            "2ba363387c71f7a487c1618aa8967b451271b2b567011a67ef983274eea531b4"
        );
        assert_eq!(
            compute_hmac_v3(
                GK,
                r.id,
                r.ts_unix_ms,
                r.profile_id,
                r.primitive,
                r.action,
                r.args_hash_hex,
                r.status,
                r.severity,
                r.flags,
                r.prev_hmac_hex,
                None,
                None,
                None,
            ),
            "e6cc8f540cfe8e3b054f4c5ea79701065f8e24704cfdaf0b2fde00fb4912c2ff"
        );
        // A v3 error row whose free-form message carries a `|` (legal: last
        // field of the longest layout) keeps verifying.
        assert_eq!(
            compute_hmac_v3(
                GK,
                43,
                1_700_000_000_456,
                "shell.profile",
                "kvendra.shell",
                "exec",
                "deadbeef",
                "error",
                "warn",
                "allowlist_denied",
                "00ff",
                None,
                Some("ALLOWLIST_VIOLATION"),
                Some("binary 'id' not allowed | see allowlist"),
            ),
            "e8d9a78fe668aed6fd2bf349d1373c3dd3b6b11ab2b08441c29ed32fb851aceb"
        );
        // The dispatch point agrees with the public builders on canonical rows.
        assert_eq!(
            compute_for_layout(GK, 1, &r).unwrap(),
            "6c608df645f6b1b02387745456882d1a216062432e22a189a4b8d81de3d951fc"
        );
        assert_eq!(
            compute_for_layout(GK, 3, &r).unwrap(),
            "e6cc8f540cfe8e3b054f4c5ea79701065f8e24704cfdaf0b2fde00fb4912c2ff"
        );
    }

    #[test]
    fn v4_none_and_empty_string_differ() {
        let r = golden_row();
        let none = compute_for_layout(GK, 4, &r).unwrap();
        for f in 0..3 {
            let mut e = r;
            match f {
                0 => e.remote_audit_id = Some(""),
                1 => e.error_code = Some(""),
                _ => e.error_message = Some(""),
            }
            assert_ne!(none, compute_for_layout(GK, 4, &e).unwrap(), "field #{f}");
        }
    }

    #[test]
    fn v4_pipe_in_primitive_cannot_alias_action() {
        let mut a = golden_row();
        a.primitive = "kvendra.git|push";
        a.action = "";
        let b = golden_row();
        let mut c = golden_row();
        c.primitive = "kvendra.git|";
        c.action = "push";
        let ta = compute_for_layout(GK, 4, &a).unwrap();
        let tb = compute_for_layout(GK, 4, &b).unwrap();
        let tc = compute_for_layout(GK, 4, &c).unwrap();
        assert_ne!(ta, tb);
        assert_ne!(tb, tc);
        assert_ne!(ta, tc);
    }

    #[test]
    fn v4_layout_number_is_bound_in_the_mac() {
        let r = golden_row();
        let v4 = injective_mac(GK, V4_DOMAIN, 4, &r);
        assert_eq!(v4, compute_for_layout(GK, 4, &r).unwrap());
        assert_ne!(v4, injective_mac(GK, V4_DOMAIN, 5, &r));
        assert_ne!(v4, injective_mac(GK, V4_DOMAIN, 3, &r));
        for legacy in 1..=3 {
            assert_ne!(v4, compute_for_layout(GK, legacy, &r).unwrap());
        }
        assert_eq!(
            v4,
            compute_hmac_v4(
                GK,
                r.id,
                r.ts_unix_ms,
                r.profile_id,
                r.primitive,
                r.action,
                r.args_hash_hex,
                r.status,
                r.severity,
                r.flags,
                r.prev_hmac_hex,
                None,
                None,
                None,
            )
        );
    }

    #[test]
    fn unknown_layouts_fail_closed() {
        let r = golden_row();
        for v in [0, -1, 5, 99, i64::MAX] {
            assert_eq!(compute_for_layout(GK, v, &r), Err(LayoutError::Unknown(v)));
        }
    }

    /// The legacy downgrade always needs a `|` planted in a field that is not
    /// the last field of v3 — the dispatch point refuses it, and the public
    /// builder never returns the colliding legacy tag for it.
    #[test]
    fn noncanonical_legacy_rows_are_refused() {
        let mut r = golden_row();
        r.remote_audit_id = Some("|ALLOWLIST_VIOLATION|ref not allowed");
        assert_eq!(
            compute_for_layout(GK, 2, &r),
            Err(LayoutError::NonCanonicalLegacy {
                layout: 2,
                field: "remote_audit_id"
            })
        );
        let mut a = golden_row();
        a.action = "push|x";
        for layout in 1..=3 {
            assert!(compute_for_layout(GK, layout, &a).is_err());
        }
        assert_ne!(
            compute_hmac_v1(
                GK,
                a.id,
                a.ts_unix_ms,
                a.profile_id,
                a.primitive,
                a.action,
                a.args_hash_hex,
                a.status,
                a.severity,
                a.flags,
                a.prev_hmac_hex,
            ),
            legacy_mac(GK, 1, &a)
        );
        // error_message may carry pipes under v3 (it is the final field).
        let mut e = golden_row();
        e.error_message = Some("a|b|c");
        assert!(compute_for_layout(GK, 3, &e).is_ok());
    }

    #[test]
    fn schema_version_and_hmac_layout_are_decoupled() {
        assert_eq!(crate::audit::migrations::CURRENT_VERSION, 3);
        assert_eq!(CURRENT_HMAC_LAYOUT, 4);
    }
}
