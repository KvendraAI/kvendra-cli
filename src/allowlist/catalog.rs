//! Destructive operations catalog (REQ-KVD-004 / ROAD-KVD-007 ISSUE-012).
//!
//! Const Rust array (ADR-KVD-017): single source of truth para
//! [`crate::allowlist::validator::validate`] y
//! [`crate::approval::policy::lookup_destructive`].
//!
//! Cada entrada en [`CATALOG`] declara una operación que requiere `opt-in`
//! explícito (`accept_destructive: true` en allowlist YAML) o que merece
//! una marca informativa (`Annotated`) en `kvendra secret validate`.
//!
//! ISSUE-KVD-CLI-9B3395 (SA7) — every `primitive.operation` of
//! [`crate::primitives::catalog`] is classified EXACTLY once: either it has a
//! rule in [`CATALOG`] or it is listed in [`READ_ONLY_OPS`]. A pair that is in
//! neither table (a future primitive/op added without classifying it) is
//! treated as DESTRUCTIVE — a catalog miss fails closed, not open. The
//! capabilities manifest derives its `destructive_ops` from [`CATALOG`], so the
//! published contract and the enforcement table cannot drift apart.

use crate::allowlist::dsl::OperationConstraints;
use serde_json::{Map, Value};

/// Severidad de una entrada del catálogo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestructiveKind {
    /// Bloquea la allowlist sin opt-in. Marca `[⚠ DESTRUCTIVE — owner accepted]`.
    Destructive,
    /// Permite la allowlist sin opt-in pero marca `[⚠ ANNOTATED]`.
    Annotated,
}

/// Una regla del catálogo.
pub struct DestructiveRule {
    pub primitive: &'static str,
    pub operation: &'static str,
    pub kind: DestructiveKind,
    /// Predicate opcional sobre args runtime (ADR-KVD-018). Si `None`, la
    /// regla aplica incondicionalmente.
    pub args_predicate: Option<fn(&Value) -> bool>,
}

// --- predicates puras (ADR-KVD-018) ---

fn git_tag_with_force(args: &Value) -> bool {
    args.get("force").and_then(Value::as_bool).unwrap_or(false)
}

fn http_method_mutates(args: &Value) -> bool {
    matches!(
        args.get("method")
            .and_then(Value::as_str)
            .map(str::to_ascii_uppercase)
            .as_deref(),
        Some("POST" | "PUT" | "PATCH" | "DELETE")
    )
}

fn issue_state_closed(args: &Value) -> bool {
    args.get("state").and_then(Value::as_str) == Some("closed")
}

// --- catálogo (owner ratificado 2026-05-07, extended 2026-05-27 with create_issue,
// 2026-09 with github.release / add_topics + git.clone / commit — ISSUE-KVD-CLI-9B3395) ---

pub const CATALOG: &[DestructiveRule] = &[
    DestructiveRule {
        primitive: "kvendra.git",
        operation: "clone",
        kind: DestructiveKind::Destructive,
        args_predicate: None,
    },
    DestructiveRule {
        primitive: "kvendra.git",
        operation: "push",
        kind: DestructiveKind::Destructive,
        args_predicate: None,
    },
    DestructiveRule {
        primitive: "kvendra.git",
        operation: "commit",
        kind: DestructiveKind::Annotated,
        args_predicate: None,
    },
    DestructiveRule {
        primitive: "kvendra.git",
        operation: "tag",
        kind: DestructiveKind::Destructive,
        args_predicate: Some(git_tag_with_force),
    },
    DestructiveRule {
        primitive: "kvendra.github",
        operation: "update_repo",
        kind: DestructiveKind::Destructive,
        args_predicate: None,
    },
    DestructiveRule {
        primitive: "kvendra.github",
        operation: "update_issue",
        kind: DestructiveKind::Annotated,
        args_predicate: Some(issue_state_closed),
    },
    DestructiveRule {
        primitive: "kvendra.github",
        operation: "create_issue",
        kind: DestructiveKind::Destructive,
        args_predicate: None,
    },
    DestructiveRule {
        primitive: "kvendra.github",
        operation: "release",
        kind: DestructiveKind::Destructive,
        args_predicate: None,
    },
    DestructiveRule {
        primitive: "kvendra.github",
        operation: "add_topics",
        kind: DestructiveKind::Destructive,
        args_predicate: None,
    },
    DestructiveRule {
        primitive: "kvendra.npm",
        operation: "publish",
        kind: DestructiveKind::Destructive,
        args_predicate: None,
    },
    DestructiveRule {
        primitive: "kvendra.npm",
        operation: "deprecate",
        kind: DestructiveKind::Destructive,
        args_predicate: None,
    },
    DestructiveRule {
        primitive: "kvendra.pypi",
        operation: "upload",
        kind: DestructiveKind::Destructive,
        args_predicate: None,
    },
    // ISSUE-KVD-CLI-9D5CF5 — a sync overwrites its destination (and, upload
    // direction, exfiltrates the local tree) with or without `--delete`, so
    // the consent gate must fire unconditionally. It used to be gated on the
    // `delete` predicate.
    DestructiveRule {
        primitive: "kvendra.aws",
        operation: "s3_sync",
        kind: DestructiveKind::Destructive,
        args_predicate: None,
    },
    DestructiveRule {
        primitive: "kvendra.aws",
        operation: "s3_cp",
        kind: DestructiveKind::Destructive,
        args_predicate: None,
    },
    DestructiveRule {
        primitive: "kvendra.aws",
        operation: "cloudfront_invalidate",
        kind: DestructiveKind::Annotated,
        args_predicate: None,
    },
    DestructiveRule {
        primitive: "kvendra.aws",
        operation: "lambda_invoke",
        kind: DestructiveKind::Destructive,
        args_predicate: None,
    },
    DestructiveRule {
        primitive: "kvendra.http",
        operation: "request",
        kind: DestructiveKind::Destructive,
        args_predicate: Some(http_method_mutates),
    },
    DestructiveRule {
        primitive: "kvendra.shell",
        operation: "exec",
        kind: DestructiveKind::Destructive,
        args_predicate: None,
    },
    DestructiveRule {
        primitive: "kvendra.unsafe.raw_token",
        operation: "get",
        kind: DestructiveKind::Destructive,
        args_predicate: None,
    },
];

/// Operaciones explícitamente read-only: sin efecto de escritura remoto ni
/// local. Junto con [`CATALOG`] clasifica cada operación del catálogo de
/// primitives exactamente una vez.
pub const READ_ONLY_OPS: &[(&str, &str)] = &[
    ("kvendra.git", "pull"),
    ("kvendra.github", "read_repo"),
    ("kvendra.github", "read_issue"),
    ("kvendra.github", "list_issues"),
    ("kvendra.npm", "read_metadata"),
    ("kvendra.pypi", "read_metadata"),
];

/// `true` si `(primitive, operation)` tiene al menos una regla en [`CATALOG`]
/// (de cualquier kind, con o sin predicate).
pub fn has_rule(primitive: &str, operation: &str) -> bool {
    CATALOG
        .iter()
        .any(|rule| rule.primitive == primitive && rule.operation == operation)
}

/// `true` si `(primitive, operation)` está en [`READ_ONLY_OPS`].
pub fn is_read_only(primitive: &str, operation: &str) -> bool {
    READ_ONLY_OPS
        .iter()
        .any(|(p, o)| *p == primitive && *o == operation)
}

/// Ni regla ni read-only → sin clasificar → se trata como destructive.
fn is_unclassified(primitive: &str, operation: &str) -> bool {
    !has_rule(primitive, operation) && !is_read_only(primitive, operation)
}

/// `true` si `(primitive, operation, args)` está marcada `Destructive` en el
/// catálogo, o si la operación no está clasificada (fail-closed).
pub fn is_destructive(primitive: &str, operation: &str, args: &Value) -> bool {
    is_unclassified(primitive, operation)
        || matches_kind(DestructiveKind::Destructive, primitive, operation, args)
}

/// `true` si `(primitive, operation, args)` está marcada `Annotated` en el catálogo.
pub fn is_annotated(primitive: &str, operation: &str, args: &Value) -> bool {
    matches_kind(DestructiveKind::Annotated, primitive, operation, args)
}

fn matches_kind(kind: DestructiveKind, primitive: &str, operation: &str, args: &Value) -> bool {
    CATALOG.iter().any(|rule| {
        rule.kind == kind
            && rule.primitive == primitive
            && rule.operation == operation
            && rule.args_predicate.is_none_or(|pred| pred(args))
    })
}

/// Validate-time check: ¿la operation declarada en YAML PODRÍA disparar una
/// ejecución destructive (ADR-KVD-018 worst-case rule)?
///
/// - Si la regla NO tiene predicate (ej. `lambda_invoke`) → siempre true.
/// - Si la regla es `kvendra.http.request` → inspecciona `methods` declarados.
/// - Si la regla tiene predicate runtime-only (ej.
///   `git.tag.force`) → worst-case true (fuerza opt-in en validate-time).
/// - Si la operación no está clasificada (ni regla ni read-only) → true.
pub fn could_be_destructive(primitive: &str, operation: &str, c: &OperationConstraints) -> bool {
    if is_unclassified(primitive, operation) {
        return true;
    }
    CATALOG.iter().any(|rule| {
        if rule.kind != DestructiveKind::Destructive {
            return false;
        }
        if rule.primitive != primitive || rule.operation != operation {
            return false;
        }
        match rule.args_predicate {
            None => true,
            Some(pred) if primitive == "kvendra.http" => pred(&constraints_to_args_value(c)),
            Some(_) => true,
        }
    })
}

/// Sintetiza un `Value` desde [`OperationConstraints`] para evaluación
/// validate-time. Solo expone los campos que el validator puede inspeccionar
/// estáticamente (e.g. `methods` declarados). Para predicates con args runtime
/// puros, [`could_be_destructive`] aplica la regla worst-case.
pub fn constraints_to_args_value(c: &OperationConstraints) -> Value {
    let mut obj = Map::new();
    if let Some(methods) = &c.methods
        && let Some(mutating) = methods.iter().find(|m| {
            matches!(
                m.to_ascii_uppercase().as_str(),
                "POST" | "PUT" | "PATCH" | "DELETE"
            )
        })
    {
        obj.insert("method".into(), Value::String(mutating.clone()));
    }
    Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn primitive_ops() -> Vec<(&'static str, &'static str)> {
        crate::primitives::catalog()
            .iter()
            .flat_map(|p| p.operations.iter().map(move |o| (p.name, *o)))
            .collect()
    }

    #[test]
    fn catalog_plus_read_only_covers_every_primitive_op() {
        let ops = primitive_ops();
        assert_eq!(CATALOG.len() + READ_ONLY_OPS.len(), ops.len());
    }

    #[test]
    fn every_primitive_op_is_classified() {
        for (p, o) in primitive_ops() {
            assert!(
                has_rule(p, o) ^ is_read_only(p, o),
                "{p}.{o} must be ruled XOR read-only"
            );
        }
    }

    #[test]
    fn every_rule_and_read_only_entry_names_a_real_op() {
        let ops = primitive_ops();
        for r in CATALOG {
            assert!(
                ops.contains(&(r.primitive, r.operation)),
                "catalog rule {}.{} is not a primitive op",
                r.primitive,
                r.operation
            );
        }
        for entry in READ_ONLY_OPS {
            assert!(
                ops.contains(entry),
                "read-only {entry:?} is not a primitive op"
            );
        }
    }

    #[test]
    fn catalog_has_at_most_one_rule_per_op() {
        for (i, a) in CATALOG.iter().enumerate() {
            for b in &CATALOG[i + 1..] {
                assert!(
                    !(a.primitive == b.primitive && a.operation == b.operation),
                    "duplicate rule for {}.{}",
                    a.primitive,
                    a.operation
                );
            }
        }
    }

    #[test]
    fn sa7_unclassified_future_op_is_destructive() {
        assert!(is_destructive(
            "kvendra.github",
            "delete_repo_v2",
            &Value::Null
        ));
        assert!(is_destructive("kvendra.npm", "unpublish", &Value::Null));
        assert!(could_be_destructive(
            "kvendra.npm",
            "unpublish",
            &OperationConstraints::default()
        ));
    }

    #[test]
    fn github_release_and_add_topics_destructive_unconditional() {
        for op in ["release", "add_topics"] {
            assert!(is_destructive("kvendra.github", op, &Value::Null));
            assert!(could_be_destructive(
                "kvendra.github",
                op,
                &OperationConstraints::default()
            ));
        }
    }

    #[test]
    fn git_commit_annotated_not_destructive() {
        assert!(is_annotated("kvendra.git", "commit", &Value::Null));
        assert!(!is_destructive("kvendra.git", "commit", &Value::Null));
        assert!(!could_be_destructive(
            "kvendra.git",
            "commit",
            &OperationConstraints::default()
        ));
    }

    #[test]
    fn git_clone_destructive_unconditional() {
        assert!(is_destructive("kvendra.git", "clone", &Value::Null));
        assert!(could_be_destructive(
            "kvendra.git",
            "clone",
            &OperationConstraints::default()
        ));
    }

    // Inverted from `s3_sync_destructive_only_with_delete`
    // (ISSUE-KVD-CLI-9D5CF5): a sync writes its destination whether or not
    // `--delete` is set, so it is destructive unconditionally.
    #[test]
    fn s3_sync_destructive_unconditional() {
        for args in [
            json!({ "delete": true }),
            json!({ "delete": false }),
            Value::Null,
        ] {
            assert!(is_destructive("kvendra.aws", "s3_sync", &args), "{args}");
        }
    }

    #[test]
    fn git_tag_destructive_only_with_force() {
        assert!(is_destructive(
            "kvendra.git",
            "tag",
            &json!({ "force": true })
        ));
        assert!(!is_destructive(
            "kvendra.git",
            "tag",
            &json!({ "force": false })
        ));
        assert!(!is_destructive("kvendra.git", "tag", &Value::Null));
    }

    #[test]
    fn http_method_mutates_matches_4_verbs() {
        for verb in ["POST", "PUT", "PATCH", "DELETE", "post", "Patch"] {
            assert!(
                is_destructive("kvendra.http", "request", &json!({ "method": verb })),
                "expected destructive for method={verb}"
            );
        }
        for safe in ["GET", "HEAD", "OPTIONS"] {
            assert!(
                !is_destructive("kvendra.http", "request", &json!({ "method": safe })),
                "expected NOT destructive for method={safe}"
            );
        }
    }

    #[test]
    fn issue_state_closed_matches() {
        assert!(is_annotated(
            "kvendra.github",
            "update_issue",
            &json!({ "state": "closed" })
        ));
        assert!(!is_annotated(
            "kvendra.github",
            "update_issue",
            &json!({ "state": "open" })
        ));
        assert!(!is_annotated(
            "kvendra.github",
            "update_issue",
            &Value::Null
        ));
    }

    #[test]
    fn lambda_invoke_destructive_unconditional() {
        assert!(is_destructive("kvendra.aws", "lambda_invoke", &Value::Null));
        assert!(is_destructive(
            "kvendra.aws",
            "lambda_invoke",
            &json!({ "anything": "goes" })
        ));
    }

    #[test]
    fn create_issue_destructive_unconditional() {
        assert!(is_destructive(
            "kvendra.github",
            "create_issue",
            &Value::Null
        ));
        assert!(is_destructive(
            "kvendra.github",
            "create_issue",
            &json!({ "title": "x", "body": "y" })
        ));
    }

    #[test]
    fn cloudfront_invalidate_annotated_not_destructive() {
        assert!(is_annotated(
            "kvendra.aws",
            "cloudfront_invalidate",
            &Value::Null
        ));
        assert!(!is_destructive(
            "kvendra.aws",
            "cloudfront_invalidate",
            &Value::Null
        ));
    }

    #[test]
    fn unknown_primitive_or_operation_is_destructive_not_annotated() {
        assert!(is_destructive("kvendra.unknown", "foo", &Value::Null));
        assert!(is_destructive("kvendra.aws", "unknown_op", &Value::Null));
        assert!(!is_annotated("kvendra.unknown", "foo", &Value::Null));
    }

    #[test]
    fn read_only_ops_are_not_destructive() {
        for (p, o) in READ_ONLY_OPS {
            assert!(!is_destructive(p, o, &Value::Null));
            assert!(!could_be_destructive(
                p,
                o,
                &OperationConstraints::default()
            ));
        }
    }

    #[test]
    fn constraints_to_args_value_extracts_mutating_method() {
        let c = OperationConstraints {
            methods: Some(vec!["GET".into(), "POST".into()]),
            ..Default::default()
        };
        let v = constraints_to_args_value(&c);
        assert_eq!(v.get("method").and_then(Value::as_str), Some("POST"));
    }

    #[test]
    fn constraints_to_args_value_omits_method_when_only_safe_verbs() {
        let c = OperationConstraints {
            methods: Some(vec!["GET".into(), "HEAD".into()]),
            ..Default::default()
        };
        let v = constraints_to_args_value(&c);
        assert!(v.get("method").is_none());
    }
}
