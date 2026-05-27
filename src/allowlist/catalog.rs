//! Destructive operations catalog (REQ-KVD-004 / ROAD-KVD-007 ISSUE-012).
//!
//! Const Rust array (ADR-KVD-017): single source of truth para
//! [`crate::allowlist::validator::validate`] y
//! [`crate::approval::policy::lookup_destructive`].
//!
//! Cada entrada en [`CATALOG`] declara una operación que requiere `opt-in`
//! explícito (`accept_destructive: true` en allowlist YAML) o que merece
//! una marca informativa (`Annotated`) en `kvendra secret validate`.

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

fn s3_sync_with_delete(args: &Value) -> bool {
    args.get("delete").and_then(Value::as_bool).unwrap_or(false)
}

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

// --- catálogo (15 entradas — owner ratificado 2026-05-07, extended 2026-05-27 with create_issue) ---

pub const CATALOG: &[DestructiveRule] = &[
    DestructiveRule {
        primitive: "kvendra.git",
        operation: "push",
        kind: DestructiveKind::Destructive,
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
    DestructiveRule {
        primitive: "kvendra.aws",
        operation: "s3_sync",
        kind: DestructiveKind::Destructive,
        args_predicate: Some(s3_sync_with_delete),
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

/// `true` si `(primitive, operation, args)` está marcada `Destructive` en el catálogo.
pub fn is_destructive(primitive: &str, operation: &str, args: &Value) -> bool {
    matches_kind(DestructiveKind::Destructive, primitive, operation, args)
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
/// - Si la regla tiene predicate runtime-only (ej. `s3_sync.delete`,
///   `git.tag.force`) → worst-case true (fuerza opt-in en validate-time).
pub fn could_be_destructive(primitive: &str, operation: &str, c: &OperationConstraints) -> bool {
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

    #[test]
    fn catalog_size_is_15() {
        assert_eq!(CATALOG.len(), 15);
    }

    #[test]
    fn s3_sync_destructive_only_with_delete() {
        assert!(is_destructive(
            "kvendra.aws",
            "s3_sync",
            &json!({ "delete": true })
        ));
        assert!(!is_destructive(
            "kvendra.aws",
            "s3_sync",
            &json!({ "delete": false })
        ));
        assert!(!is_destructive("kvendra.aws", "s3_sync", &Value::Null));
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
    fn unknown_primitive_or_operation_returns_false() {
        assert!(!is_destructive("kvendra.unknown", "foo", &Value::Null));
        assert!(!is_destructive("kvendra.aws", "unknown_op", &Value::Null));
        assert!(!is_annotated("kvendra.unknown", "foo", &Value::Null));
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
