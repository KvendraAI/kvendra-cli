//! Parser de filtros para `kvendra audit export --filter <expr>`.
//!
//! Sintaxis mínima soportada:
//!   `profile_id=<value>`, `primitive=<value>`, `op=<value>`,
//!   `result_status=<value>`, `args_contains=<value>`.
//! Separados por `,`. Caso de uso AC-EXPORT-1.

use std::collections::HashMap;

/// Parsed filter expression. Empty map = no filter.
#[derive(Debug, Default, Clone)]
pub struct ExportFilter {
    pub fields: HashMap<String, String>,
}

impl ExportFilter {
    pub fn parse(expr: &str) -> Self {
        let mut fields = HashMap::new();
        for kv in expr.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if let Some((k, v)) = kv.split_once('=') {
                fields.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
        Self { fields }
    }

    pub fn matches(&self, ev: &crate::audit::reader::StoredEvent) -> bool {
        for (k, v) in &self.fields {
            let hit = match k.as_str() {
                "profile_id" => ev.profile_id == *v,
                "primitive" => ev.primitive == *v,
                "op" | "action" => ev.action == *v,
                "result_status" | "status" => ev.status == *v,
                _ => true, // unknown keys → no-op (forward-compat)
            };
            if !hit {
                return false;
            }
        }
        true
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_filter() {
        let f = ExportFilter::parse("profile_id=alice,primitive=kvendra.git");
        assert_eq!(f.fields.get("profile_id"), Some(&"alice".to_string()));
        assert_eq!(f.fields.get("primitive"), Some(&"kvendra.git".to_string()));
    }

    #[test]
    fn empty_expr_yields_empty_filter() {
        let f = ExportFilter::parse("");
        assert!(f.is_empty());
    }
}
