//! Cascade resolution + naming helpers for approval mode.
//!
//! Cascade priority (más específica gana):
//!   1. env var `KVENDRA_APPROVAL_MODE`
//!   2. profile YAML `approval.mode`
//!   3. global `~/.kvendra/config.toml` `[approval] mode`
//!   4. default `ask-destructive` (ADR-KVD-016 — silent es opt-in explícito)

use crate::allowlist::{Operation, ProfileSpec, catalog};
use crate::approval::{ApprovalMode, Transport};
use serde_json::Value;

/// Resuelve el modo activo siguiendo la cascade canónica.
pub fn resolve_mode(
    env_var: Option<ApprovalMode>,
    profile_override: Option<ApprovalMode>,
    global: ApprovalMode,
) -> ApprovalMode {
    env_var.or(profile_override).unwrap_or(global)
}

/// Decide if the active approval mode + transport requires `/dev/tty` for the
/// prompt. CLI commands (`Transport::Cli`) keep the historical semantics:
/// `silent` does not require TTY, `ask*` does. MCP transport never uses TTY
/// for approval — the prompt is delegated to the OS biometric / dialog popup
/// (REQ-KVD-006 / ISSUE-KVD-CLI-020) to mitigate PAT-KVD-007.
pub fn requires_tty(mode: ApprovalMode, transport: Transport) -> bool {
    match transport {
        Transport::Cli => matches!(mode, ApprovalMode::Ask | ApprovalMode::AskDestructive),
        Transport::Mcp => false,
    }
}

/// Determina si la combinación de modo + flag destructive dispara prompt.
pub fn should_prompt(mode: ApprovalMode, destructive: bool) -> bool {
    match mode {
        ApprovalMode::Silent => false,
        ApprovalMode::Ask => true,
        ApprovalMode::AskDestructive => destructive,
    }
}

/// Parsea un string a `ApprovalMode`. Acepta `silent`, `ask`, `ask-destructive`
/// y `ask_destructive` (alias snake_case por comodidad CLI/env).
pub fn parse_mode(s: &str) -> Option<ApprovalMode> {
    match s.trim().to_ascii_lowercase().as_str() {
        "silent" => Some(ApprovalMode::Silent),
        "ask" => Some(ApprovalMode::Ask),
        "ask-destructive" | "ask_destructive" => Some(ApprovalMode::AskDestructive),
        _ => None,
    }
}

/// Devuelve el nombre canónico (kebab-case) para mostrar en `config approval`.
pub fn mode_name(mode: ApprovalMode) -> &'static str {
    match mode {
        ApprovalMode::Silent => "silent",
        ApprovalMode::Ask => "ask",
        ApprovalMode::AskDestructive => "ask-destructive",
    }
}

/// Single source of truth para la flag `destructive` (REQ-KVD-004 / ADR-KVD-017):
/// consulta primero el catálogo canónico y, si no aplica, el field
/// `destructive: true` declarado por el user en el YAML.
pub fn lookup_destructive(
    spec: &ProfileSpec,
    primitive: &str,
    operation: &str,
    args: &Value,
) -> bool {
    if catalog::is_destructive(primitive, operation, args) {
        return true;
    }
    spec.allowlist
        .primitives
        .iter()
        .filter(|p| p.name == primitive)
        .flat_map(|p| p.operations.iter())
        .find_map(|op: &Operation| op.get(operation))
        .and_then(|c| c.destructive)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cascade_env_wins_over_profile_and_global() {
        assert_eq!(
            resolve_mode(
                Some(ApprovalMode::Silent),
                Some(ApprovalMode::Ask),
                ApprovalMode::AskDestructive
            ),
            ApprovalMode::Silent
        );
    }

    #[test]
    fn cascade_profile_wins_over_global_when_no_env() {
        assert_eq!(
            resolve_mode(None, Some(ApprovalMode::Silent), ApprovalMode::Ask),
            ApprovalMode::Silent
        );
    }

    #[test]
    fn cascade_global_when_no_env_no_profile() {
        assert_eq!(
            resolve_mode(None, None, ApprovalMode::Ask),
            ApprovalMode::Ask
        );
    }

    #[test]
    fn cascade_default_when_global_default() {
        assert_eq!(
            resolve_mode(None, None, ApprovalMode::default()),
            ApprovalMode::AskDestructive
        );
    }

    #[test]
    fn requires_tty_cli_only_for_ask_modes() {
        assert!(!requires_tty(ApprovalMode::Silent, Transport::Cli));
        assert!(requires_tty(ApprovalMode::Ask, Transport::Cli));
        assert!(requires_tty(ApprovalMode::AskDestructive, Transport::Cli));
    }

    #[test]
    fn requires_tty_mcp_never() {
        assert!(!requires_tty(ApprovalMode::Silent, Transport::Mcp));
        assert!(!requires_tty(ApprovalMode::Ask, Transport::Mcp));
        assert!(!requires_tty(ApprovalMode::AskDestructive, Transport::Mcp));
    }

    #[test]
    fn should_prompt_matrix() {
        assert!(!should_prompt(ApprovalMode::Silent, true));
        assert!(!should_prompt(ApprovalMode::Silent, false));
        assert!(should_prompt(ApprovalMode::Ask, true));
        assert!(should_prompt(ApprovalMode::Ask, false));
        assert!(should_prompt(ApprovalMode::AskDestructive, true));
        assert!(!should_prompt(ApprovalMode::AskDestructive, false));
    }

    #[test]
    fn parse_mode_accepts_both_snake_and_kebab_destructive() {
        assert_eq!(parse_mode("silent"), Some(ApprovalMode::Silent));
        assert_eq!(parse_mode("ask"), Some(ApprovalMode::Ask));
        assert_eq!(
            parse_mode("ask-destructive"),
            Some(ApprovalMode::AskDestructive)
        );
        assert_eq!(
            parse_mode("ask_destructive"),
            Some(ApprovalMode::AskDestructive)
        );
        assert_eq!(parse_mode("  Silent  "), Some(ApprovalMode::Silent));
        assert_eq!(parse_mode("nope"), None);
    }

    #[test]
    fn lookup_destructive_consults_catalog_when_args_match() {
        let yaml = r#"
profile_id: t
secret:
  type: aws
allowlist:
  primitives:
    - name: kvendra.aws
      operations:
        - s3_sync:
            buckets: ["b"]
            accept_destructive: true
"#;
        let spec: ProfileSpec = serde_yml::from_str(yaml).unwrap();
        // Catalog: s3_sync con delete=true → Destructive (sin necesidad de
        // user-declared field).
        let args_with_delete = serde_json::json!({ "delete": true });
        assert!(lookup_destructive(
            &spec,
            "kvendra.aws",
            "s3_sync",
            &args_with_delete
        ));
        // Sin delete=true: catálogo NO marca destructive y el YAML tampoco
        // declara destructive: true → false.
        let args_no_delete = serde_json::json!({});
        assert!(!lookup_destructive(
            &spec,
            "kvendra.aws",
            "s3_sync",
            &args_no_delete
        ));
    }

    #[test]
    fn lookup_destructive_reads_user_declared_when_catalog_no_match() {
        let yaml = r#"
profile_id: t
secret:
  type: token
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - read_issue:
            repos: ["owner/repo"]
            destructive: true
"#;
        let spec: ProfileSpec = serde_yml::from_str(yaml).unwrap();
        // read_issue NO está en el catálogo, pero el user declaró destructive: true.
        assert!(lookup_destructive(
            &spec,
            "kvendra.github",
            "read_issue",
            &serde_json::Value::Null
        ));
        // Operation distinta: no marcada en catálogo ni declarada → false.
        assert!(!lookup_destructive(
            &spec,
            "kvendra.github",
            "read_repo",
            &serde_json::Value::Null
        ));
        assert!(!lookup_destructive(
            &spec,
            "kvendra.unknown",
            "x",
            &serde_json::Value::Null
        ));
    }

    #[test]
    fn lookup_destructive_lambda_invoke_unconditional() {
        let yaml = r#"
profile_id: t
secret:
  type: aws
allowlist:
  primitives:
    - name: kvendra.aws
      operations:
        - lambda_invoke:
            functions: ["fn"]
            accept_destructive: true
"#;
        let spec: ProfileSpec = serde_yml::from_str(yaml).unwrap();
        // lambda_invoke siempre destructive según catálogo, aunque args sea null.
        assert!(lookup_destructive(
            &spec,
            "kvendra.aws",
            "lambda_invoke",
            &serde_json::Value::Null
        ));
    }
}
