//! Cascade resolution + naming helpers for approval mode.
//!
//! Cascade priority (más específica gana):
//!   1. env var `KVENDRA_APPROVAL_MODE`
//!   2. profile YAML `approval.mode`
//!   3. global `~/.kvendra/config.toml` `[approval] mode`
//!   4. default `ask-destructive` (ADR-KVD-016 — silent es opt-in explícito)

use crate::allowlist::{Operation, ProfileSpec};
use crate::approval::ApprovalMode;

/// Resuelve el modo activo siguiendo la cascade canónica.
pub fn resolve_mode(
    env_var: Option<ApprovalMode>,
    profile_override: Option<ApprovalMode>,
    global: ApprovalMode,
) -> ApprovalMode {
    env_var.or(profile_override).unwrap_or(global)
}

/// `silent` no exige TTY (CI/automation). `ask*` sí.
pub fn requires_tty(mode: ApprovalMode) -> bool {
    matches!(mode, ApprovalMode::Ask | ApprovalMode::AskDestructive)
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

/// Recorre la allowlist del profile y retorna la flag `destructive` declarada
/// para `(primitive, operation)`. Si no aparece, `false` por defecto.
///
/// Sister ISSUE-KVD-CLI-012 introducirá un catalog canónico que poblará el
/// fallback (e.g. `kvendra.shell.exec`, `kvendra.aws.s3_sync` con `delete:true`,
/// etc.). Hasta entonces el field YAML es la única fuente.
pub fn lookup_destructive(spec: &ProfileSpec, primitive: &str, operation: &str) -> bool {
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
    fn requires_tty_only_for_ask_modes() {
        assert!(!requires_tty(ApprovalMode::Silent));
        assert!(requires_tty(ApprovalMode::Ask));
        assert!(requires_tty(ApprovalMode::AskDestructive));
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
    fn lookup_destructive_reads_field_or_defaults_false() {
        let yaml = r#"
profile_id: t
secret:
  type: token
allowlist:
  primitives:
    - name: kvendra.aws
      operations:
        - s3_sync:
            buckets: ["b"]
            destructive: true
        - s3_cp:
            buckets: ["b"]
"#;
        let spec: ProfileSpec = serde_yml::from_str(yaml).unwrap();
        assert!(lookup_destructive(&spec, "kvendra.aws", "s3_sync"));
        assert!(!lookup_destructive(&spec, "kvendra.aws", "s3_cp"));
        assert!(!lookup_destructive(&spec, "kvendra.aws", "missing_op"));
        assert!(!lookup_destructive(&spec, "kvendra.unknown", "s3_sync"));
    }
}
