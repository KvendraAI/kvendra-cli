//! Cascade resolution + naming helpers for approval mode.
//!
//! Signed cascade (más específica gana):
//!   1. profile YAML `approval.mode` (HMAC-signed allowlist)
//!   2. global `~/.kvendra/config.toml` `[approval] mode` (HMAC-signed)
//!   3. default `ask-destructive` (ADR-KVD-016 — silent es opt-in explícito)
//!
//! The unsigned env var `KVENDRA_APPROVAL_MODE` is a ONE-WAY RATCHET on top of
//! the signed mode (ISSUE-KVD-CLI-705EF0): it may only TIGHTEN it
//! (`Silent < AskDestructive < Ask`). A looser env value is ignored — and the
//! divergence is audit-flagged — unless the signed config sets
//! `[approval] allow_env_downgrade = true`.

use crate::allowlist::{Operation, ProfileSpec, catalog};
use crate::approval::{ApprovalMode, Transport};
use serde_json::Value;

/// Audit flag: a looser `KVENDRA_APPROVAL_MODE` was present and IGNORED.
pub const FLAG_APPROVAL_ENV_IGNORED: &str = "approval_env_ignored";
/// Audit flag: a looser `KVENDRA_APPROVAL_MODE` was APPLIED because the signed
/// config opted in (`allow_env_downgrade = true`).
pub const FLAG_APPROVAL_MODE_OVERRIDDEN: &str = "approval_mode_overridden";
/// Audit flag: a stricter `KVENDRA_APPROVAL_MODE` tightened the signed mode.
pub const FLAG_APPROVAL_ENV_TIGHTENED: &str = "approval_env_tightened";
pub const FLAG_APPROVAL_MODE_SILENT: &str = "approval_mode_silent";
pub const FLAG_APPROVAL_MODE_ASK: &str = "approval_mode_ask";
pub const FLAG_APPROVAL_MODE_ASK_DESTRUCTIVE: &str = "approval_mode_ask_destructive";
pub const FLAG_APPROVAL_SRC_ENV: &str = "approval_src_env";
pub const FLAG_APPROVAL_SRC_PROFILE: &str = "approval_src_profile";
pub const FLAG_APPROVAL_SRC_SIGNED: &str = "approval_src_signed";

/// Where the effective approval mode came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalSource {
    /// The unsigned `KVENDRA_APPROVAL_MODE` env var.
    Env,
    /// The signed per-profile allowlist YAML `approval.mode`.
    Profile,
    /// The signed global `config.toml` `[approval] mode` (or its default).
    Signed,
}

/// How the env var interacted with the signed mode, when it diverged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvOverride {
    /// Looser env value, not opted in → ignored; the signed mode stays.
    DowngradeIgnored,
    /// Looser env value, opted in by the signed config → applied.
    DowngradeApplied,
    /// Stricter env value → applied (the ratchet only blocks downgrades).
    Tightened,
}

/// Effective approval mode + its provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalOutcome {
    pub mode: ApprovalMode,
    pub source: ApprovalSource,
    pub env_override: Option<EnvOverride>,
}

impl ApprovalOutcome {
    /// Canonical audit flags for this outcome: the effective mode, its source
    /// and, when the env var diverged from the signed mode, how.
    pub fn audit_flags(&self) -> Vec<&'static str> {
        let mut flags = Vec::with_capacity(3);
        if let Some(o) = self.env_override {
            flags.push(match o {
                EnvOverride::DowngradeIgnored => FLAG_APPROVAL_ENV_IGNORED,
                EnvOverride::DowngradeApplied => FLAG_APPROVAL_MODE_OVERRIDDEN,
                EnvOverride::Tightened => FLAG_APPROVAL_ENV_TIGHTENED,
            });
        }
        flags.push(match self.mode {
            ApprovalMode::Silent => FLAG_APPROVAL_MODE_SILENT,
            ApprovalMode::Ask => FLAG_APPROVAL_MODE_ASK,
            ApprovalMode::AskDestructive => FLAG_APPROVAL_MODE_ASK_DESTRUCTIVE,
        });
        flags.push(match self.source {
            ApprovalSource::Env => FLAG_APPROVAL_SRC_ENV,
            ApprovalSource::Profile => FLAG_APPROVAL_SRC_PROFILE,
            ApprovalSource::Signed => FLAG_APPROVAL_SRC_SIGNED,
        });
        flags
    }
}

/// Strictness rank: `Silent(0) < AskDestructive(1) < Ask(2)` — the order
/// `should_prompt` implements.
pub fn strictness(mode: ApprovalMode) -> u8 {
    match mode {
        ApprovalMode::Silent => 0,
        ApprovalMode::AskDestructive => 1,
        ApprovalMode::Ask => 2,
    }
}

/// Resolve the effective mode. The signed baseline is
/// `profile_override.unwrap_or(global)`; the unsigned `env_var` may only
/// tighten it, unless `allow_env_downgrade` (read from the SIGNED config)
/// opts in to letting it loosen it too.
pub fn resolve_mode_ratcheted(
    env_var: Option<ApprovalMode>,
    profile_override: Option<ApprovalMode>,
    global: ApprovalMode,
    allow_env_downgrade: bool,
) -> ApprovalOutcome {
    let signed = match profile_override {
        Some(mode) => ApprovalOutcome {
            mode,
            source: ApprovalSource::Profile,
            env_override: None,
        },
        None => ApprovalOutcome {
            mode: global,
            source: ApprovalSource::Signed,
            env_override: None,
        },
    };
    let Some(env) = env_var else {
        return signed;
    };
    match strictness(env).cmp(&strictness(signed.mode)) {
        std::cmp::Ordering::Greater => ApprovalOutcome {
            mode: env,
            source: ApprovalSource::Env,
            env_override: Some(EnvOverride::Tightened),
        },
        std::cmp::Ordering::Equal => signed,
        std::cmp::Ordering::Less if allow_env_downgrade => ApprovalOutcome {
            mode: env,
            source: ApprovalSource::Env,
            env_override: Some(EnvOverride::DowngradeApplied),
        },
        std::cmp::Ordering::Less => ApprovalOutcome {
            env_override: Some(EnvOverride::DowngradeIgnored),
            ..signed
        },
    }
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

    fn resolve(
        env: Option<ApprovalMode>,
        profile: Option<ApprovalMode>,
        global: ApprovalMode,
        optin: bool,
    ) -> (ApprovalMode, ApprovalSource, Option<EnvOverride>) {
        let o = resolve_mode_ratcheted(env, profile, global, optin);
        (o.mode, o.source, o.env_override)
    }

    /// ISSUE-KVD-CLI-705EF0 — the pre-fix test asserted the bug (env Silent
    /// won over a signed profile `Ask`). A looser env value is now ignored.
    #[test]
    fn cascade_env_does_not_weaken_profile_or_global() {
        assert_eq!(
            resolve(
                Some(ApprovalMode::Silent),
                Some(ApprovalMode::Ask),
                ApprovalMode::AskDestructive,
                false
            ),
            (
                ApprovalMode::Ask,
                ApprovalSource::Profile,
                Some(EnvOverride::DowngradeIgnored)
            )
        );
    }

    #[test]
    fn env_downgrade_of_global_is_ignored_and_flagged() {
        let o = resolve_mode_ratcheted(
            Some(ApprovalMode::Silent),
            None,
            ApprovalMode::AskDestructive,
            false,
        );
        assert_eq!(
            (o.mode, o.source, o.env_override),
            (
                ApprovalMode::AskDestructive,
                ApprovalSource::Signed,
                Some(EnvOverride::DowngradeIgnored)
            )
        );
        let flags = o.audit_flags();
        for f in [
            FLAG_APPROVAL_ENV_IGNORED,
            FLAG_APPROVAL_MODE_ASK_DESTRUCTIVE,
            FLAG_APPROVAL_SRC_SIGNED,
        ] {
            assert!(flags.contains(&f), "missing {f} in {flags:?}");
        }
    }

    #[test]
    fn env_downgrade_applied_only_with_signed_opt_in() {
        let o = resolve_mode_ratcheted(
            Some(ApprovalMode::Silent),
            None,
            ApprovalMode::AskDestructive,
            true,
        );
        assert_eq!(
            (o.mode, o.source, o.env_override),
            (
                ApprovalMode::Silent,
                ApprovalSource::Env,
                Some(EnvOverride::DowngradeApplied)
            )
        );
        assert!(o.audit_flags().contains(&FLAG_APPROVAL_MODE_OVERRIDDEN));
    }

    #[test]
    fn env_may_tighten_regardless_of_opt_in() {
        for optin in [false, true] {
            assert_eq!(
                resolve(
                    Some(ApprovalMode::Ask),
                    None,
                    ApprovalMode::AskDestructive,
                    optin
                ),
                (
                    ApprovalMode::Ask,
                    ApprovalSource::Env,
                    Some(EnvOverride::Tightened)
                )
            );
        }
    }

    #[test]
    fn env_equal_to_signed_is_not_an_override() {
        let o = resolve_mode_ratcheted(
            Some(ApprovalMode::AskDestructive),
            None,
            ApprovalMode::AskDestructive,
            false,
        );
        assert_eq!(o.source, ApprovalSource::Signed);
        assert_eq!(o.env_override, None);
    }

    #[test]
    fn cascade_profile_wins_over_global_when_no_env() {
        assert_eq!(
            resolve(None, Some(ApprovalMode::Silent), ApprovalMode::Ask, false),
            (ApprovalMode::Silent, ApprovalSource::Profile, None)
        );
    }

    #[test]
    fn cascade_global_when_no_env_no_profile() {
        assert_eq!(
            resolve(None, None, ApprovalMode::Ask, false),
            (ApprovalMode::Ask, ApprovalSource::Signed, None)
        );
    }

    #[test]
    fn cascade_default_when_global_default() {
        assert_eq!(
            resolve(None, None, ApprovalMode::default(), false).0,
            ApprovalMode::AskDestructive
        );
    }

    #[test]
    fn strictness_agrees_with_should_prompt() {
        let modes = [
            ApprovalMode::Silent,
            ApprovalMode::AskDestructive,
            ApprovalMode::Ask,
        ];
        for a in modes {
            for b in modes {
                if strictness(a) <= strictness(b) {
                    for d in [false, true] {
                        assert!(!should_prompt(a, d) || should_prompt(b, d));
                    }
                }
            }
        }
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
    - name: kvendra.git
      operations:
        - tag:
            repos: ["github.com/o/*"]
            accept_destructive: true
"#;
        let spec: ProfileSpec = serde_yaml_ng::from_str(yaml).unwrap();
        // Re-authored on `git.tag` + `force` (ISSUE-KVD-CLI-9D5CF5 made
        // `s3_sync` destructive unconditionally, so it has no predicate left).
        // Catalog: tag con force=true → Destructive (sin necesidad de
        // user-declared field).
        let args_with_force = serde_json::json!({ "force": true });
        assert!(lookup_destructive(
            &spec,
            "kvendra.git",
            "tag",
            &args_with_force
        ));
        // Sin force=true: catálogo NO marca destructive y el YAML tampoco
        // declara destructive: true → false.
        let args_no_force = serde_json::json!({});
        assert!(!lookup_destructive(
            &spec,
            "kvendra.git",
            "tag",
            &args_no_force
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
        let spec: ProfileSpec = serde_yaml_ng::from_str(yaml).unwrap();
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
        // ISSUE-KVD-CLI-9B3395 — an unclassified primitive/op fails CLOSED.
        assert!(lookup_destructive(
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
        let spec: ProfileSpec = serde_yaml_ng::from_str(yaml).unwrap();
        // lambda_invoke siempre destructive según catálogo, aunque args sea null.
        assert!(lookup_destructive(
            &spec,
            "kvendra.aws",
            "lambda_invoke",
            &serde_json::Value::Null
        ));
    }
}
