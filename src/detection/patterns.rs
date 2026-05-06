//! Detection regex patterns — REQ-KVD-002 Bloque 7 / AC-DET-1, AC-DET-2.
//!
//! Patterns for 7 secret providers + AWS env-var assignment form. Compiled
//! lazily into a `regex::RegexSet` (see [`crate::detection::pattern_set`]).

/// Provider id → regex source. Patterns are written conservatively; the
/// entropy filter then drops obvious lorem-ipsum false positives.
pub const PROVIDER_PATTERNS: &[(&str, &str)] = &[
    // GitHub PATs and OAuth tokens. ghp_/gho_/ghs_/ghu_ prefix is standard.
    ("github_pat_classic", r"ghp_[A-Za-z0-9]{36}"),
    ("github_oauth", r"gho_[A-Za-z0-9]{36}"),
    ("github_app_server", r"ghs_[A-Za-z0-9]{36}"),
    ("github_user_to_server", r"ghu_[A-Za-z0-9]{36}"),
    ("github_pat_fine", r"github_pat_[A-Za-z0-9_]{82}"),
    // npm bearer tokens (registry).
    ("npm_token", r"npm_[A-Za-z0-9]{36}"),
    // PyPI API tokens.
    ("pypi_token", r"pypi-AgEI[A-Za-z0-9_\-]{30,}"),
    // Hugging Face.
    ("hf_token", r"hf_[A-Za-z0-9]{34}"),
    // AWS access key id (always prefixed AKIA, 16 alnum).
    ("aws_akid", r"AKIA[0-9A-Z]{16}"),
    // AWS secret access key — env-var assignment form (avoid generic 40-char regex).
    (
        "aws_secret_env",
        r"(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}",
    ),
    // Anthropic.
    ("anthropic_key", r"sk-ant-[A-Za-z0-9_\-]{60,}"),
    // OpenAI sk-… (≥48 chars after prefix).
    ("openai_key", r"sk-[A-Za-z0-9]{48,}"),
];
