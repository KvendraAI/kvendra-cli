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
    // Slack bot/user/app/refresh tokens (xoxb-/xoxp-/xoxa-/xoxr-/xoxs-).
    ("slack_token", r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    // Stripe live secret / restricted keys (test keys sk_test_ intentionally
    // NOT matched — those are non-sensitive by Stripe's own guidance).
    ("stripe_secret_key", r"(?:sk|rk)_live_[0-9A-Za-z]{24,}"),
    // Google API key (Maps, Cloud, …).
    ("google_api_key", r"AIza[0-9A-Za-z_\-]{35}"),
    // GitLab personal access token.
    ("gitlab_pat", r"glpat-[0-9A-Za-z_\-]{20,}"),
    // Google OAuth 2.0 access token (`ya29.`).
    ("google_oauth_token", r"ya29\.[0-9A-Za-z_\-]{20,}"),
    // JSON Web Token — three base64url segments, header begins `eyJ` (base64 of
    // `{"`). Session/id tokens (e.g. the Cognito Pro token) take this shape.
    (
        "jwt",
        r"eyJ[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]{8,}",
    ),
    // PEM private key block (SSH / TLS / PGP). Match the WHOLE block, not just
    // the header: the header line alone is barely above the entropy threshold,
    // so redacting only it would leave the high-entropy key body visible. `(?s)`
    // lets `.` cross newlines; the match spans BEGIN…END so the entire key is
    // replaced.
    // Match BEGIN … up to the END marker, OR to end-of-text if the END was
    // truncated (a tool that cut its own output must not leak the key body
    // just because the footer is missing). `\z` = end of text.
    (
        "private_key_pem",
        r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)",
    ),
];

/// Providers that are REDACTED in output but do NOT block/quarantine on inbound
/// `tools/call` args. A JWT or Google OAuth token is commonly a LEGITIMATE
/// argument (e.g. an `Authorization: Bearer` value the agent must send), so
/// treating it as an inbound-smuggling signal in `severity = block` mode would
/// deny legitimate calls. They still must never be echoed back, so output
/// redaction keeps them.
pub const REDACT_ONLY_PROVIDERS: &[&str] = &["jwt", "google_oauth_token"];

/// Providers that must be redacted regardless of the entropy filter — their
/// framing (a PEM `BEGIN … PRIVATE KEY` block) is a strong enough signal on its
/// own, and a contrived low-entropy body must not slip a real key past.
pub const ALWAYS_REDACT_PROVIDERS: &[&str] = &["private_key_pem"];
