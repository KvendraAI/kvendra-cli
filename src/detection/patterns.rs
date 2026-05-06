//! Detection regex patterns — Pase B placeholder.
//!
//! Pre-loaded list, not yet compiled. Pase B compiles to `regex::RegexSet`
//! and runs on inbound/outbound MCP traffic.

pub const PROVIDER_PATTERNS: &[(&str, &str)] = &[
    ("github_pat_classic", r"ghp_[A-Za-z0-9]{36,}"),
    ("github_pat_fine", r"github_pat_[A-Za-z0-9_]{36,}"),
    ("npm_token", r"npm_[A-Za-z0-9]{36,}"),
    ("pypi_token", r"pypi-AgEI[A-Za-z0-9_\-]+"),
    ("hf_token", r"hf_[A-Za-z0-9]{34,}"),
    ("aws_akid", r"AKIA[0-9A-Z]{16}"),
    ("anthropic_key", r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    ("openai_key", r"sk-[A-Za-z0-9]{48,}"),
];
