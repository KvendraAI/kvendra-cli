//! Wire types v1 — canonical Rust mirror of `openapi.yaml` v1.0.0 published in
//! `KvendraAI/kvendra-enterprise/packages/protocol-spec/`. Hand-written for
//! M1 Sprint 4 (REQ-KVD-CLI-004 / IF-KVD-ENTERPRISE-002). Codegen pass via
//! `scripts/codegen.sh` (progenitor) is deferred — keeping the surface tight
//! and hand-curated lets us evolve in lockstep with the backend while only
//! consuming the endpoints we actually need.
//!
//! All fields stay aligned with the wire JSON keys (`#[serde(rename)]` where
//! needed). Backwards-compatible tolerance: every optional field uses
//! `#[serde(default)]` so a v1.2.0 → v1.1.0 broker response still
//! deserializes when the new field is absent.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────
// tokens:issue (POST /v1/profiles/{profile_id}/tokens:issue)
// ─────────────────────────────────────────────────────────────────────────

/// Body sent to the broker on each `tools/call` that needs an ephemeral
/// credential. See IF-KVD-ENTERPRISE-002 §3.2 "tokens:issue".
#[derive(Debug, Clone, Serialize)]
pub struct IssueTokenRequest {
    pub primitive: String,
    pub op: String,
    pub args_hash: String,
    /// RFC3339 timestamp at which the CLI dispatched the call.
    pub requested_at: String,
}

/// Successful 200 response from `tokens:issue`. The ephemeral token has a
/// short TTL (≤15min per ADR-KVD-ENTERPRISE-001) and the `audit_id`
/// correlates with the central audit entity (`AUDIT` in the broker DynamoDB).
#[derive(Debug, Clone, Deserialize)]
pub struct IssueTokenResponse {
    pub token: String,
    /// RFC3339 timestamp of token expiry (UTC).
    pub expires_at: String,
    /// ULID — populated only by the remote broker. Local resolver leaves it
    /// `None` by construction (see [`crate::secret_resolver::EphemeralSecret`]).
    pub audit_id: String,
    pub scope: ScopeMetaWire,
}

/// Wire shape of the scope envelope returned alongside an ephemeral token.
/// Opaque `constraints` deliberately mirrors the broker's freeform JSON.
#[derive(Debug, Clone, Deserialize)]
pub struct ScopeMetaWire {
    pub primitive: String,
    pub op: String,
    #[serde(default)]
    pub constraints: serde_json::Value,
}

// ─────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ErrorBody {
    #[serde(rename = "type")]
    pub error_type: String,
    pub message: String,
    #[serde(default)]
    pub retry_after_seconds: Option<u64>,
}

// ─────────────────────────────────────────────────────────────────────────
// Workspaces (GET /v1/workspaces, /v1/workspaces/{id})
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct Workspace {
    pub workspace_id: String,
    pub tenant_id: String,
    pub name: String,
    pub plan: String,
    #[serde(default)]
    pub trial_expires_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkspaceListResponse {
    pub items: Vec<Workspace>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────
// Members (GET /v1/workspaces/{id}/members)
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct Member {
    pub member_id: String,
    pub email: String,
    pub role: String,
    pub joined_at: String,
    #[serde(default)]
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MemberListResponse {
    pub items: Vec<Member>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────
// Templates (GET /v1/workspaces/{id}/templates) — allowlist policy YAMLs
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct Template {
    pub template_id: String,
    pub yaml_blob: String,
    pub version: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TemplateListResponse {
    pub items: Vec<Template>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────
// Profiles (GET /v1/workspaces/{id}/profiles, POST .../profiles)
// ─────────────────────────────────────────────────────────────────────────

/// Redacted view of a workspace profile. The broker NEVER returns plaintext
/// material in list endpoints; only `tokens:issue` yields a token.
#[derive(Debug, Clone, Deserialize)]
pub struct ProfileRedacted {
    pub profile_id: String,
    pub secret_type: String,
    pub template_id: String,
    pub created_at: String,
    #[serde(default)]
    pub expiration_at: Option<String>,
    pub created_by: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProfileListResponse {
    pub items: Vec<ProfileRedacted>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// Body sent when an admin/owner adds a new workspace secret. The plaintext
/// is opaque to the broker layer — it is sealed with the workspace KMS key
/// before persistence (per IF-KVD-ENTERPRISE-002 §4 "Custodia centralizada").
#[derive(Debug, Clone, Serialize)]
pub struct CreateProfileRequest {
    pub profile_id: String,
    pub secret_type: String,
    pub template_id: String,
    /// Plaintext secret material — only leaves the laptop encrypted in TLS.
    pub plaintext_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_at: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────
// /v1/me
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct MeResponse {
    pub member_id: String,
    pub email: String,
    /// IF-002 v1.2.0 addition (optional in v1.1.0). When absent, the CLI
    /// falls back to `GET /v1/workspaces`.
    #[serde(default)]
    pub active_workspaces: Vec<String>,
    #[serde(default)]
    pub default_workspace_id: Option<String>,
}
