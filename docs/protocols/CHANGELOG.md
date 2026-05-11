# Wire Protocol Changelog

Versioning policy: path-versioned (`/v1/...`).

- **MAJOR** — breaking change (field removed, semantics changed, endpoint removed). A new path version is introduced; the prior version stays live for at least 6 months with `Deprecation` headers on every response.
- **MINOR** — backwards-compatible addition (new endpoint, new optional field, new error type).
- **PATCH** — documentation clarification with no wire impact.

## Unreleased

_Nothing yet._

## v1.0.0 — 2026-05-11

Initial M1-ready release.

### Foundation
- `GET /v1/healthz`
- `GET /v1/me`

### Workspaces, members, profiles, templates
- `GET POST /v1/workspaces`
- `GET /v1/workspaces/{workspace_id}`
- `GET POST /v1/workspaces/{workspace_id}/members`
- `DELETE /v1/workspaces/{workspace_id}/members/{member_id}`
- `GET POST /v1/workspaces/{workspace_id}/profiles`
- `PUT DELETE /v1/workspaces/{workspace_id}/profiles/{profile_id}`
- `GET POST /v1/workspaces/{workspace_id}/templates`

### Token-vending core
- `POST /v1/profiles/{profile_id}/tokens:issue`

### Audit & overview
- `GET /v1/workspaces/{workspace_id}/audit`
- `GET /v1/workspaces/{workspace_id}/overview`

### Authentication
- OIDC discovery at `https://auth.kvendra.cloud/.well-known/openid-configuration`.
- RS256 JWTs, custom claims under the `kvendra:` namespace.

### Notes
- Plan flag (`trial | team | enterprise`) is hardcoded on the workspace at creation time. Stripe billing integration is intentionally deferred — see `ADR-KVD-ENTERPRISE-008`.
- The OpenAPI 3.1 source of truth is the closed-source server file `packages/protocol-spec/openapi.yaml`. This markdown is the published public surface.
