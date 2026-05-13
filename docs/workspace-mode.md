# Kvendra CLI — workspace mode (Team / Enterprise)

Workspace mode lets a Kvendra-CLI install consume secrets from a remote
broker instead of (or in addition to) the local zero-knowledge vault. It
unlocks the Team / Enterprise tiers without changing the eight existing
primitives: `kvendra.git`, `kvendra.github`, `kvendra.npm`, `kvendra.pypi`,
`kvendra.aws`, `kvendra.http`, `kvendra.shell`, and the
`kvendra.unsafe.raw_token` escape hatch.

Available from `kvendra` `0.3.0-alpha.1`.

---

## Mental model

| Concept | Local (Free) | Workspace (Team / Enterprise) |
|---|---|---|
| Where the secret lives | `~/.kvendra/secrets/<profile>.blob` | broker-side, sealed with workspace KMS key |
| Resolver | `LocalVaultResolver` (decrypts blob) | `RemoteBrokerResolver` (`POST /v1/profiles/{id}/tokens:issue`) |
| TTL of the resolved token | effectively non-expiring | 5–15 min (per `ADR-KVD-ENTERPRISE-001`) |
| Audit correlation | local-only | local row carries `remote_audit_id` (ULID) → central audit |
| `secret add` / `rotate` | full access | admin/owner only (server RBAC) |
| Allowlist YAMLs | `~/.kvendra/allowlists/` (editable) | `~/.kvendra/cache/allowlists/<ws>/` (read-only, broker-synced) |

The CLI selects the resolver automatically at `mcp serve` startup. With
zero `~/.kvendra/sessions/*.token` files present it stays in local mode;
with exactly one session token it switches to workspace mode for that
workspace. Two or more session tokens require
`KVENDRA_ACTIVE_WORKSPACE=<id>` to disambiguate.

---

## Logging into a workspace

```bash
# Default IdP and broker live at *.kvendra.cloud. Self-hosters override:
#   KVENDRA_AUTH_URL=https://idp.example.com
#   KVENDRA_BROKER_URL=https://broker.example.com
#   KVENDRA_CLIENT_ID=<oidc-public-client-id>

kvendra login --workspace acme-corp/frontend
```

The CLI:

1. Discovers the OIDC endpoints at `KVENDRA_AUTH_URL/.well-known/openid-configuration`.
2. Binds the first free loopback port in the range `54321..=54330` (10 ports).
   The IdP application is preconfigured with all 20 URLs
   (`http://127.0.0.1:<port>/callback` + `http://localhost:<port>/callback`)
   so the exact bound port matches the `redirect_uri`.
3. Opens the system browser for the Authorization Code + PKCE flow.
   If `webbrowser::open` fails (headless / containerized shells), the
   `authorize` URL is also printed to stderr so you can copy-paste it.
4. Receives the `code` + `state` on the loopback callback (constant-time
   CSRF check), exchanges them for a JWT + refresh_token.
5. Persists `~/.kvendra/sessions/<ws-slug>.token` (file mode `0600`).
6. Runs an initial allowlist sync so the next `mcp serve` starts hot.

The slug `<ws-slug>` translates `acme-corp/frontend` to
`acme-corp__frontend` so the workspace id survives on a single
filesystem path.

---

## Inspecting the active session

```bash
kvendra session info           # human-readable, minimal
kvendra session info -v        # verbose (refresh expiry, issuer, URLs)
kvendra session info --json    # machine-readable
```

Sample verbose output:

```
Mode: workspace
Workspace: acme-corp/frontend
Tenant: acme-corp
Member: bob@acme.com
Member id: 550e8400-e29b-41d4-a716-446655440000
JWT expires at: 2026-05-13T16:30:00Z (28 minutes from now)
Refresh token expires at: 2026-06-12T05:30:00Z
Last token refresh: 2026-05-13T15:25:00Z
Last allowlist sync: 2026-05-13T16:00:00Z
Issuer: https://auth.kvendra.cloud
Audience (client_id): 5ab5mhjhv0l6akhiqndvt636b
Broker URL: https://api.kvendra.cloud
Auth URL: https://auth.kvendra.cloud
```

---

## Background tasks during `mcp serve`

Two tokio tasks run while the broker is alive:

| Task | Cadence | What it does |
|---|---|---|
| `auth::refresh::refresh_if_needed` | every 60 s | Refreshes the JWT 5 min before expiry. `invalid_grant` → deletes the session and the next `tools/call` returns `WorkspaceSessionExpired`. |
| `workspace::allowlist_sync::sync_once` | every 5 min (configurable) | Re-pulls `GET /v1/workspaces/{ws}/templates`. Atomic write + mode `0400` on the cached YAMLs. |

If the sync has not succeeded in over 24 h the workspace is marked
`stale_blocked` and the next `tools/call` returns `AllowlistCacheStale`.
Recover with `kvendra workspace allowlist refresh`.

---

## Working with workspace secrets

Members and admins both call the primitives the same way; the difference
is who can create / rotate secrets:

```bash
# Admin: register a new shared secret. Server-side RBAC enforces the role.
kvendra workspace add-secret github-deploy \
  --secret-type github_pat \
  --template-id github-deploy-tmpl-v1 \
  --secret-env GITHUB_PAT_DEPLOY

# Member (read-only): the local CLI refuses early.
kvendra secret add my-pat --secret-env GH_PAT
# Error: insufficient privilege for 'add' ...

# Inspect membership.
kvendra workspace members list
kvendra workspace profiles list
```

---

## Logging out

```bash
kvendra logout --workspace acme-corp/frontend
# Deletes ~/.kvendra/sessions/acme-corp__frontend.token + sidecar .lock.

kvendra logout
# Without --workspace: locks the local vault (zeroes the derived key).
```

---

## Files on disk

```
~/.kvendra/
├── sessions/
│   ├── <ws>.token          # JSON, mode 0600 (jwt, refresh_token, member_email, ...)
│   ├── <ws>.token.lock     # cross-process advisory flock sidecar
│   └── <ws>.token.tmp.<pid># half-written file, removed on rename
├── cache/
│   └── allowlists/<ws>/
│       ├── <template>.yaml      # mode 0400, read-only owner
│       ├── <template>.yaml.etag # ETag (or vN fallback)
│       └── .stale_blocked       # touched after 24 h without sync
└── audit.db                # schema v2 (remote_audit_id, hmac_version)
```

The refresh_token lives plaintext on disk (mode 0600). This matches
`ADR-KVD-ENTERPRISE-002`: a compromised laptop yields a JWT revocable
server-side within 5–15 min via `tokens:issue` policy + IdP-side
revocation.

---

## Trust boundaries

| Threat | Mitigation |
|---|---|
| Local file leak (laptop compromised) | Refresh_token mode 0600, broker TTL ≤ 30 d, server-side revocation. |
| Stale local allowlist | 24 h `stale_blocked` gate + broker server-side enforcement on every `tokens:issue` (defense in depth). |
| OIDC CSRF | PKCE `state` parameter compared in constant time. |
| Broker downtime | `BrokerUnreachable` returns a user-friendly error; primitives that do not need a profile keep working. |

---

## Smoke test (manual, against `kvendra-enterprise-staging`)

```bash
# Pre: vault initialised, KVENDRA_MCP_PASSWORD set, you are an active member
# of acme-corp/frontend in staging.
unset KVENDRA_ACTIVE_WORKSPACE
kvendra logout                                # clean state
kvendra login --workspace acme-corp/frontend  # opens browser, PKCE flow
kvendra session info                          # mode == workspace
kvendra session info -v                       # extended fields populated
kvendra session info --json | jq .workspace_id  # parseable
# Drive a primitive via your MCP client (Claude Code) and confirm the
# CloudWatch logs of kvendra-staging-tokens-issue show the call.
sqlite3 ~/.kvendra/audit.db \
  "SELECT id, action, remote_audit_id, hmac_version FROM audit_events
   ORDER BY id DESC LIMIT 5"
kvendra audit --verify   # chain must verify across v1 + v2 rows
kvendra logout --workspace acme-corp/frontend
```

---

## Related entities

- `REQ-KVD-CLI-004` — `SecretResolver` trait + login.
- `REQ-KVD-CLI-008` — JWT refresh proactivo.
- `REQ-KVD-CLI-009` — allowlist sync.
- `REQ-KVD-CLI-010` — audit DB migration.
- `IF-KVD-ENTERPRISE-002` — wire contract consumed by `RemoteBrokerResolver`.
- `ADR-KVD-ENTERPRISE-001` — token-vending TTL semantics.
- `ADR-KVD-ENTERPRISE-002` — workspace custodia centralizada + trust boundary.
- `ADR-KVD-026` — cloud-agnostic wire.
