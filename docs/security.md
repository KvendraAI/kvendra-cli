# Security model — kvendra-cli v0.1.0

## Trust narrative

kvendra implements a **zero-knowledge vault** (Argon2id-derived key,
AES-256-GCM ciphers, master password never stored to disk except as a
sentinel hash) plus a **capability-based MCP broker** (7 git/github/npm/
pypi/aws/http/shell primitives + an escape hatch for raw tokens).

The trust narrative for v0.1.0:

1. **Defense layer 1 — Filesystem integrity**: `~/.kvendra/` is per-user
   (mode 0700), individual files mode 0600, sentinel + recovery codes +
   profile blobs all HMAC-protected against in-place tampering.

2. **Defense layer 2 — Allowlist gate**: each profile's allowlist YAML is
   HMAC-signed with `kvendra/allowlist-hmac/v1` sub-key (TOCTOU-safe).
   Boundary calls outside scope return `AllowlistViolation` with a
   canonical audit row flag (`allowlist_denied`).

3. **Defense layer 3 — Approval gate**: destructive ops (write, push,
   destroy) require explicit user consent via TTY (CLI) or modal/dialog
   (MCP). Approval results are audit-logged with canonical flags
   (`mcp_approval_biometric_granted` / `mcp_approval_biometric_rejected`).

4. **Defense layer 4 — Audit log integrity**: every MCP call + every
   sensitive CLI op writes a row to `~/.kvendra/audit.db`, HMAC-chained
   with sub-key `kvendra/audit-hmac/v1`. Tampering detected via
   `kvendra audit --verify`.

## v0.1.0 caveats

### MCP password caching: RAM-only, not Touch ID

In v0.1.0, the `master_password_cache = "ram-only"` mode is the default
and only mode for MCP transport. Touch ID-protected password caching
(promised in early roadmap material) requires a signed binary
(Apple Developer ID), which is **not available** in v0.1.0.

The full technical analysis of this caveat lives in `PAT-KVD-CLI-001` in
the project knowledge base. The summary:

- **Destructive ops via MCP** still require approval. The approval gate
  degrades from "Touch ID biometric" to "macOS modal consent dialog with
  Approve/Cancel buttons" — the cryptographic factor is weaker (button
  click vs fingerprint), but the structural promise is preserved: no
  silent automated bypass.
- **CLI-direct ops** (when user runs `kvendra` interactively) require
  TTY password prompt every time the cache expires (see
  `idle_timeout_minutes` in `config.toml`).
- **No silent silent approval** in either transport — `PAT-KVD-CLI-001`
  documents this with audit-log evidence from real-run testing.

Touch ID and signed-binary distribution are planned for v0.2.0 via
`ROAD-KVD-CLI-002`.

## Reporting security issues

Security-relevant issues should be reported per the project's
[`SECURITY.md`](../SECURITY.md) policy.

## References

- `ROAD-KVD-CLI-001` — v0.1.0 stable readiness roadmap.
- `ROAD-KVD-CLI-002` — v0.2.0 "Mac compatible" (Apple Dev ID + Touch ID).
- `PAT-KVD-CLI-001` — v0.1.0 approval gate behavior without Apple Dev ID.
- `PAT-KVD-CLI-002` — Test verification against binary actual output.
- `PAT-KVD-CLI-003` — Allowlist enforcer permissive-on-absence anti-pattern.
