# Changelog

All notable changes to the `kvendra` crate are documented here. The format
is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/) with
`-alpha.N` / `-beta.N` pre-release suffixes during the pre-1.0 phase.

## [Unreleased]

## [0.5.0] — 2026-05-28 — `kvendra capabilities` subcommand (broker manifest discovery)

Additive, no breaking. Adds a new top-level `kvendra capabilities` subcommand that emits the canonical broker capabilities manifest as JSON on stdout. Wire-public, read-only, auth-less — designed to be consumed by `kvendra-skills` at runtime (`onboard-project` Step 1.5, `release-manager` IF-MANIFEST sync, `lint-claudemd` primitive cross-check).

### Added

- `kvendra capabilities` — emits a JSON manifest with `broker_version` (matches `CARGO_PKG_VERSION`), `schema_version: 1` (stable wire contract), and `primitives[]` with `{id, ops, destructive_ops, vault_profile_pattern, since_version, deprecated_in?}`. Covers the 8 canonical primitives × 24 ops. Zero vault unlock, zero network IO, zero filesystem writes (`AC-CLI-3`).
- `kvendra capabilities --pretty` — multi-line indented JSON for human reading (`AC-CLI-9`). Default output is compact single-line JSON.
- Manifest schema versioning contract (`AC-CLI-8`): `schema_version: 1` is stable. Consumers MUST verify `schema_version == 1`. Bumping requires a major REQ + IF-MANIFEST schema bump in lockstep.
- Snapshot + invariant unit tests in `src/cli/capabilities.rs` (8 primitives, 24 ops, `destructive_ops ⊆ ops`, deterministic order, compact vs pretty round-trip).

### Trazabilidad

- Implementa: `REQ-KVD-ECDAE9` (`scope: Piece A`, ACs `AC-CLI-1..9`).
- ROAD: `ROAD-KVD-SKILLS-C20D24` M2 first item.
- TXN: `TXN-KVD-20260528-005`.
- Sibling REL (downstream consumer): `REL-KVD-SKILLS-N.alpha` (release-manager extension) + `REL-KVD-SKILLS-N+1` (onboard-project Step 1.5 + STD-TPL library).

### Distribution

- `cargo publish` of `0.5.0` is gated to PHASE 3 owner-manual per `STD-KVD-57DAE1`. Until then, the subcommand is locally testable via `cargo build --release && ./target/release/kvendra capabilities --pretty`.

## [0.4.1] — 2026-05-27 — kvendra.github primitive: create_issue + list_issues + yank-recovery stable

Aditivo, no breaking. Extiende el primitive `kvendra.github` con dos nuevas operations para soportar sync bidireccional KB↔GitHub Issues.

### Added

- `kvendra.github.create_issue` — `POST /repos/{owner}/{repo}/issues`. Destructive (requiere `accept_destructive: true` en allowlist YAML). El campo `body` se sanitiza ad-hoc antes del POST: tokens (`ghp_*`, `kvd_live_*`, `sk-*`), AWS keys, master password patterns y paths absolutos `/Users/<name>/` son reemplazados por `<redacted:provider>` vía `detection::sanitize_value`. Args: `{ repo, title, body?, labels?, assignees?, milestone? }`. (`REQ-KVD-CLI-1D156A`)
- `kvendra.github.list_issues` — `GET /repos/{owner}/{repo}/issues` con filtros (`state`, `labels`, `since`) y paginación transparente. Read-only (no destructive opt-in). Default `max_pages=10`, cap `50`. Retorna wrap rico `{ issues, truncated, pages_fetched }`. (`REQ-KVD-CLI-1D156A`)

### Allowlist catalog

- Catalog destructive: `kvendra.github.create_issue` añadido como `Destructive` (incondicional). Total reglas: 14 → **15**.

### Trazabilidad

- Implementa: `REQ-KVD-CLI-1D156A` (`scope: A+B`, sub-task `C (pulls parity)` diferida).
- Resuelve: `ISSUE-KVD-CLI-ADBC83`.
- Origin: workflow KB↔GitHub sync demand.

### Distribution

- **crates.io `max_stable_version`**: `None` → `0.4.1` (yank-recovery — recovers from `0.4.0` yank executed 2026-05-27 12:24 UTC).
- **`cargo install kvendra`** (sin `--version`) ahora resuelve a `0.4.1`. Cierra la ventana "no stable" abierta el 2026-05-27 12:24 UTC.
- **`0.4.1-alpha.1`** se preserva publicada (NOT yanked) — installable explícito vía `cargo install kvendra --version "0.4.1-alpha.1"` por trazabilidad.
- **`0.4.0`** permanece yanked (sin cambio) por `ISSUE-KVD-CLI-8CDFB5`.

### Yank-recovery context

Este release recupera la posición `max_stable_version` perdida tras el yank de `0.4.0` (commit `df6274c`, 2026-05-20) por `Cargo.toml [target.'cfg(unix)'.dependencies]` mal cerrado que atrapaba 23 deps cross-platform (ver `ISSUE-KVD-CLI-8CDFB5` + `PAT-KVD-CLI-FFE04A`). El código de `0.4.1` es funcionalmente superset de `0.4.0`: incluye el fix cross-platform + feat(github) `create_issue` + `list_issues`.

CI 9/9 verde en `main` por primera vez (rustfmt, clippy, test [ubuntu/macos/windows], msrv [1.88], cloud-agnostic-lint, e2e-smoke [ubuntu/macos]).

### Trazabilidad (yank-recovery)

- **REQ**: `REQ-KVD-CLI-04C06A` (release-engineering / yank-recovery).
- **TXN**: `TXN-KVD-20260527-004`.
- **PAT canónico**: `PAT-KVD-CLI-A45DEA` (segunda aplicación — primer scenario fue `0.4.0` promotion el 2026-05-20).
- **ISSUE incident origen**: `ISSUE-KVD-CLI-8CDFB5`.
- **PAT lesson cfg(unix)**: `PAT-KVD-CLI-FFE04A` (cumplido en HEAD).
- **REL anterior (pre-release)**: `REL-KVD-CLI-0.4.1.1`.
- **REL reemplazada (yanked)**: `REL-KVD-CLI-0.4.0`.

## [0.4.0] — 2026-05-20 — First cross-platform stable since 0.1.0

**Consolidates the 0.4.0 alpha series (.1..6) into a stable release.** Works on
macOS, Linux, and Windows. No Apple Developer ID required. Promotes
`max_stable_version` in crates.io from `0.1.0` (2026-05-08) to `0.4.0`, so
`cargo install kvendra` now installs this version by default.

### Added (consolidated from alpha.1..6)

- **Cross-platform session model** (`kvendra unlock` / `lock` /
  `session status`) with session blob TTL — supersedes the macOS-only
  Touch ID + Keychain ACL approach. AES-256-GCM
  `~/.kvendra/sessions/active.blob` with HKDF sub-key wrap (per
  `ADR-KVD-022`). Closes the `path-to-stable` chapter of
  `ROAD-KVD-CLI-002`. (`REQ-KVD-CLI-011`, alpha.1)
- **3-layer anti-captured-env defense**: `/dev/tty` direct + triple
  `isatty` + parent ancestry enrichment. Validated empirically vs
  Claude Code Bash tool, `!` shell escape, and native terminal
  (probe `/tmp/kvendra-probe.sh`). (`PAT-KVD-CLI-008`, alpha.1)
- **Pro tier inspector** (`kvendra pro inspect`) — surfaces JWT
  identity + tier + email + tenant_id from the id_token. (alpha.3 +
  alpha.4 OIDC compliance: `pro.email` from id_token claim, not
  access_token.)
- **Allowlist wildcard glob single-segment matcher** — `refs/tags/v*`
  now matches any tag without literal per-tag entries. The matcher
  treats `*` as `[^/]*` (does not cross `/`), with anchored
  full-string match. Validated end-to-end pushing `v0.4.0-alpha.6`
  with no per-tag literal. (`REQ-KVD-CLI-E0C962`, alpha.5)
- **MCP tolerant boot** + **audit writer lazy-spawn** — the broker
  survives `LockedPendingUnlock` state without crash; the audit
  thread is spawned on the first event instead of at boot.
  (alpha.2)

### Fixed (consolidated from alpha.1..6)

- Decoder crash on malformed JWT in `list_active_sessions` + 6
  collateral callsites curated in a single pass
  (`ISSUE-KVD-CLI-2F07ED`, alpha.3).
- `login --pro` tracing — explicit `tracing::info!(target:
  "kvendra::login", flag: "pro_login_succeeded", ...)` for
  observability (`ISSUE-KVD-CLI-9AE300`, alpha.3).
- Pro tier detection in `session info` (`ISSUE-KVD-CLI-170F9D`,
  alpha.3).
- Pro session `email` field populated from id_token, not
  access_token (Cognito OIDC compliance; `ISSUE-KVD-CLI-940018`,
  alpha.4).
- Clippy lints post Rust 1.95.0 toolchain upgrade — 6 lints fixed
  (`clippy::assertions_on_constants`,
  `clippy::doc_overindented_list_items`,
  `clippy::items_after_test_module`). Runtime invariant test
  replaced by compile-time `const _: () = { ... }` block (stricter:
  build fails instead of runtime). (`ISSUE-KVD-CLI-062364`, alpha.6)

### Distribution

- **crates.io**: kvendra `0.4.0` published. Now the
  `max_stable_version` (was `0.1.0` since 2026-05-08).
  `cargo install kvendra` installs this version by default.
- **Yanked from crates.io**: `0.0.1`, `0.0.2` (pre-MVP placeholders),
  and `0.1.0` (superseded as max_stable by `0.4.0`; still
  installable via `cargo install kvendra --version "0.1.0"`).
- **GitHub Releases**: `v0.4.0` with `prerelease: false`. First
  non-prerelease tag since `v0.1.0`.

### Verified

- `cargo test --all-features --no-fail-fast`: 394 PASS / 0 FAIL /
  3 IGNORED.
- `cargo clippy --all-features --all-targets -- -D warnings`: 0
  errors.
- `cargo build --release`: kvendra v0.4.0 binary OK.
- crates.io API post-publish: `max_stable_version: "0.4.0"`,
  `newest_version: "0.4.0"`, `0.0.1`/`0.0.2`/`0.1.0` `yanked: true`.

### Pending follow-up (NOT blockers)

- Physical Windows smoke validation — CI matrix is green; physical
  PoC tracked in `ROAD-KVD-CLI-002` caveat list. Owner-call accepted
  this as non-blocker for 0.4.0 stable.
- Apple Developer ID + Touch ID 1-tap UX → future ROAD v0.3.0+
  nice-to-have for macOS power users.
- Windows Authenticode + Linux GPG signing + reproducible builds →
  `ROAD-CLI-003` (future).

### Trazabilidad

- ROAD parent: `ROAD-KVD-CLI-002` (done 2026-05-18 vía
  `REL-KVD-CLI-0.4.0.1`; this release consolidates the path).
- Consolidates: `REL-KVD-CLI-0.4.0.1` ..
  `REL-KVD-CLI-0.4.0.6`.
- Supersedes (as crates.io `max_stable`): `REL-KVD-CLI-0.1.0`.
- Resolves: `ISSUE-KVD-CLI-6508C3` (CLAUDE.md drift + crates.io
  max_stable promotion trigger).
- Origin: consultancy-v3 session 2026-05-20 — owner prompt
  "queremos que la versión estable apunte a la última".

## [0.4.0-alpha.6] — 2026-05-20 — Clippy hygiene post Rust 1.95.0

Code-hygiene release: limpia 6 lints clippy pre-existentes que el upgrade
del Rust toolchain a 1.95.0 stable endureció a errores fail-on-warn.
Cierra `ISSUE-KVD-CLI-062364`. **Sin cambios funcionales** — sólo
refactor de docstrings, conversión de runtime→compile-time assertions,
y reordenación de items en módulos test.

### Changed
- `src/session/ttl.rs` — invariantes de TTL movidas de un `#[test] fn`
  runtime a un `const _: () = { ... }` block compile-time
  (`clippy::assertions_on_constants`). Más estricto + más rápido: el
  build falla si las constantes salen del rango canónico.
- `src/vault/mod.rs` — doc-comments con indentación corregida en 2
  ocurrencias (`clippy::doc_overindented_list_items`).
- `src/cli/mcp.rs` — `fn read_keychain_password` reordenado para
  preceder al `mod tests` (`clippy::items_after_test_module`).

### Verified
- `cargo clippy --all-features --all-targets -- -D warnings` verde
  (0 errores).
- `cargo test --all-features --no-fail-fast` verde (394 PASS / 0 FAIL /
  3 IGNORED). El test count bajó de 395 a 394 porque el `#[test] fn
  defaults_are_in_canonical_range` fue eliminado: las invariantes ahora
  se verifican en compile-time vía `const _: () = { ... }`, lo que es
  estrictamente más fuerte (fallo en build en lugar de runtime).

## [0.4.0-alpha.5] — 2026-05-20 — Allowlist YAML wildcard `*` general

Polish release on top of `0.4.0-alpha.4`. Cierra `ISSUE-KVD-CLI-280B87`
(allowlist `refs` matcher exact-literal — workaround per-tag eliminado)
y materializa la spec `TEST-KVD-CLI-097` D8 (glob single-segment).

### Changed
- **`glob_match` ahora soporta `*` en cualquier posición del pattern, no sólo
  como sufijo `/*`** (`REQ-KVD-CLI-E0C962`). El carácter `*` se comporta
  como `[^/]*` (single-segment, no cruza `/`); caracteres regex
  (`.`, `+`, `?`, ...) se tratan literalmente; el match queda anclado
  full-string (`^...$`). Aplica a campos `refs`, `buckets`,
  `distributions`, `functions`, `packages`, `projects`, `org`, `repos`/`repo`
  del allowlist DSL. Sin dependencias nuevas (usa `regex` ya presente).

### Fixed
- `refs: ["refs/tags/v*"]` ya permite push de `refs/tags/v0.4.0-alpha.3`
  (`ISSUE-KVD-CLI-280B87`). Workaround per-tag literal en el allowlist
  del profile `github.kvendraai.cli-write` puede eliminarse re-firmando
  con `kvendra secret set-allowlist`.

### Breaking — internal semantic change
- El matcher previo de `prefix/*` cruzaba `/` silenciosamente
  (`release/*` matcheaba `release/v1/sub`). El nuevo matcher rechaza
  ese caso, alineando con `TEST-KVD-CLI-097` B2b. Owners que dependan
  del comportamiento previo deben re-firmar allowlists con entries
  split-explícitas. Sin usuarios reales hoy fuera del owner; no se
  considera ruptura externa.

## [0.4.0-alpha.4] — 2026-05-19 — Pro session email from id_token (OIDC compliance)

Polish release on top of `0.4.0-alpha.3`. Cierra `ISSUE-KVD-CLI-940018` (reclasificado del original `ISSUE-KVD-ENTERPRISE-CC3B95`): el campo `pro.email` aparecía como `None` en `kvendra session info --json` porque el flow `login --pro` solo persistía el access_token, y Cognito sigue OIDC estrictamente — el claim `email` va en el id_token, no en el access_token.

### Fixed
- **`session info` no mostraba `pro.email`** (`ISSUE-KVD-CLI-940018`, redirect from `ISSUE-KVD-ENTERPRISE-CC3B95`): `pro_login()` ahora persiste también `~/.kvendra/sessions/pro.id_token` (mode 0600) junto al access_token. `read_pro_view` prefiere id_token para extraer email/issuer/exp con fallback al access_token para backwards-compat con instalaciones pre-0.4.0-alpha.4. `logout` sin `--workspace` borra idempotentemente el sidecar pro.id_token. El access_token sigue siendo consumido por `kvendra backup` endpoints sin cambios. Causa raíz verificada empíricamente: Cognito client tiene `AllowedOAuthScopes: [openid, email, profile]` correctamente, pero el `email` claim solo se incluye en el id_token (comportamiento OIDC estándar, no bug de Cognito ni del SAM template). Fix CLI-side: 4 ficheros tocados, 3 tests añadidos. 388/388 PASS.

## [0.4.0-alpha.3] — 2026-05-19 — Pro tier inspector + decoder fix + login tracing

Polish release on top of `0.4.0-alpha.2`. Consolida 3 fixes detectados durante el dogfooding del manual gate TEST-M1: el decoder bug original que la sesión Pro disparaba en `kvendra session info`, la falta de detección del tier Pro en el inspector, y la ausencia de tracing structured log en `kvendra login --pro`. Closes `ISSUE-KVD-CLI-2F07ED`, `ISSUE-KVD-CLI-170F9D` and `ISSUE-KVD-CLI-9AE300`.

### Fixed
- **`session info` crash post `login --pro`** (`ISSUE-KVD-CLI-2F07ED`): `list_active_sessions` no excluía `pro.token` del scan de workspace tokens. `pro.token` es un JWT raw escrito intencionalmente por `pro_login()` y consumido por `backup::load_pro_jwt`; aparecía como pseudo-workspace `"pro"` y `SessionState::load` fallaba con `decode: expected value at line 1 column 1`. Filtro añadido en `src/session/store.rs:225-237`. Adicionalmente: error de `SessionState::load` ahora incluye el path completo + hint sobre raw tier tokens (defence-in-depth para futuros `team.token`/`enterprise.token`); workaround redundante `.find(|w| w != "pro")` en `src/cli/notifs.rs:135-138` eliminado (single source of truth en el listado canónico). Curaba 5 callsites afectados además del reportado: `cli/logout.rs:30`, `cli/secret.rs:134`, `cli/workspace.rs:127`, `mcp/server.rs:294`, `cli/notifs.rs:135`. 5 tests de regresión añadidos (3 unit + 2 integration via `assert_cmd`).
- **`session info` no detectaba tier Pro** (`ISSUE-KVD-CLI-170F9D`): el comando reportaba `Mode: local (Free tier)` aunque `~/.kvendra/sessions/pro.token` existiera. Nueva struct `ProSessionView` (active, email, issuer, expires_at, seconds_until_expiry, blob_path) en `src/cli/session_info.rs` + función `read_pro_view(home)` que detecta el token y decodifica claims via `decode_jwt_payload` (promovido a `pub(crate)` desde `src/cli/login.rs`). Lógica de `mode` actualizada: solo pro.token → `mode: "pro"` ("Mode: pro (cloud backup)"); workspace presente → `mode: "workspace"` con bloque `pro` también serializado en paralelo (coexistencia full visibility). JSON expone el campo `pro` cuando aplica. Tests añadidos: 3 unit en `src/cli/session_info.rs` (happy path, fresh install, garbled JWT defensive) + 1 integration en `tests/session_info_pro_coexist.rs` (coexistencia pro+workspace). Test integration existente `session_info_works_with_pro_token_present` actualizado para reflejar `mode: "pro"` post-fix.
- **`login --pro` sin tracing structured log** (`ISSUE-KVD-CLI-9AE300`): `pro_login()` solo emitía `eprintln!` para feedback humano; ningún structured event capturable por agregadores de logs. Añadido `tracing::info!(target: "kvendra::login", flag: "pro_login_succeeded", email, issuer, expires_at)` tras el persist exitoso de `pro.token`. `JwtClaims` gana campo `exp: Option<i64>` (Unix timestamp) y el helper formatea como RFC3339. NO escribe audit DB row — incompatible con vault locked durante `login --pro` (OAuth flow no requiere master password), coherente con `ADR-KVD-010` L1 V4-relaxed (audit chain depende del vault unlock). Si se requiere persistencia, queda como follow-up ENH. 1 test añadido (`decodes_exp_claim_and_formats_rfc3339`).

## [0.4.0-alpha.2] — 2026-05-19 — MCP tolerant boot + audit writer lazy-spawn

Polish/extension release on top of `0.4.0-alpha.1`. Closes the cold-start
friction left by `REQ-KVD-CLI-011`: the MCP server now arranca tolerant
when no session blob is available at boot, and self-heals transparently
when `kvendra unlock` is executed afterwards — eliminating the need for
Claude Code restart in the arranque-sin-credenciales case. Also fixes a
forensics gap detected during validation (audit writer was never spawned
post-self-heal from `LockedPendingUnlock`).

Implements `REQ-KVD-CLI-42CB74`, closes `ISSUE-KVD-CLI-E6591F` and
`ISSUE-KVD-CLI-9764AC`. Supersedes partial `PAT-KVD-009` (canonical fix
"restart Claude Code") for the arranque-sin-credenciales case.

### Added
- **Tolerant MCP boot**: `kvendra mcp serve` now starts in `LockedPendingUnlock` state when no session blob, env var, or keychain credential is available — instead of exiting with error. `whoami`, `help`, and `config_get` remain functional in this state; vault-dependent tools return JSON-RPC error `-32002` with `help.topic: vault-locked-pending-unlock`. The MCP server auto-recovers transparently on the next vault-dependent tool call once `kvendra unlock` is executed in another terminal — no Claude Code restart needed. Supersedes partial PAT-KVD-009 (canonical fix "restart Claude Code") for the arranque-sin-credenciales case. Implements REQ-KVD-CLI-42CB74.

### Changed
- **Audit flag rename**: `session_self_healed` (REQ-KVD-CLI-011 idle self-heal path) renamed to `mcp_self_heal_from_idle` for symmetry with the new `mcp_self_heal_from_pending` flag introduced by tolerant MCP boot. Any external SQL query filtering by the literal `session_self_healed` must be updated.

### Fixed
- **Audit writer late-spawn**: when `kvendra mcp serve` starts in `LockedPendingUnlock` state, the audit writer was initialized as `None` (vault locked → no HMAC chain key derivable) and never re-spawned after successful self-heal from pending. Tool calls succeeded but audit rows were not persisted to `~/.kvendra/audit.db` (only emitted to stderr/tracing, with `auditEventId: 0` in JSON-RPC response). The writer is now lazy-spawned within `try_self_heal_vault` upon successful unlock from pending, with double-checked locking to prevent races between concurrent tool calls. Closes ISSUE-KVD-CLI-9764AC.

## [0.4.0-alpha.1] — 2026-05-18 — cross-platform session model (REQ-KVD-CLI-011)

Version note: this release intentionally skips the original `0.2.0` slot
(which was reserved for the Apple Developer ID + Touch ID path now
deprecated by this release) and jumps to `0.4.0-alpha.1` so the semver
ordering on crates.io stays monotonically increasing after the published
`0.3.0-alpha.1` (workspace mode). The `0.2.0` slot is permanently
unused; see `ROAD-KVD-CLI-002` re-scope decision (consultancy-v3
2026-05-18 / TXN-KVD-20260518-002).



Path to `0.2.0` re-scoped on 2026-05-18 (consultancy-v3 / TXN-KVD-20260518-002):
the macOS-only Apple Developer ID + Touch ID Keychain ACL path is replaced by
a cross-platform session model that works on macOS, Linux and Windows without
any signing dependency. Foundational decisions in `PAT-KVD-CLI-008`
(strategic + technical lessons) and `ADR-KVD-029` (session blob storage).

### Added

- **`src/session/local.rs`** — local master-session blob at
  `~/.kvendra/sessions/active.blob` (AES-256-GCM, machine-bound wrap key,
  HMAC-SHA256 sidecar, advisory flock, mode 0600). HKDF sub-key
  `kvendra/session-wrap/v1` (fourth alive sub-key under the
  `ADR-KVD-022` convention, after audit / allowlist / config).
- **`src/captured_env/`** — three-layer anti-captured-env defense for
  `kvendra unlock`: `/dev/tty` / `CONIN$` open + triple `isatty` +
  parent ancestry enrichment. Validated empirically against Claude Code
  Bash tool and `!` shell escape on 2026-05-18.
- **`Vault::unlock_from_derived_key`** — install a pre-derived key,
  verifying it against the sentinel. `kvendra mcp serve` uses this to
  avoid paying the Argon2id cost on every startup.
- **CLI surface**:
  - `kvendra unlock --extend` — refresh TTL without re-typing.
  - `kvendra unlock --ttl <duration>` — override TTL, capped by config.
  - `kvendra lock` — now also deletes the session blob + HMAC sidecar.
  - `kvendra session info` — local session row coexists with the
    Sprint 4 workspace JWT row in both human and JSON output.
- **Config**: new `[session]` block with `default_ttl_seconds`
  (default 4h), `max_ttl_seconds` (default 24h, hard ceiling 7d) and
  `renew_on_activity` (default false).
- **Audit flag constants** (AC-SESSION-14) — the nine canonical strings
  for the local session lifecycle are now `pub const` in
  `src/audit/mod.rs`.

### Changed

- **`kvendra mcp serve`** — the local session blob is the canonical
  unlock path. Order: session blob → `--use-keychain` (legacy) →
  `--password-env` / `KVENDRA_MCP_PASSWORD`. The interactive TTY
  prompt fallback was removed because an MCP subprocess never has a
  usable terminal.

### Deprecated

- **`kvendra config mcp-password enable`** / `--use-keychain`
  (REQ-KVD-005, macOS Keychain ACL) — feature-preserved for users with
  an Apple Developer ID but no longer required. Returns as a
  `v0.3.0+` nice-to-have alongside Touch ID 1-tap UX once the Apple
  Developer ID + notarization pipeline lands.

### Zero new external crates

Everything reuses what was already in `Cargo.toml`. Windows uses
`std::io::IsTerminal` from the standard library; the ancestry walker
shells out to `ps`. Full `CONIN$` + `GetConsoleProcessList` enforcement
on Windows is staged for the physical PoC tracked under the related
ISSUE.

## [0.3.0-alpha.1] — 2026-05-13

**Workspace mode (Team / Enterprise tier groundwork).** This release
introduces the optional `RemoteBrokerResolver` and the OIDC PKCE login
flow that backs it. The standalone (Free) tier path is preserved
byte-for-byte: a binary upgraded to `0.3.0-alpha.1` with no workspace
session on disk behaves exactly like `0.1.0`.

Version note: `0.2.0` is reserved for the Apple Developer ID +
notarization milestone tracked under `ROAD-KVD-CLI-002`. Workspace
mode is intentionally minted as `0.3.0-alpha.N` so the two branches
do not collide.

### Added

- **`SecretResolver` trait** with two implementations:
  - `LocalVaultResolver` — wraps the existing zero-knowledge vault,
    preserving pre-Sprint-4 semantics (`audit_id == None`,
    `expires_at == now + 365d`).
  - `RemoteBrokerResolver` — `POST /v1/profiles/{id}/tokens:issue`
    against the broker behind `KVENDRA_BROKER_URL` (default
    `https://api.kvendra.cloud`). Full HTTP error mapping:
    `401 → WorkspaceMembershipRevoked`,
    `403 → InsufficientPrivilege`, `410 → ProfileExpired`,
    `429 → RateLimited`.
- **OIDC Authorization Code + PKCE flow** (`auth/oidc.rs`) with a
  loopback callback receiver bound in the port range `54321..54330`
  (10 ports × {127.0.0.1, localhost} = 20 URLs configured in the
  OIDC public client). PKCE per RFC 7636, state CSRF token,
  constant-time comparison.
- **Proactive JWT refresh** (`auth/refresh.rs`) — 5 min lead time,
  cross-process flock on `~/.kvendra/sessions/<ws>.token.lock`,
  `invalid_grant` re-mapped to `WorkspaceSessionExpired`. Runs in a
  background tokio task while `mcp serve` is live.
- **Allowlist sync** (`workspace/allowlist_sync.rs`) — pulls templates
  from the broker on `login` and every 5 min thereafter; per-template
  cache YAML under `~/.kvendra/cache/allowlists/<ws>/`, file mode
  `0o400`. After 24 h without a successful sync the workspace is
  marked `stale_blocked` and `tools/call` rejects with
  `AllowlistCacheStale`.
- **Audit DB migration v2** (`audit/migrations.rs`):
  - New columns `remote_audit_id TEXT NULL` and
    `hmac_version INTEGER NOT NULL DEFAULT 1`.
  - Index `idx_audit_remote_id`.
  - `schema_migrations` ledger tracks applied versions.
  - **HMAC versioning per row** — historical rows keep `compute_hmac_v1`
    (no `remote_audit_id`); new rows write `compute_hmac_v2` which
    binds the ULID into the chain. `verify_chain` dispatches on the
    row's `hmac_version` column.
- **CLI subcommands**:
  - `kvendra login --workspace <id>` — PKCE flow + persist session +
    initial allowlist sync.
  - `kvendra logout [--workspace <id>]` — delete session or lock vault.
  - `kvendra session info [-v] [--json]` — show mode, workspace,
    member, JWT TTL. Verbose adds refresh expiry, audience,
    last_token_refresh_at, last_allowlist_sync_at, broker/auth URLs.
  - `kvendra workspace add-secret` (admin/owner via broker RBAC).
  - `kvendra workspace allowlist refresh`.
  - `kvendra workspace members list`.
  - `kvendra workspace profiles list`.
- **Cloud-agnostic CI lint** — `scripts/ci-cloud-agnostic-check.sh`
  greps `src/{secret_resolver,auth,protocol,workspace,session}/` for
  vendor-specific strings and fails the build on any leak. Wired into
  `.github/workflows/ci.yml` as the `cloud-agnostic` job.
- **New error variants** (`error.rs`): `WorkspaceMembershipRevoked`,
  `WorkspaceSessionExpired`, `RateLimited`, `BrokerUnreachable`,
  `OidcCallbackPortRangeExhausted`, `OidcStateMismatch`,
  `OidcDiscoveryFailed`, `OidcFlow`, `AuditMigrationHmacMismatch`,
  `AuditMigrationAborted`, `InsufficientPrivilege`,
  `MultipleWorkspaceSessionsAmbiguous`, `AllowlistCacheStale`,
  `AllowlistDeniedByBroker`, `SessionStore`.

### Changed

- **`kvendra secret add` / `secret rotate`** now return
  `InsufficientPrivilege` in workspace mode, pointing the user at
  `kvendra workspace add-secret` (server-side RBAC).
- **`AuditEvent`** gains `remote_audit_id: Option<String>`. Eight
  in-tree construction sites updated.
- **`ServerContext`** gains `resolver`, `session`, `workspace_id`.
- **`Cargo.toml`** new deps: `async-trait`, `chrono`, `url`,
  `urlencoding`, `fs2`, `tiny_http`, `webbrowser`.

### Notes for upgraders

- A binary upgraded to `0.3.0-alpha.1` with no workspace session on
  disk behaves identically to `0.1.0`. The migration only adds columns
  and indices to `audit.db`; existing rows keep their v1 HMACs.
- Trust boundary: workspace `refresh_token` lives plaintext on disk at
  `~/.kvendra/sessions/<ws>.token` (mode 0600). This matches
  `ADR-KVD-ENTERPRISE-002` — a compromised laptop yields a JWT
  revocable server-side within 5–15 min.

### Trazabilidad

- ISSUE-KVD-CLI-046 (parent), REQ-KVD-CLI-004/008/009/010,
  ADR-KVD-ENTERPRISE-001/002, ROAD-KVD-ENTERPRISE-001 M1 Sprint 4.

## [0.1.0] — 2026-05-08

**First stable release.** Multi-platform CLI (macOS / Linux / Windows)
with full structural security: allowlist gate, audit log HMAC chain,
transport separation, consent gate on destructive ops.

This release is the cumulative scope of all alpha series (alpha.1
through alpha.11) since the project's first commit, plus distribution
documentation polish.

Smoke real Windows+Linux validation deferred per `RUN-KVD-CLI-001`
(owner without hardware access on release day). CI matrix coverage
(Ubuntu/macOS/Windows `cargo test` 284 green) accepted as substitute;
extending `e2e-smoke.yml` to ubuntu-latest is the recommended
post-stable mitigation.

### Released features

- **Capability-based MCP broker** — 7 primitives (git, github, npm,
  pypi, aws, http, shell) + 1 escape hatch (`unsafe.raw_token`).
- **Zero-knowledge vault** — Argon2id key derivation + AES-256-GCM
  ciphers, master password never stored except as sentinel hash.
- **Per-profile allowlist YAML** — HMAC-signed, TOCTOU-safe, full
  22-field DSL coverage (operations, repos, refs, regions, buckets,
  forbidden args, etc.).
- **Audit log HMAC chain** — every call + every sensitive CLI op
  recorded with canonical flags. Verifiable via `kvendra audit --verify`.
- **Transport separation** — CLI=TTY (interactive), MCP=approval
  (consent gate).
- **Recovery codes** — 8 numeric one-time codes generated at `init`,
  regenerable via `kvendra config recovery-codes regenerate`.
- **Cross-platform CI** — Ubuntu/macOS/Windows test matrix, 284 tests.
- **E2E smoke harness** — `scripts/e2e-smoke.sh` for pre-tag validation,
  also runnable in GitHub Actions.

### Not in 0.1.0 (future)

- **Touch ID-protected MCP password storage** — requires signed binary
  (Apple Developer ID). Planned for v0.2.0 (`ROAD-KVD-CLI-002`). Current
  default uses RAM-only master password cache with consent modal — secure
  in practice (see `PAT-KVD-CLI-001`).
- **Apple notarization, Homebrew formula** — v0.2.0.
- **Windows Authenticode signing, Linux GPG signing** — v0.3.0+
  (`ROAD-KVD-CLI-003`).

### Documentation

- README install section rewritten for cross-platform, no code-signing
  required (`ISSUE-KVD-CLI-041`).
- New `docs/install.md` with platform-specific guides (macOS Gatekeeper,
  Linux distros, Windows SmartScreen).
- New `docs/security.md` with trust narrative, defense layers, and v0.1.0
  caveats.

### Migration from alpha series

No breaking changes since alpha.11. Vault, audit log, allowlist YAML
all backward-compatible. Existing alpha.11 users can `cargo install
--force --git ...` to upgrade.

## [0.1.0-alpha.11] — 2026-05-08

REL-KVD-CLI-0.1.0.11 — polish bundle pre-stable + smoke harness validation
gate. Intermediate alpha between `0.1.0-alpha.10` and `0.1.0` stable. Closes
the polish cluster of ROAD-KVD-CLI-001 and delivers an E2E smoke harness for
cross-platform validation. Activates REQ-KVD-CLI-001 / -002 / -003. Adds
PAT-KVD-CLI-002 and PAT-KVD-CLI-003.

### Security

- **Allowlist enforcement gap closed in `kvendra.git clone`** (closes
  ISSUE-KVD-CLI-043). Pre-fix, calls carrying `args.url` bypassed the
  enforcer (permissive-on-absence). Post-fix, the enforcer canonicalises
  the URL and matches it against `repos: [...]` in the YAML. Severity
  bumped minor → security-relevant after analysis. Anti-pattern captured
  in PAT-KVD-CLI-003.
- **`allowlist_denied` audit flag** emitted after every
  `KvendraError::AllowlistViolation` in the MCP dispatcher (closes
  ISSUE-KVD-CLI-033). Companion canonical flags `profile_expired` and
  `unsafe_not_enabled` added for forensic discrimination.
- **`allowlist_hmac_migrated` audit row** emitted after auto-migration of
  legacy profiles (closes ISSUE-KVD-CLI-023). Required refactoring
  `enforce_allowlist` from sync to async to access the AuditWriter.
- **`recovery_code_replay_attempted,slot_<N>` audit row** emitted after a
  replay attempt in `rebind-home` (closes ISSUE-KVD-CLI-026). Raw code
  never appears in the row (hash uses `sha256(prev_canon|slot)`).

### Added

- **`kvendra config recovery-codes regenerate` subcommand** (closes
  ISSUE-KVD-CLI-025). Double-barrier pattern: master password unlock
  followed by a TTY re-typed acknowledge `REGENERATE-RECOVERY-CODES`.
  Generates 8 fresh codes, Argon2id-hashed, atomic 0600 rewrite. Audit
  row records `previous_used_count`. Does NOT consume a recovery code
  (deadlock-avoidance).
- **E2E smoke harness** (closes ISSUE-KVD-CLI-037). New
  `scripts/e2e-smoke.sh` (~270 lines, 7 phases T1 / T1.5 / T2 / T3 / D /
  E / F), `docs/smoke.md` checklist, and `.github/workflows/e2e-smoke.yml`
  (macos-latest, paths-filtered). Designed to catch regressions of the
  PAT-KVD-004 family before tag-push.
- **SIGPIPE handler** installed in `main()` (closes ISSUE-KVD-CLI-042).
  `kvendra <cmd> | head` and similar pipelines no longer panic with
  exit 101 — they exit cleanly with 141. Discovered while building the
  smoke harness.

### Tests

- 261 → **284** cargo tests passed (+23 new). Coverage spans the audit
  canonical flags, the allowlist enforcer fix, the recovery-codes
  regenerate subcommand, and the smoke harness assertions.

### Compatibility

- Audit DB schema unchanged. Existing rows are NOT rewritten.
- Audit HMAC chain unchanged (sub-key `kvendra/audit-hmac/v1`).
- Allowlist YAML format unchanged. Existing `repos: [...]` entries
  continue to work; canonicalisation is runtime-only.
- CLI surface backward-compatible. Only addition is
  `recovery-codes regenerate`.

### Patterns

- **PAT-KVD-CLI-002** — "Test assertions must verify against the binary's
  actual output, not SPEC-imagined wording." Five iterations of the old
  pattern were eliminated with a verify-binary preventive sweep.
- **PAT-KVD-CLI-003** — "Allowlist enforcer permissive-on-absence."
  Anti-pattern detected in `inner.get(field)` with single-name lookup.
  Applies to any new branch added to the enforcer.

### Caveats

- Apple Developer ID + Touch ID remain deferred to 0.2.0
  (`ROAD-KVD-CLI-002`). Approval gate still functions via the macOS modal
  consent-only path (PAT-KVD-CLI-001).
- `cargo publish kvendra 0.1.0-alpha.11` to crates.io is NOT automated
  in this release (alpha publish is opt-in, owner-decided).

### Smoke validation

After this release, the owner's real cross-platform smoke (Windows +
Linux, task #7 of the pipeline) runs against the fixed `v0.1.0-alpha.11`
tag, not HEAD/main. Any cross-platform regression will be closed via
alpha.12 before the stable 0.1.0 tag — it will NOT be folded into 0.1.0.

## [0.1.0-alpha.10] — 2026-05-08

ISSUE-KVD-CLI-031 — Allowlist enforcer field-coverage fix. The Milestone 2
boundary smoke (AC-M2-6) caught two structural bugs in
`src/allowlist/enforcer.rs::check_args` that together blew the per-profile
authorisation surface wide open: (a) the three branches that **were**
implemented (`forbidden_args`, `methods`, `repos`) read their inputs from
the **top-level envelope** instead of the inner `args` payload, so any
real MCP `tools/call` request (canonical shape
`{profile_id, operation, args:{...}}`) silently bypassed those checks;
(b) **19 of the 22** declared `OperationConstraints` fields had no
enforcement branch at all and were dead letter — `buckets`, `distributions`,
`functions`, `binaries`, `packages`, `projects`, `refs`, `tag_pattern`,
`fields_allowed`, `forbidden_fields`, `forbidden_methods`,
`forbidden_env_export_to_agent`, `url_pattern_regex`, `endpoints`, `org`,
`repo` (singular alias), `cwd_pattern`, `args_constraints`,
`env_vars_to_inject`. The pre-existing tests passed because their fixtures
used a "flat" envelope shape that did not match the real MCP callsite —
PAT-KVD-004 reaffirmed (canonical shapes must be identical between tests
and runtime).

### Security

- **Allowlist enforcer now reads from the canonical MCP envelope's inner
  `args` payload** (D8). All 22 `OperationConstraints` fields have an
  enforcement branch. Any `kvendra.aws.s3_sync` / `cloudfront_invalidate`
  / `lambda_invoke` call against a resource outside the allowlist is now
  rejected with a clear `AllowlistViolation`. Same for
  `kvendra.shell.run` (binaries, cwd, argv templates, env injection),
  `kvendra.git` (refs, tag patterns, repo alias), `kvendra.github`
  (org/owner extraction, fields_allowed, forbidden_fields),
  `kvendra.npm` / `kvendra.pypi` (packages/projects), and
  `kvendra.http.request` (`forbidden_methods`, `endpoints` literal,
  `url_pattern_regex`).
- Closes the security gap that allowed the AC-M2-6 attacker trace
  (`s3://attacker-bucket/...` reaching dispatch on a profile scoped to
  `kvendra-com-prod`) and the symmetric paths through the other 18
  fields. Threat model L2 (data exfil via mis-scoped allowlist) is now
  structurally blocked at the enforcer.

### Added

- `regex` crate use in the enforcer for `url_pattern_regex`,
  `tag_pattern`, and `cwd_pattern` (already a transitive dep — no new
  Cargo dependency).
- New helpers in `src/allowlist/enforcer.rs`: `regex_match`,
  `regex_full_match`, `extract_bucket_from_s3_uri`,
  `extract_owner_from_repo`, `argv_matches_template`.
- D1..D8 decision register documented as module-level doc-comments in
  `enforcer.rs` and as field-level doc-comments in `dsl.rs`.
- `tests/integration_aws_allowlist_boundary.rs` — canonical regression
  smoke for AC-M2-6 with two integration tests
  (`aws_s3_sync_blocks_bucket_outside_allowlist` and
  `aws_cloudfront_invalidate_blocks_distribution_outside_allowlist`).
- ~50 net new in-line tests in `src/allowlist/enforcer.rs::tests` —
  bloque A (3 fields previously enforced, but with the canonical MCP
  envelope shape — PAT-KVD-004), bloque B (one happy + one violation
  per new field), bloque D (defense-in-depth edges: missing inner
  args, denylist precedence, malformed regex, envelope-meta keys not
  visible to `fields_allowed`).

### Caveats

- The `url_pattern_regex` and `tag_pattern` regexes are still
  evaluated at every `tools/call`. Pre-compiling them at YAML load
  time is a follow-up perf optimisation; today's cost is acceptable
  (single allowlist load per call already pays an HMAC verify and a
  YAML parse).
- `args_constraints` template matching is **strict-length** (D2): a
  call with fewer or more argv slots than the template is a no-match.
  Use the `*` wildcard token for any-single-slot, or declare multiple
  templates of different lengths to cover variants.
- `accept_broad_scope` is intentionally **not** enforced at runtime
  (D7) — it remains a validator-time signal only. Operators who want
  broad-scope rejection at YAML load are unaffected; the runtime
  enforcer trusts the validator's previous gate.

## [0.1.0-alpha.9] — 2026-05-07

E2E smoke regression fix uncovered while validating the alpha.7+ bundle
on a clean vault with `master_password_cache: os-keychain`. REQ-008
(alpha.7) introduced HMAC verification in `Config::load`, which in turn
caused every pre-unlock load (`Config::load(home, None)`) to return
`Err("cannot verify")` for any signed `config.toml`. Callers swallowed
the error via `unwrap_or_default()`, reverting **every user-set
preference** (most visibly `master_password_cache: os-keychain`) to the
hard-coded default, silently disabling the REQ-005 keychain fast-path
from alpha.7 onwards. The bug went unnoticed because no automated test
exercised the full `kvendra unlock` subprocess against a vault with
non-default preferences.

### Fixed

- `Config::load(home, None)` now parses signed configs without verifying
  the HMAC trailer (a `tracing::debug!` line records the deferral). The
  post-unlock load (`Config::load(home, Some(&vault))`) still enforces
  the HMAC and the `home_canonical` redirect check, so tampering is
  caught the moment the vault becomes available. Pre-unlock callers can
  read user preferences (`master_password_cache`, `idle_timeout_minutes`)
  from the signed config without hitting the soft-error fallback.
- The `home_canonical` redirect check is now gated on `vault.is_some()`
  for the same reason: pre-unlock the signed value cannot be trusted, so
  the check is deferred to the post-unlock load.

### Added

- Slow integration test `unlock_preserves_user_preferences_from_signed_config`
  in `tests/cli.rs` (gated by `#[ignore]`). Drives a full `init` → `config
  keychain enable` → `unlock` → `config keychain status` subprocess chain
  and asserts that the user's `OsKeychain` preference survives the
  bootstrap path. This is the test that would have caught the regression.

### Notes

- All bundle invariants from REQ-005..008 remain intact: tampered configs
  are still rejected at the post-unlock load (E2 of the smoke), and the
  KVENDRA_HOME-redirect attack is still blocked at the same point (E3).
  The pre-unlock window is best-effort for bootstrap settings and does
  not relax the threat model: an attacker who tampers `master_password_cache`
  to `OsKeychain` cannot read the keychain entry without Touch ID, and
  any tampering of `idle_timeout_minutes` is caught at the post-unlock
  verify before the broker accepts traffic.

## [0.1.0-alpha.8] — 2026-05-07

E2E smoke fix uncovered while validating the alpha.7 bundle on a clean
vault. `kvendra secret set-allowlist <profile> --file <yaml>` returned
`KvendraError::VaultLocked` because the dispatcher invoked the helper
without `ensure_unlocked`. Post-REQ-007 the helper needs the
`kvendra/allowlist-hmac/v1` HKDF sub-key (only available while the
vault is unlocked), so any caller that did not happen to pre-unlock
the vault hit the error. Existing tests exercised
`compute_allowlist_hmac` directly, bypassing the CLI dispatcher and
missing the bug.

### Fixed

- `kvendra secret set-allowlist` now unlocks the vault via the same
  helper used by `add` / `rotate` (env var `KVENDRA_PASSWORD` or
  `--password-stdin`) before computing the HMAC. Behaviour matches
  the documented flow in REQ-KVD-007 and the `set-allowlist` examples
  in the README.

### Added

- New `--password-stdin` flag on `kvendra secret set-allowlist`,
  consistent with the other vault-mutating subcommands.
- Slow integration test `secret_set_allowlist_unlocks_vault_via_env_var`
  in `tests/cli.rs` (gated by `#[ignore]` for CI cost — opt-in via
  `cargo test -- --include-ignored`). Drives the full subprocess
  path that the previous unit tests bypassed.

## [0.1.0-alpha.7] — 2026-05-07

REQ-KVD-008 / ISSUE-KVD-CLI-019 — Config.toml HMAC + `home_canonical` +
`rebind-home` triple-barrier (4/4 of the ROAD-KVD-008 bundle). Closes
GAP 5 (config tampering) and GAP 7 (KVENDRA_HOME redirect) of the L1
threat model. Together with REQ-005..007 the four structural barriers
of the L1 surface are complete.

### Changed

- **`Config::save` signature** now requires `&Vault` (the unlocked vault
  provides the HKDF sub-key for the HMAC trailer). Any caller without an
  unlocked vault gets a clear error pointing at `kvendra unlock`.
- **`Config::load` signature** now takes `vault: Option<&Vault>`. A signed
  `config.toml` (any post-REQ-008 file) requires the vault to verify the
  trailer; passing `None` against a signed file returns a soft error so
  pre-unlock callers (`kvendra unlock` itself, `mcp serve` before unlock)
  can degrade gracefully.

### Added

- HKDF sub-key `kvendra/config-hmac/v1` derived from the unlocked session
  key. Triple-domain separated from `audit-hmac/v1` and `allowlist-hmac/v1`
  — a leak of any one sub-key cannot forge HMACs in either of the other
  two namespaces.
- New trailing field `_hmac` in `~/.kvendra/config.toml` (last line). The
  HMAC-SHA256 covers every preceding TOML byte; any change (including
  whitespace) trips the load-time verify.
- New field `[vault] home_canonical: Option<String>` persisted inside the
  signed payload. Verified on load (both sides canonicalized) — a copy
  of `~/.kvendra/` to a different path no longer passes the loader.
- New subcommand `kvendra config rebind-home --new-path <path>` with
  triple-barrier verification: master password unlock, recovery code
  validation (one-shot), TTY confirmation via re-typed path. Strict
  no-TTY policy (D4=A) — non-interactive invocations are rejected.
- New `KvendraError` variants: `RecoveryCodeAlreadyUsed { slot, used_for,
  used_at }`, `RebindRequiresTty`, `RebindConfirmationMismatch`. The
  pre-existing `RecoveryCodeInvalid` keeps its name but the error
  message is now sharper.
- New canonical audit flags emitted by the new flow:
  `config_tampered_detected`, `home_redirect_detected`, `home_rebound`,
  `recovery_code_replay_attempted`, `config_hmac_migrated`. The first
  three are `error`/`warn` severity; the last two are info-level
  tracing lines.
- New `kvendra::audit::PRIMITIVE_SYSTEM = "kvendra.system"` constant.
  The `home_rebound` audit row uses it (paralleling the existing
  `vault_created` bootstrap row).
- Auto-migration on first unlock post-upgrade. Pre-REQ-008 configs (no
  `_hmac` trailer) are silently re-saved with the trailer + canonical
  home — `kvendra::config::auto_migrate_config_if_needed`. Trust
  caveat: the existing config bytes become the signed baseline.
- Helpers `kvendra::vault::recovery::validate_code_unconsumed` and
  `mark_code_consumed` for the rebind triple-barrier flow.

### Tests

- 23 net new tests for REQ-KVD-008 covering: HMAC determinism + triple-way
  domain separation, save/load round-trip, HMAC mismatch rejection, copy
  attack rejection, attacker-owned-vault forge rejection, modified-home
  rejection, auto-migration silent path, all four rebind barriers
  (master password / recovery code / typed path / no-TTY), recovery
  code replay rejection, audit row schema (primitive + severity + slot
  in flags CSV), and a macOS-only canonicalize sanity test.

### Caveats

- **Editing `~/.kvendra/config.toml` by hand invalidates the HMAC.** The
  supported path is `kvendra config <subcommand>`. A recovery from a bad
  edit is to restore the previous file from backup, or to bootstrap a
  fresh config via the subcommands.
- **Auto-migration is trust-on-first-use.** If the alpha.6 config was
  already tampered with, the migration accepts the tampered bytes as the
  signed baseline. Operators with security-sensitive workloads should
  re-bootstrap their config via the subcommands after upgrading.
- **`rebind-home` consumes one recovery code permanently.** The
  `kvendra config recovery-codes regenerate` subcommand does NOT exist
  in this release — a follow-up ISSUE will land post-release. Plan
  ahead: keep a margin of unused recovery codes if you anticipate
  multiple rebinds (laptop migrations, encrypted-volume moves).
- **`rebind-home` strict no-TTY policy** (D4=A) blocks legitimate
  automation. Workaround: invoke the command in an interactive shell
  on the destination machine.
- **`home_canonical` is semipermanent.** Once stamped, the only way to
  change it is `rebind-home` (which consumes a recovery code). Symlink
  changes to the parent path will trip the load-time check.
- **Linux / WSL canonicalize edge-cases** are tracked as
  `pending-automation:linux-ci-matrix` and
  `pending-automation:wsl-ci-matrix` in the KB. The macOS canonicalize
  invariants are covered by `canonicalize_macos_volumes_and_users_paths`.

## [0.1.0-alpha.6] — 2026-05-07

REQ-KVD-007 / ISSUE-KVD-CLI-018 — Allowlist YAML HMAC + TOCTOU cache fix
(3/4 of ROAD-KVD-008 bundle). Closes GAPs 3 and 4 of the L1 threat model:
out-of-band edits of `~/.kvendra/allowlists/<id>.yaml` are now detected on
every `tools/call`, and the `[a]pprove-all-5min` cache is keyed on the
allowlist's HMAC so any file modification invalidates the cached approval
within the TTL window.

### Changed

- **`ApprovalCache::{lookup, approve, revoke}` signature** now takes
  `ApprovalCacheKey { profile_id, allowlist_hmac_hex }` (struct key)
  instead of `&str`. Internal API — no end-user impact, but cache hits
  now require an exact match on both the profile id and the HMAC of the
  allowlist YAML at the moment the entry was inserted.

### Added

- HKDF sub-key `kvendra/allowlist-hmac/v1` derived from the unlocked
  session key (parallel to `kvendra/audit-hmac/v1`). Domain-separated
  from the audit HMAC, so a leak of one cannot forge the other.
- New field `Profile.allowlist_hmac_hex: Option<String>` persisted in
  `~/.kvendra/profiles/<id>.json`. `#[serde(default)]` keeps profiles
  written by older binaries loadable.
- `kvendra::vault::compute_allowlist_hmac(key, raw_yaml)` — single
  source of truth for the HMAC over the YAML's raw bytes (no
  parse / re-serialize, no whitespace normalization).
- `Vault::allowlist_hmac_key()` accessor.
- `enforce_allowlist` re-computes the HMAC of the YAML on disk and
  compares it against the value stored in the profile meta. Mismatch
  returns `KvendraError::AllowlistTampered(profile_id)` and emits a
  structured tracing log with `flag = "allowlist_tampered_detected"`.
- **JSON-RPC `error_type: "allowlist_tampered"`** distinct from the
  existing `allowlist_violation`. The error data includes a hint
  pointing the operator to `kvendra secret set-allowlist <profile>
  --file <yaml>` or a backup restore.
- New canonical audit flags: `allowlist_tampered_detected` (severity
  `error`, recorded when the HMAC verify fails) and
  `allowlist_hmac_migrated` (info-level tracing line emitted on
  first read of a legacy profile).
- **Auto-migration on first read.** Profiles persisted by an older
  binary load with `allowlist_hmac_hex = None`; the first
  `tools/call` against such a profile signs the current YAML with the
  freshly derived sub-key and writes the HMAC back to the meta.
  Silent — no operator action required. Trust caveat: any tampering
  that occurred before the migration is implicitly accepted as the
  signed baseline. Operators with security-sensitive workloads
  should re-run `kvendra secret set-allowlist` after upgrading to
  rebaseline from a known-good YAML.

### Tests

- 13 new tests for REQ-KVD-007 covering the HMAC determinism /
  domain-separation invariants, the verify path (allow / reject /
  auto-migrate / no-op), the TOCTOU cache fix, audit-chain integrity
  in the presence of an `allowlist_tampered_detected` row, and
  backward-compat of the legacy meta JSON shape.

### Caveats

- Manual editing of `~/.kvendra/allowlists/<id>.yaml` is intentionally
  not supported and will trip `enforce_allowlist`. The supported path
  is `kvendra secret set-allowlist <profile> --file <yaml>`.
- The HMAC is over the file's exact raw bytes — comments, trailing
  whitespace, and line-ending differences all change the signature.

## [0.1.0-alpha.5] — 2026-05-07

REQ-KVD-006 / ISSUE-KVD-CLI-020 closure (2/4 of ROAD-KVD-008 bundle).
Closes the TTY hijack pattern documented in PAT-KVD-007 structurally:
the MCP subprocess no longer touches `/dev/tty` for approval prompts.
CLI commands keep the TTY behaviour. macOS only in this release;
Windows / Linux: `KVENDRA_APPROVAL_MODE=silent` workaround. ADR-KVD-021
documents the transport-based separation pattern (sister of ADR-KVD-020,
extends ADR-KVD-016). Implementation uses `osascript` display dialog;
TouchID-native `LAContext.evaluatePolicy` is a future hardening
drop-in replacement.

### Changed (REQ-KVD-006 / ISSUE-KVD-CLI-020)

- **Approval flow now branches on transport.** `kvendra mcp serve` (MCP
  transport) sends approval prompts to an OS-mediated dialog popup —
  never to `/dev/tty`. CLI commands keep the historical TTY behaviour.
  Closes the TTY-hijack pattern documented in **PAT-KVD-007** structurally:
  no env-var heuristic, just the binary's own subcommand. macOS only in
  this release; Windows / Linux: the broker rejects approval prompts with
  a clear error pointing to the `KVENDRA_APPROVAL_MODE=silent` workaround.
- **`approval::policy::requires_tty` signature**: `requires_tty(mode)` →
  `requires_tty(mode, transport)`. Internal API — no end-user impact.

### Added

- New module `src/approval/transport.rs` with `Transport::{Cli, Mcp}` enum,
  threaded through `mcp::ServerContext` (`Transport::Mcp` from
  `serve_with_vault`).
- New module `src/approval/biometric.rs` with `BiometricApprovalBackend`
  implementing the `ApprovalBackend` trait. Run on `tokio::spawn_blocking`
  to keep the reactor responsive while the OS popup is on-screen.
- `keychain_acl::request_user_presence_only(reason)`. macOS implementation
  shells out to `osascript` to display a native modal dialog (TouchID-
  native `LAContext.evaluatePolicy` is a future hardening). Windows /
  Linux return `BiometricError::Unavailable`.
- 3 new `ApprovalDecision` variants: `BiometricGranted` (cache-warming
  success), `BiometricRejected` (user dismissed the popup; blocks
  dispatch with `error_type = "approval_denied"`), and
  `BiometricUnavailable` (platform without OS popup support; blocks
  dispatch with `error_type = "approval_no_biometric"`).
- 3 new canonical audit flags: `mcp_approval_biometric_granted`,
  `mcp_approval_biometric_rejected`, `mcp_approval_biometric_not_available`.
- Test coverage: 8 net new tests across `approval/transport`, `approval/
  biometric`, `approval/policy`, `keychain_acl/macos`, plus 4 contract
  tests in `tests/approval_integration.rs` for the new variants.

## [0.1.0-alpha.4] — 2026-05-07

REQ-KVD-005 / ISSUE-KVD-CLI-017 closure (1/4 of ROAD-KVD-008 bundle).
Closes GAP 1 + GAP 6 of the L1 threat model on macOS by replacing the
exposed `mcp-password fetch` + wrapper-script pattern with an inline
`--use-keychain` flag gated by `kSecAttrAccessControl(.userPresence)`.
Mitigates the TTY-hijack pattern (PAT-KVD-007) when the broker is
spawned by an IDE/Desktop MCP client. macOS only in this release;
Windows / Linux fall back to the legacy `KVENDRA_MCP_PASSWORD` env var
path until cross-platform hardening lands. ADR-KVD-020 documents the
decision orthogonal to ADR-KVD-012.

### Changed (REQ-KVD-005 / ISSUE-KVD-CLI-017)

- **`kvendra mcp serve --use-keychain`** (new flag, **macOS only**): reads
  the master password from the OS keychain (item `kvendra/mcp-password/v1`
  under service `kvendra`) gated by `kSecAttrAccessControl(.userPresence)`.
  Every read triggers a TouchID popup, or — when biometric hardware is
  absent — the OS modal password popup. The prompt is OS-mediated and
  never touches `/dev/tty`, mitigating the TTY-hijack pattern documented
  in **PAT-KVD-007** when the broker is spawned by an IDE/Desktop MCP
  client (Claude Code, Cursor, ...).
- **`kvendra config mcp-password fetch` removed.** The legacy wrapper
  script (`~/.kvendra/wrappers/kvendra-mcp-serve`) is no longer generated
  by `enable`. Together these eliminate the GAP 1 + GAP 6 surfaces
  identified in the L1 threat model (ADR-KVD-010 V2-extension): an L1
  attacker can no longer obtain the password via `kvendra config
  mcp-password fetch` and cannot substitute the wrapper.
- **`kvendra config mcp-password migrate-to-keychain-acl`** (replaces
  `migrate`): rewrites `~/.claude.json` (and other supported clients) to
  use `command: kvendra` + `args: ["mcp", "serve", "--use-keychain"]`,
  re-saves the keychain entry with `userPresence` ACL, removes any
  leftover wrapper script, and writes a `*.bak.<timestamp>` of the
  original config.
- **Compatibility note:** `--use-keychain` and `enable` /
  `migrate-to-keychain-acl` are **macOS only** in this release. On
  Windows / Linux they reject explicitly to avoid creating a false sense
  of biometric protection (a `keyring`-base item without enforced ACL
  would be readable by any L1 process). Workaround on those platforms:
  continue using the legacy `KVENDRA_MCP_PASSWORD` env var path. Cross-
  platform hardening (Windows Hello, Linux PolKit / `pam`) is tracked in
  ROAD-KVD-008 and will land in a follow-up.

### Added

- New module `src/keychain_acl/` (`mod` + `macos` + `other` stubs)
  exposing `save_with_user_presence` / `read_with_user_presence` /
  `delete` over `service: kvendra`. macOS implementation uses
  `core-foundation` + `security-framework` with
  `SecAccessControlCreateWithFlags(USER_PRESENCE)`.
- `KvendraError::BiometricRejected` and `KvendraError::BiometricUnavailable`
  variants for unambiguous error reporting.
- 6 new integration tests in `tests/cli.rs` covering `fetch` removal,
  `--use-keychain` clap surface, and `--password-env` / `--no-unlock`
  conflict semantics; 3 new unit tests in `cli/config_mcp_password.rs`.

## [0.1.0-alpha.3] — 2026-05-07

ROAD-KVD-007 closure: 5-issue hardening + polish bundle gating AWS
profile habilitation, public marketing, and 0.1.0 stable promotion.
No breaking changes to the YAML allowlist surface (new fields are
`Option<bool>` with `#[serde(default)]`); a previously-valid
`accepts_minimum_valid_profile` legacy fixture had to add
`accept_destructive: true` on `kvendra.git.push` to keep semantics.

### Added

- **ISSUE-KVD-CLI-011** (REQ-KVD-003) — Configurable interactive approval
  layer for `tools/call`. New `src/approval/` module (`mod`, `policy`,
  `cache`, `tty`) with three modes (`silent` / `ask` / `ask-destructive`,
  default `ask-destructive`), env > profile-YAML > config.toml > default
  cascade, ASCII-box prompt to `/dev/tty` (Unix) / `CONIN$+CONOUT$`
  (Windows), in-memory `[a]pprove-all-5min` cache, audit flags
  `approval_granted` / `_denied` / `_timeout` / `_no_tty_denied` /
  `_cache_hit`. New CLI subcommand `kvendra config approval get|set|status`.
  ADRs: KVD-013 (prompt format), KVD-014 (cache storage), KVD-015 (timeout
  default 30s), KVD-016 (silent does NOT require TTY). Closes V7 +
  partially mitigates O1.LLM-auto-approve in the threat model
  (ADR-KVD-010). Tests: 28 (26 unit + 8 integration).
- **ISSUE-KVD-CLI-012** (REQ-KVD-004) — Forbidden methods restrictivos en
  allowlist. New `src/allowlist/catalog.rs` with `const CATALOG: &[DestructiveRule]`
  of 14 owner-ratified entries (e.g. `kvendra.aws.s3_sync` with `delete:true`,
  `kvendra.git.push`, `kvendra.unsafe.raw_token`, etc.) + 4 pure
  `fn(&Value) -> bool` predicates. Validator rejects allowlists with
  destructive ops missing `accept_destructive: true`; `secret validate`
  marks each operation `[⚠ DESTRUCTIVE — owner accepted]` /
  `[⚠ ANNOTATED]` inline. `approval::policy::lookup_destructive` now
  consults the catalog (single source of truth with REQ-003). ADRs:
  KVD-017 (const Rust array), KVD-018 (fn pointer signature), KVD-019
  (print format). Tests: 23 unit. Closes the third structural barrier
  for V7.
- **ISSUE-KVD-CLI-010** (last hardening) — `kvendra config mcp-password
  enable | migrate --client claude-code | status | disable | fetch`. The
  master password no longer needs to live in plaintext under
  `~/.claude.json`: it is stored in the OS keychain via the `keyring`
  crate (`service: kvendra`, `label: kvendra/mcp-password/v1`,
  independent of the `derived-key/v1` namespace from ADR-KVD-012),
  and a wrapper script at `~/.kvendra/wrappers/kvendra-mcp-serve`
  (perms 0700) loads it at spawn time. Closes the V2-extension where
  any process of the same user could read the password from the MCP
  client config.
- **ISSUE-KVD-CLI-014** (REQ-KVD-005 fix B+C) — LLM-friendly tool docs:
  `PrimitiveInfo` gains a multi-line `operations_doc` per catalog entry
  (8 primitives) so `tools/list` returns descriptions enumerating each
  operation's expected `args` shape. `tools/call` now intercepts
  `KvendraError::InvalidArgs` and returns a structured JSON-RPC error
  (`code = INVALID_PARAMS`, `data = { error_type, primitive, operation,
  hint, message }`) so the agent can self-correct without retries.
  Diagnosis from `consultancy-v3` Sesion 3 confirmed H2 as the root
  cause of the AC-MCP-4 retry pattern; option A (one tool per
  operation) was deferred post-Beta to avoid breaking existing allowlists.
- **TEST entries** in KB v3: TEST-KVD-CLI-030 (AC-APPROVAL-6 no TTY),
  TEST-KVD-CLI-031 (AC-APPROVAL-4 timeout), TEST-KVD-CLI-032
  (AC-APPROVAL-3 TTY isolation).

### Fixed

- **ISSUE-KVD-CLI-013** — `kvendra.github.add_topics` now appends
  rather than replacing. The previous implementation called
  `PUT /repos/{owner}/{repo}/topics` directly with the new list, which
  GitHub interprets as a replacement; the new flow GETs the existing
  topics, merges by `merge_topics_unique` (preserves order, deduplicates
  by string value), and then PUTs the merged list. Sister-primitive
  audit (`update_repo`, `update_issue`, `release`, `git.tag` without
  `--force`, `aws.s3_sync` with `delete: true` opt-in) confirmed only
  `add_topics` had this issue. Detected during the AC-MCP-4 write smoke
  on 2026-05-07.

### Changed

- `OperationConstraints` (allowlist DSL) gains two `Option<bool>` fields,
  `destructive` (declarative; from REQ-003) and `accept_destructive`
  (opt-in; from REQ-004). Both default to `None`, so existing
  allowlist YAML files keep parsing without changes — a fixture
  reproducing `~/.kvendra/allowlists/github.kvendraai.cli-readonly.yaml`
  is asserted to keep validating in `validator::tests`.
- `Config` gains an `approval: ApprovalConfig` section with
  `mode: ApprovalMode` (default `AskDestructive`),
  `timeout_seconds: u32` (default 30, validated to `[5, 600]`), and
  `cache_ttl_seconds: u32` (default 300). Existing `config.toml`
  files keep loading without changes (all fields default).
- `JsonRpcResponse::error_with_data(...)` constructor added per JSON-RPC
  2.0 §5.1; consumed by the approval block-dispatch path and by the
  new structured `InvalidArgs` response.
- `mcp::server::tools_call` adds the approval hook between the
  allowlist enforcement and the `Started` audit row. Detection layer
  ordering remains: detection → allowlist → approval → audit
  Started → dispatch.
- `approval::policy::lookup_destructive(spec, primitive, operation, args)`
  signature now takes `args: &Value` so it can consult the catalog at
  approval time with the actual runtime arguments.

### Trace

- ROAD-KVD-007: `in-progress` → `done`.
- TXNs (5): TXN-KVD-20260507-002 / 003 / 004 / 005 / 006.
- Commits in main: `db2b0c5` (011), `413a59b` (012), `c761f8f` (013),
  `400ab41` (014), `4ae7d36` (010), and this version bump on top.
- Suite: 78 → **149 passed** (+71 tests), 0 failed, 1 ignored
  (pre-existing slow Argon2id E2E).
- Threat model V7 (ADR-KVD-010) now has four structural barriers
  (allowlist + forbidden methods + approval + audit) plus the keychain
  pattern for `KVENDRA_MCP_PASSWORD`.

### Out of scope (deferred)

- `cargo publish` real to crates.io. The placeholder `kvendra` v0.0.2
  remains the published artifact until `0.1.0` (no `-alpha` suffix) is
  cut.
- GitHub Releases via cargo-dist binaries — deferred to `0.1.0` stable.
- Promotion to `0.1.0` stable — owner decided 2026-05-07 to keep the
  conservative alpha bump until a final smoke E2E with Claude Code
  confirms the bundle in real use.

## [0.1.0-alpha.2] — 2026-05-07

Cleanup release before Sesion 2 (Claude Code MCP integration). Closes
six open ISSUEs from Sesion 1 owner self-validation. No breaking
changes to the CLI surface.

### Fixed

- **ISSUE-KVD-CLI-002** — `kvendra init` now prompts the master password
  twice (entry + confirmation) with constant-time comparison via
  `subtle::ConstantTimeEq` and up to 3 attempts before aborting. Restores
  AC-VAULT-1 from REQ-KVD-002. Standard pattern for Bitwarden / KeePass
  / age — silent typos no longer survive until the first failed unlock.
- **ISSUE-KVD-CLI-003** — `kvendra init` now bootstraps `~/.kvendra/audit.db`
  with a single `kvendra.system / vault_created` event so forensics can
  anchor the audit chain to vault initialisation rather than the
  filesystem mtime of `audit.db`. Implementation lives in the new
  `audit::bootstrap` module.
- **ISSUE-KVD-CLI-004** — `~/.kvendra/sentinel.blob` is created with
  Unix permissions `0600` (was `0644`). Defence-in-depth on top of
  Argon2id — narrows the offline bruteforce surface from local users.
- **ISSUE-KVD-CLI-005** — `~/.kvendra/config.toml` is created with `0600`
  (was `0644`). Protects `vault.master_password_cache`,
  `idle_timeout_minutes`, and `detection.severity` from local-user
  tampering.
- **ISSUE-KVD-CLI-006** — `~/.kvendra/` and its `secrets/`, `allowlists/`,
  `profiles/` subdirectories are created with `0700` (was `0755`).
  Convention shared with `~/.ssh`, `~/.gnupg`, `~/.password-store`,
  `~/.config/sops`. Other local users can no longer enumerate the vault
  layout.
- **ISSUE-KVD-CLI-008** — `kvendra secret validate` enriches its output
  with (a) inline per-operation constraints (`(repos: ...)`,
  `(refs: ...)`, etc. — walker over all 21 `OperationConstraints`
  fields), (b) a unicode `✓` / `✗` mark next to `VALID` / `REJECTED`,
  and (c) an expiration day delta (`(N days remaining)` /
  `(expires today)` / `(expired N days ago)`). Restores AC-ALLOW-2.

### Added

- `kvendra::config::create_dir_secure(path)` — public helper that
  `mkdir -p` plus tightens directory perms to `0700` on Unix.
- `kvendra::config::set_file_mode_secure(path)` — public helper that
  tightens an existing file to `0600` on Unix (no-op elsewhere).
- `kvendra::audit::bootstrap::write_vault_created_event(...)` — emits
  the initial audit row referencing `env!("CARGO_PKG_VERSION")`.
- Unit tests for `cli::init::passwords_match`, `cli::secret::format_constraints`,
  `cli::secret::format_expiration` (5 new tests). Integration test
  `tests/security_and_audit.rs::kvendra_home_perms_are_0700_and_files_are_0600`
  covers home + 3 subdirs + sentinel + config + profile blob + profile
  meta in a single Unix run. Integration test
  `tests/security_and_audit.rs::vault_created_event_persisted_after_init_bootstrap`
  covers the new audit bootstrap.

### Changed

- `cli::init` and `cli::secret::set-allowlist` now route their write
  paths through the new `create_dir_secure` / `set_file_mode_secure`
  helpers; the inline `#[cfg(unix)] PermissionsExt` blocks have been
  removed from the call sites.
- `Vault::create_with_params`, `Vault::reset_password_with_mnemonic`,
  `Vault::save_profile_meta`, and `Vault::put_secret` apply
  `set_file_mode_secure` after every sensitive `fs::write`, so the
  defence-in-depth invariant holds regardless of which entry point
  created the file.

## [0.1.0-alpha.1] — 2026-05-06

Initial Alpha 0.1 MVP release. First real published version of the
Kvendra developer harness CLI.

### Added

- Vault subsystem (`vault/`) with Argon2id KDF, AES-256-GCM AEAD, BIP-39
  mnemonic + 8 numeric one-shot recovery codes, sentinel + session key
  with HKDF-derived audit sub-key.
- 7 canonical MCP primitives + 1 escape hatch (`kvendra.git`,
  `kvendra.github`, `kvendra.npm`, `kvendra.pypi`, `kvendra.aws`,
  `kvendra.http`, `kvendra.shell`, `kvendra.unsafe.raw_token`) wired
  through a sanitising MCP server (`mcp::server::build_sanitized_payload`).
- Allowlist DSL (YAML) + restrictive validator + enforcer.
- Audit log: SQLite (rusqlite bundled, WAL mode) with HMAC-SHA256 chain.
  `audit verify --password-stdin` re-derives the HMAC sub-key
  cross-process from the master password.
- TUI (gated by feature `tui`, default on): dashboard + audit watch.
- Detection layer with `warn` / `error` / `block` severities.
- CLI surface (clap derive): `init`, `unlock`, `lock`, `secret`,
  `primitive`, `mcp serve`, `dashboard`, `audit`, `config`,
  `completion`.
- Cross-platform OS keychain integration (`keyring 3.x`).
- THREAT-MODEL.md (Nivel 2 zero-knowledge target).
- CI matrix workflow.

### Notes

- This release was bundled as `KvendraAI/kvendra-cli` HEAD `9e972dc`.
- The placeholder `kvendra` v0.0.2 on crates.io stays as the published
  artifact until `0.1.0` (no `-alpha` / `-beta`) is cut.
