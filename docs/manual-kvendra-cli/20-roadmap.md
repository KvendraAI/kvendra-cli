# 20. Roadmap

## Descripción

Estado real del producto Kvendra CLI a fecha de redacción de este manual (2026-05-10) y previsión de las siguientes versiones. Las roadmaps formales viven en KB v3 (`ROAD-KVD-CLI-001` cerrado, `ROAD-KVD-CLI-002` planificado). Este capítulo es una vista narrada de qué hay hoy, qué llega y qué queda explícitamente fuera por ahora.

## Versión actual: `0.1.0` stable

**Tag**: `v0.1.0` en `KvendraAI/kvendra-cli`. Push: 2026-05-08. Release entity: `REL-KVD-CLI-0.1.0` en KB v3.

Lo que `0.1.0` entrega ya está descrito en el [capítulo 1](./01-introduccion.md). Resumen:

> **Vault local zero-knowledge** Nivel 2 con Argon2id + AES-256-GCM.
>
> **MCP capability broker** stdio con JSON-RPC 2.0.
>
> **7 primitives canónicas + 1 escape hatch documentado.**
>
> **Allowlist DSL declarativo** con 22/22 fields runtime-enforced.
>
> **Audit log SQLite WAL HMAC-chain** con verificación cross-process.
>
> **Detection layer** con patterns canónicos y severidades workspace.
>
> **TUI** dashboard + audit watch.
>
> **Threat model Nivel 2** formal con 4 GAPs L1 cerrados estructuralmente.

### `ROAD-KVD-CLI-001` — closed 2026-05-08

Bundle del path to `0.1.0`:

> Multi-platform CLI sin code-signing.
>
> Smoke harness E2E (`scripts/e2e-smoke.sh` + `docs/smoke.md`).
>
> Polish bundle alpha.11 (audit log canonicalization + recovery codes regenerate).
>
> Distribution docs cross-platform (`docs/install.md`).
>
> Apple Developer ID **NO** es blocker — el approval gate funciona sin él (PAT-KVD-CLI-001).

## Próxima versión: `0.2.0` — Mac compatible

**Track**: `ROAD-KVD-CLI-002` (planned). Paralela, no bloqueante para `0.1.0`.

Goals:

> **Apple Developer ID** + Touch ID + signing pipeline.
>
> **Notarization** del binario macOS para evitar el modal "developer cannot be verified".
>
> **Homebrew formula** como canonical install path para Mac signed.
>
> **Touch ID-protected MCP password** marketing (el approval gate ya soporta keychain ACL `userPresence`; `0.2.0` lo formaliza con Apple Dev ID).

ISSUEs movidos desde `ROAD-CLI-001` a `ROAD-CLI-002`:

- `ISSUE-KVD-CLI-028` (Touch ID ACL — Apple Dev ID gated)
- `ISSUE-KVD-CLI-034` (entitlements file)
- `ISSUE-KVD-CLI-035` (CI codesign+notarize)
- `ISSUE-KVD-CLI-036` (distribution docs Mac-signed canonical)

Estimación: ~3-6 semanas de elapsed time (gating real es Apple Dev ID enrollment, no esfuerzo de eng).

## `0.3.0` — Windows + Linux signing

**Track**: `ROAD-KVD-CLI-003` (futuro, sin fecha).

Goals:

> **Windows Authenticode** signing.
>
> **Linux GPG** signing + reproducible builds.
>
> **winget manifest** PR a `microsoft/winget-pkgs`.
>
> **Linux distros canonical**: AUR, Snap, Flatpak (community-maintained packaging).

## Versiones futuras (post-stable line)

### Cloud sync (Pro tier)

`ROAD-KVD-005` cubre el cloud mode opt-in para Pro tier:

> **S3-backed encrypted vault sync** entre máquinas del mismo usuario.
>
> El plaintext jamás cruza la red — los blobs se suben ya cifrados con la derived key local.
>
> Hosted en `kvendra-platform` (AGPL-3.0).

### Marketplace de primitives

`ROAD-KVD-005` P2.x:

> **Community-contributed primitives** (`kvendra.linear`, `kvendra.notion`, `kvendra.discord`, etc.).
>
> Pipeline: PR → security review → versioned + signed → `kvendra primitive install <name>`.
>
> Repo `kvendra-skills` (Apache-2.0).

### Workspaces multi-user (Team tier)

> **RBAC** dentro de un workspace.
>
> **Audit dashboard cross-machine** consolidado.
>
> **Policy enforcement** cross-machine (severidad detection layer org-wide).

### Enterprise tier

> **SSO / SAML** integration.
>
> **Nitro Enclaves cloud mode** (Nivel 3 zero-knowledge real — plaintext jamás cruza memory de Lambda en claro, attestation verificable client-side).
>
> **Compliance reports** (SOC 2 Type II, ISO 27001, HIPAA).
>
> **`kvendra-enterprise`** repo privado con features closed source justificadas (`ADR-KVD-004`).

### Otras tracks identificadas

> **Hardware-backed wrapping** (Secure Enclave / TPM 2.0 / Yubikey FIDO2) — cierra vector O1. Diferido post-MVP.
>
> **Pre-commit hook `kvendra git secret-scan`** — detection layer extension.
>
> **Desktop app** — solo si demanda Team/Enterprise lo justifica. No es killer feature.

## Versiones recientes (CHANGELOG resumen)

Para historial completo, ver `CHANGELOG.md` en root del repo.

| Versión | Fecha | Highlights |
|---------|-------|-----------|
| `0.1.0` | 2026-05-08 | First stable. Multi-platform unsigned. Bundle ROAD-KVD-008 complete (4/4 GAPs L1 cerrados). |
| `0.1.0-alpha.11` | 2026-05-08 | Polish bundle: audit canonicalization + recovery codes regenerate + smoke harness. |
| `0.1.0-alpha.10` | 2026-05-08 | **SECURITY/HIGH fix** ISSUE-KVD-CLI-032: 22/22 allowlist fields runtime enforced (pre-fix: 0/22 effective). Tests 204→256. |
| `0.1.0-alpha.7` | 2026-05-07 | Bundle ROAD-008 complete: GAP_5 + GAP_7 cerrados (config.toml HMAC + home_canonical signed). |
| `0.1.0-alpha.6` | 2026-05-06 | GAP_4 cerrado (allowlist HMAC + TOCTOU cache fix). |
| `0.1.0-alpha.5` | 2026-05-05 | GAP_3 cerrado (transport-based approval CLI=TTY MCP=biometric). |
| `0.1.0-alpha.4` | 2026-05-04 | GAP_1 + GAP_2 cerrados (mcp-password keychain ACL + wrapper eliminated). |
| `0.1.0-alpha.1` | 2026-05-06 | Primer release real (post placeholder `0.0.2`). MVP CLI completo en bruto. |

## Política de versionado

- **`0.1.x`** patches: bug fixes y security patches sin cambios en superficie pública del MCP. No cambian schemas de `tools/list` ni shape de allowlist YAML.
- **`0.2.0`**: cambios en infraestructura (signing) sin breaking changes en API.
- **`0.x.0`** mayor: posible breaking. Se documenta migration path.

## Política de soporte

- **Versión actual stable** (`0.1.x`) — soporte completo.
- **Versiones alpha** — best-effort. Se anima a actualizar a `0.1.0`+.
- **Pre-stable (`0.0.x`)** — no soporte; eran placeholders de namespace.

## Entrada al proyecto para colaboradores

Repos relevantes:

| Repo | Licencia | Para qué |
|------|----------|----------|
| `KvendraAI/kvendra-cli` | Apache-2.0 | Este binario — código del CLI |
| `KvendraAI/kvendra-platform` | AGPL-3.0 | Server cloud (cuando exista) |
| `KvendraAI/kvendra-skills` | Apache-2.0 | Marketplace de primitives community |
| `KvendraAI/kvendra-helm` | Apache-2.0 | Helm chart self-host |
| `KvendraAI/kvendra-web` | MIT | Landing y docs portal |

Política de contribuciones inicial: **DCO (Developer Certificate of Origin)** — cada commit signed-off. CLA queda diferido (`ADR-KVD-004`).

## Notas importantes

> **Nota:** Las versiones publicadas en crates.io son **inmutables**. `cargo publish kvendra 0.1.0` solo puede hacerse una vez. Si descubres un bug crítico tras publish, la ruta es `0.1.1` con el fix — no es posible re-publicar `0.1.0`. Solo `cargo yank` (deprecación), nunca borrado.

> **Advertencia:** El roadmap es vivo. Las prioridades pueden cambiar según señales del owner (consultancy-v3 sessions) y del cluster competidor. `ROAD-KVD-CLI-002` está **planned** pero no fechado — el gating es Apple Dev ID enrollment, que tiene elapsed time variable. Para timeline operacional real, consulta el KB v3.
