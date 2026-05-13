# Manual de Kvendra CLI

Manual técnico y funcional del binario `kvendra` (Rust, Apache-2.0). Cubre qué resuelve el producto, cómo se usa en el día a día y qué hay debajo del capó: criptografía, MCP capability broker, primitives, allowlist, audit log y threat model.

Audiencia interna del equipo Kvendra. Versión documentada: `0.1.0` stable (release `REL-KVD-CLI-0.1.0`, 2026-05-08).

## Índice

### Bloque 0 — Punto de partida

1. [Introducción](./01-introduccion.md) — qué es Kvendra CLI, problema que resuelve, audiencia objetivo, qué hay y qué no en `0.1.0`.
2. [Mental model](./02-mental-model.md) — capability-based security en tres minutos. Por qué el agente nunca recibe el plaintext del token.

### Parte I — Funcional

3. [Instalación](./03-instalacion.md) — `cargo install kvendra`, GitHub Releases, requisitos por sistema operativo.
4. [Bootstrap del vault](./04-bootstrap-vault.md) — `kvendra init`: master password, recovery phrase BIP-39, recovery codes.
5. [Gestión de secretos y profiles](./05-gestion-secretos.md) — `secret add/list/rotate/revoke/export/import/validate`.
6. [Uso vía MCP con agentes](./06-uso-mcp-con-agentes.md) — configuración Claude Code, Cursor, Cline; `kvendra mcp serve`.
7. [Allowlist DSL](./07-allowlist-dsl.md) — YAML por profile, defaults restrictivos, ejemplos por servicio.
8. [Audit log](./08-audit-log.md) — `kvendra audit` (TUI / `--json` / `--verify`), HMAC chain, troubleshooting.
9. [TUI dashboard](./09-tui-dashboard.md) — `kvendra dashboard`, `kvendra audit --watch`.
10. [Recuperación](./10-recuperacion.md) — olvido de master password, recovery codes, regeneración.

### Parte II — Técnica

11. [Arquitectura](./11-arquitectura.md) — módulos Rust, capas, flujo end-to-end de una invocation MCP.
12. [Vault y criptografía](./12-vault-criptografia.md) — Argon2id, AES-256-GCM, layout de blobs, dominio HKDF.
13. [Servidor MCP](./13-mcp-server.md) — JSON-RPC 2.0 stdio, `tools/list`, `tools/call`, sanitización canónica.
14. [Primitives](./14-primitives.md) — las 7 canónicas + escape hatch, schemas, error model, audit hooks.
15. [Allowlist enforcer](./15-allowlist-enforcer.md) — 22/22 fields runtime, helper TIER 0, validator vs enforcer.
16. [Detection layer](./16-detection-layer.md) — patterns canónicos, severidades workspace, integración pipeline.
17. [Audit internals](./17-audit-internals.md) — SQLite WAL, HMAC chain, sub-key HKDF, `audit verify` cross-process.
18. [Threat model](./18-threat-model.md) — Nivel 2 zero-knowledge formal, vectores cubiertos vs aceptados.
19. [Stack técnico](./19-stack-tecnico.md) — crates y versiones, features Cargo, MSRV.

### Bloque final — Contexto y referencia

20. [Roadmap](./20-roadmap.md) — `0.1.0` done, `0.2.0` Mac compatible, `0.3.0` Windows + Linux signing.
21. [Licencia Open Core](./21-licencia-open-core.md) — Apache-2.0 vs AGPL platform vs Enterprise closed.
22. [FAQ y troubleshooting](./22-faq-troubleshooting.md) — patterns conocidos (idle_timeout, restart Claude Code), errores comunes.

---

## Audiencia

Equipo Kvendra (founder + colaboradores futuros). Documento `internal`: vive en este repo pero no se publica todavía en el doc-portal externo. Sirve como referencia para entender qué entrega el `0.1.0` antes de redactar guías públicas en `kvendra.com/docs`.

## Prerrequisitos

Para entender el manual completo:

- Familiaridad con la línea de comandos en macOS, Linux o Windows.
- Conceptos básicos de criptografía simétrica (AES-GCM, KDF) — opcionales pero útiles para la Parte II.
- Conocer qué es MCP (Model Context Protocol) o estar dispuesto a leer la introducción del [capítulo 13](./13-mcp-server.md).
- Acceso al KB v3 (`PRJ-KVD`) para profundizar en entidades referenciadas (`REQ-*`, `ADR-*`, `IF-*`, `PAT-*`, `GLO-*`).

## Documentación relacionada

Otras fuentes en este repo y en KB v3:

- `docs/install.md` — guía corta de instalación cross-platform sin firma de código.
- `docs/security.md` — disclosure y reporting policy (RFC 9116 en `SECURITY.md`).
- `docs/smoke.md` — harness E2E (`scripts/e2e-smoke.sh`).
- `THREAT-MODEL.md` — versión canónica del threat model en root del repo.
- `CHANGELOG.md` — historial completo de cambios alpha.1 → 0.1.0.
- KB v3: `CMP-KVD-CLI`, `REQ-KVD-002`, `REQ-KVD-CLI-001..003`, `ROAD-KVD-005`, `ROAD-KVD-CLI-001`, `ADR-KVD-004/010/022`, `IF-KVD-CLI-001..008`, `PAT-KVD-003`, `GLO-KVD-001..011`.

---

*Última actualización: 2026-05-10*
