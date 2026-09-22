# 1. Introducción

## Descripción

**Kvendra CLI** (`kvendra`) es un binario Rust único que actúa como **MCP capability broker con vault zero-knowledge local** entre un agente de IA (Claude Code, Cursor, Cline, Continue, …) y los servicios externos donde ese agente necesita ejecutar operaciones reales: GitHub, npm, PyPI, AWS, registries privados, scripts del sistema.

La promesa central es sencilla de enunciar: **el agente nunca recibe el plaintext de las credenciales**. En su lugar, invoca *primitives* MCP del estilo `kvendra.<servicio>.<acción>(profile_id, args)`. El binario `kvendra` resuelve el secret asociado al `profile_id` desde un vault local cifrado, valida la operación contra una *allowlist* declarativa específica del profile, ejecuta la acción contra el servicio externo y devuelve únicamente el resultado al agente.

## Problema que resuelve

Hoy, un developer que usa un agente de IA tiene tres malas opciones para que ese agente actúe sobre sus servicios externos:

> **Opción A:** pegar el token en el chat o en un fichero del workspace
>
> Riesgo: el plaintext queda en el contexto del LLM, en logs del cliente, posiblemente en backends de terceros. Rotación obligatoria tras cada sesión.
>
> **Opción B:** exportar el token como variable de entorno (`export GITHUB_TOKEN=ghp_…`)
>
> Riesgo: cualquier subproceso lanzado por el agente lo hereda. Difícil de auditar. Persistente entre sesiones de shell. Visible en `ps eww` y `/proc/<pid>/environ`.
>
> **Opción C:** prohibir al agente actuar en servicios externos
>
> Coste: mata gran parte del valor del asistente.

Kvendra CLI introduce una cuarta opción: **capability binding por profile**. El agente recibe la capacidad de ejecutar *operaciones acotadas* (no el token), y cada invocación queda registrada en un audit log local con HMAC chain inmutable.

## Para quién es

- **Developers** que usan agentes de IA y quieren que esos agentes ejecuten `git push`, `aws s3 sync`, `npm publish`, `gh release create` y similares — sin pegar tokens en el chat.
- **Founders y equipos pequeños** que aún no tienen Vault corporativo ni HSM, pero quieren disciplina de capabilities desde el día uno.
- **Auditors** y reviewers externos: el código del CLI es Apache-2.0 y todo el path criptográfico es revisable en una sesión razonable.

No es para usuarios *no-CLI*. La Desktop app está deliberadamente diferida (ver [capítulo 20](./20-roadmap.md)).

## Qué entrega Kvendra CLI hoy (0.6.4)

> **Nota de versión:** la versión actual publicada en crates.io es **0.6.4**. El producto está en fase **Alpha**: la base es sólida y en uso real, pero la superficie sigue evolucionando entre minor versions. La cadena shipped desde `0.1.0` es: `0.1.0` (primera release del broker) → `0.4.x` (cross-platform, Pro tier, `capabilities`) → `0.5.0` (`kvendra capabilities`) → `0.6.0` (break-glass, [capítulo 23](./23-break-glass.md)) → `0.6.2` (audit v3: export firmado PDF/CSV/JSON) → **`0.6.4` (security hardening tras auditoría externa de Salva Ferrer; ver capítulos [15](./15-allowlist-enforcer.md), [16](./16-detection-layer.md) y [18](./18-threat-model.md))**.

Resumen ejecutivo de lo que un usuario real puede hacer hoy:

> **Vault local zero-knowledge:**
> - **KDF:** Argon2id, cost ≥1 s/intento.
> - **AEAD:** AES-256-GCM por blob.
> - **Storage:** `~/.kvendra/secrets/<profile_id>.blob`.
> - **Master password** jamás persiste; la derived key vive solo en RAM mientras la sesión está unlocked.
>
> **MCP capability broker:**
> - JSON-RPC 2.0 sobre stdio, compatible con Claude Code, Cursor, Cline, Continue.
> - 7 primitives canónicas (`kvendra.git`, `kvendra.github`, `kvendra.npm`, `kvendra.pypi`, `kvendra.aws`, `kvendra.http`, `kvendra.shell`) + 1 escape hatch documentado (`kvendra.unsafe.raw_token`).
> - Sanitización recursiva del payload de respuesta antes de devolverlo al agente.
>
> **Allowlist DSL declarativo:**
> - Modelo por capas (TIER 0-4) sobre las 22 fields del DSL, validadas en runtime por `allowlist::enforcer`. En 0.6.4 se cerró **fail-closed** la última familia de fields que aún quedaban no-op; los detalles y la historia están en el [capítulo 15](./15-allowlist-enforcer.md).
> - Defaults restrictivos: `methods: []` o un `url_pattern_regex` de scope amplio se rechazan al firmar el allowlist salvo `accept_broad_scope: true` explícito en el YAML.
> - HMAC sidecar `~/.kvendra/allowlists/<profile_id>.yaml.hmac` (sub-key `kvendra/allowlist-hmac/v1`).
>
> **Audit log:**
> - SQLite WAL en `~/.kvendra/audit.db` con HMAC chain (sub-key `kvendra/audit-hmac/v1`).
> - `kvendra audit --verify` valida la cadena cross-process; `kvendra audit export` genera un bundle firmado (PDF + CSV + JSON canónico) verificable con `kvendra audit verify-export`.
>
> **Detection layer:**
> - Patterns regex + heurística de entropía sobre input/output del agente.
> - Severidad workspace `warn | error | block`.
>
> **TUI:**
> - `kvendra dashboard` (vista global) y `kvendra audit --watch` (live tail).
> - Feature Cargo `tui` (default-on); puede compilarse headless desactivándola.
>
> **Manifest de capabilities (v0.5.0):**
> - `kvendra capabilities [--pretty]` emite el manifest canónico del broker en JSON (read-only, auth-less). Lo consume `kvendra-skills`. Inspección de primitives con `kvendra primitive list` / `kvendra primitive info <name>`.
>
> **Break-glass (v0.6.0):**
> - `kvendra bypass` / `protect` / `grant-pubkey` / `verify-grant` — relajación firmada, acotada y con TTL del enforcement del hook `kvendra-skills`. Cubierto en el [capítulo 23](./23-break-glass.md).
>
> **Backup cloud (Pro tier):**
> - `kvendra backup push/list/pull/restore/prune` cifra el vault en cliente y lo sube a Kvendra cloud. Es hoy el **camino de recuperación recomendado** (ver [capítulo 10](./10-recuperacion.md)).
>
> **Modelo de sesión cross-platform:**
> - `kvendra unlock` corre en tu terminal (nunca dentro del cliente MCP) y escribe `~/.kvendra/sessions/active.blob` machine-bound (hostname+uid+ruta) con TTL (default 4h); cada `kvendra mcp serve` lo lee. `kvendra unlock --extend` refresca el TTL **re-autenticando** con la master password (0.6.4, finding A1).

## Qué NO entrega 0.6.4

Para evitar expectativas mal alineadas:

- **No hay sync cross-device en vivo.** Tu vault vive en una máquina. Para replicarlo (o recuperarlo) existe `kvendra backup` (Pro tier), pero no es un sync multi-máquina en tiempo real: es push/pull explícito.
- **No hay Desktop app.** Sólo CLI + TUI. Ver decisión en `ROAD-KVD-005`.
- **No hay marketplace público de primitives.** Las 7 primitives canónicas son las que mantiene el core team. La extensibilidad community sigue siendo post-MVP.
- **No hay hardware-backed wrapping** (Secure Enclave, TPM 2.0, FIDO2) todavía. El sub-vector O1 (RAM dump durante sesión unlocked) está documentado como aceptado en el [threat model](./18-threat-model.md); el wrapping hardware-backed es la **Fase 1** del roadmap de endurecimiento del vault (`ROAD-KVD-CLI-393064`, ver [capítulo 20](./20-roadmap.md)).
- **La recuperación por mnemónica BIP-39 está temporalmente fail-closed** en 0.6.4: `kvendra recover` existe pero rechaza; el camino de recuperación real es `kvendra backup` (ver [capítulo 10](./10-recuperacion.md)).

## Cómo se relaciona con el resto del producto Kvendra

Kvendra CLI es **la concretion de `ROAD-KVD-005`** (Capability Broker MCP) sobre el modelo de **`ROAD-KVD-004`** (Secrets Vault zero-knowledge). Es una pieza más del producto, junto con `kvendra-skills` (el plugin de skills que consume `kvendra capabilities`), la Kvendra KB y el backend Enterprise.

> **El CLI es opcional.** No es obligatorio ni en Pro ni en self-hosted: un tenant puede operar el broker y las skills sin instalar el binario `kvendra`. El CLI es la vía local-first para gestionar el vault, servir el broker MCP en tu máquina y auditar.

A futuro (opt-in, sin tocar el default local-first):

- Modos cloud avanzados: credenciales efímeras, server-assist y broker remoto son fases del roadmap de endurecimiento del vault (`ROAD-KVD-CLI-393064`, ver [capítulo 20](./20-roadmap.md)).

El boundary Open Core entre CLI / platform / Enterprise está fijado en `ADR-KVD-004` ([capítulo 21](./21-licencia-open-core.md)).

## Notas importantes

> **Nota:** El binario es `kvendra` (lowercase). El package crates.io también es `kvendra`. La org GitHub es `KvendraAI`. El handle social unificado es `kvendraai`. Estas asimetrías están documentadas en `DOC-KVD-001` y son convención del proyecto.

> **Advertencia:** Kvendra CLI está en fase **Alpha**. La base criptográfica (Argon2id, AES-256-GCM, ed25519, PKCE) es sólida y el binario está en uso real, pero la superficie sigue evolucionando entre minor versions con migración automática de la metadata de `~/.kvendra/`. Las 7 primitives canónicas y el shape de sus argumentos se mantienen estables; los cambios de 0.6.4 fueron de **endurecimiento de seguridad** (cerrar fail-closed la capa de autorización), no breaking del contrato MCP. Ver capítulos [15](./15-allowlist-enforcer.md), [16](./16-detection-layer.md) y [18](./18-threat-model.md).
