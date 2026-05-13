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

## Qué entrega `0.1.0` stable

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
> - 22 fields runtime-enforced, ninguno no-op.
> - Defaults restrictivos: `methods: []` o `url_pattern_regex: ".*"` se rechazan en setup salvo `--accept-broad-scope` explícito.
> - HMAC sidecar `~/.kvendra/allowlists/<profile_id>.yaml.hmac` (sub-key `kvendra/allowlist-hmac/v1`).
>
> **Audit log:**
> - SQLite WAL en `~/.kvendra/audit.db` con HMAC chain (sub-key `kvendra/audit-hmac/v1`).
> - `kvendra audit --verify` valida la cadena cross-process.
>
> **Detection layer:**
> - Patterns regex + heurística de entropía sobre input/output del agente.
> - Severidad workspace `warn | error | block`.
>
> **TUI:**
> - `kvendra dashboard` (vista global) y `kvendra audit --watch` (live tail).
> - Feature Cargo `tui` (default-on); puede compilarse headless desactivándola.

## Qué NO entrega `0.1.0`

Para evitar expectativas mal alineadas:

- **No hay sync cross-device.** Tu vault vive en una máquina. Si necesitas el mismo vault en laptop + desktop, lo gestionas manualmente — el sync server-side es Pro tier (post-MVP).
- **No hay Desktop app.** Sólo CLI + TUI. Ver decisión en `ROAD-KVD-005`.
- **No hay binarios firmados con Apple Developer ID** todavía. La instalación en macOS pasa por `cargo install` o por aceptar el binario unsigned. La track de signing es `ROAD-KVD-CLI-002` (`0.2.0` Mac compatible).
- **No hay marketplace público de primitives.** Las 7 primitives canónicas son las que mantiene el core team. La extensibilidad community es post-MVP.
- **No hay hardware-backed wrapping** (Secure Enclave, TPM 2.0, Yubikey FIDO2). El sub-vector O1 (RAM dump durante sesión unlocked) está documentado como aceptado en el [threat model](./18-threat-model.md).

## Cómo se relaciona con el resto del producto Kvendra

Kvendra CLI es una de las dos piezas con código real hoy en el producto Kvendra (la otra es `kvendra-web`, el sitio público). Es **la concretion de `ROAD-KVD-005`** (Capability Broker MCP) sobre el modelo de **`ROAD-KVD-004`** (Secrets Vault zero-knowledge).

A futuro:

- `kvendra-platform` (AGPL-3.0) añadirá modos cloud opt-in: sync, multi-user, audit dashboard cross-machine.
- `kvendra-skills` (Apache-2.0) será el marketplace de primitives community-contributed.
- `kvendra-helm` permitirá self-host de la plataforma para clientes Enterprise.

El boundary Open Core entre CLI / platform / Enterprise está fijado en `ADR-KVD-004` ([capítulo 21](./21-licencia-open-core.md)).

## Notas importantes

> **Nota:** El binario es `kvendra` (lowercase). El package crates.io también es `kvendra`. La org GitHub es `KvendraAI`. El handle social unificado es `kvendraai`. Estas asimetrías están documentadas en `DOC-KVD-001` y son convención del proyecto.

> **Advertencia:** El `0.1.0` de Kvendra CLI es la **primera release estable** del producto, pero el producto entero sigue siendo joven. La superficie pública del MCP (las primitives, el shape de los argumentos) está congelada para `0.1.x`; cualquier cambio breaking iría a `0.2.0`. La superficie *interna* del KB v3 y de la metadata de `~/.kvendra/` puede evolucionar entre minor versions con migración automática.
