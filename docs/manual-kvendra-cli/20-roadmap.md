# 20. Roadmap

## Descripción

Estado real del producto Kvendra CLI a fecha `2026-09-15` y previsión de las siguientes versiones. Las roadmaps formales viven en el Kvendra KB. Este capítulo es una vista narrada de qué hay hoy, qué llega y qué queda explícitamente fuera por ahora.

> **Nota:** la roadmap forward de `0.6.x` en adelante es un único hilo: **el endurecimiento del vault por capas**, formalizado en `ROAD-KVD-CLI-393064` (ejecuta `ADR-KVD-CLI-64CD49`). Todo lo que llega es **opt-in**; el nivel por defecto se queda en `basic` para no bloquear a nadie al arrancar (ver `../security/protection-levels.md`).

## Versión actual: `0.6.4`

**Tag**: `v0.6.4` en `KvendraAI/kvendra-cli`. Es una release de **security hardening** tras una auditoría estática externa (**Salva Ferrer**, avtn.es) sobre `0.6.3` + pentest interno. La base criptográfica (Argon2id, AES-256-GCM, firma ed25519 de grants, OAuth PKCE) se confirmó sólida; los defectos explotables eran **caminos fail-open de la capa de autorización**, todos cerrados fail-closed en `0.6.4`. Detalle en `../security/advisory-cli-0.6.4.md` y en el [capítulo 18](./18-threat-model.md).

Lo que `0.6.4` entrega, resumido:

> **Vault local zero-knowledge** Nivel 2 con Argon2id (64 MiB / t3 / p1) + AES-256-GCM.
>
> **MCP capability broker** stdio con JSON-RPC 2.0, enforcement **fail-closed**.
>
> **7 primitives canónicas + 1 escape hatch documentado** (`kvendra.unsafe.raw_token`, con cuota por sesión).
>
> **Allowlist DSL declarativo** runtime-enforced con resolución real del payload interno.
>
> **Audit log SQLite WAL HMAC-chain** (schema v3: `error_code` + `error_message`) con verificación cross-process.
>
> **Detection layer** con patterns canónicos y severidades por workspace.
>
> **Break-glass** firmado ed25519 (`bypass`/`protect`/`grant-pubkey`/`verify-grant`) — ver [capítulo 23](./23-break-glass.md).
>
> **Modo workspace / Pro tier**: OIDC PKCE, `kvendra backup` (cloud) y `kvendra capabilities`.
>
> **TUI** dashboard + audit watch.

## Cadena de releases shipped (`0.1.0` → `0.6.4`)

| Versión | Highlights |
|---------|-----------|
| `0.1.0` | Primer stable. Vault local zero-knowledge, MCP broker stdio, 7 primitives + escape hatch, allowlist DSL, audit log HMAC-chain, detection layer, TUI. Threat model Nivel 2 con los 4 GAPs L1 cerrados estructuralmente. Multi-plataforma **sin** code-signing. |
| `0.4.x` | **Cross-platform** consolidado (macOS arm64/x86_64, Linux x86_64, Windows x86_64) + **Pro tier**: modo workspace OIDC PKCE, `kvendra login --pro`, `kvendra backup` (push/list/pull/restore/prune). |
| `0.5.0` | `kvendra capabilities [--pretty]` — manifest canónico del broker en JSON, read-only y auth-less, consumido por `kvendra-skills` (`REQ-KVD-ECDAE9`). |
| `0.6.0` | **Break-glass** (`REQ-KVD-SKILLS-41032D`): 4 subcomandos del binario que relajan, firmado y con TTL, el enforcement del hook `kvendra-skills`. Firma ed25519 (`ed25519-dalek 2`), grant canonicalizado con JCS (`serde_jcs`). |
| `0.6.2` | **Audit v3**: columnas `error_code` (taxonomía cerrada) + `error_message` (sanitizado), ambas commit al HMAC chain. Migración idempotente lazy on-startup. |
| `0.6.4` | **Security hardening** tras auditoría externa + pentest: familia de bugs fail-open de la capa de autorización cerrada fail-closed (C1/C2/C4/H2/H4/H5…), integridad de `config.toml`/allowlist ahora **rechazo** ante tamper, `unlock --extend` re-autentica, `npm publish --ignore-scripts`, línea JSON-RPC malformada ya no mata el serve loop. |

Para el historial `pre-0.1.0` (alphas) ver `CHANGELOG.md` en el root del repo.

## Roadmap forward — endurecimiento del vault por capas

`ROAD-KVD-CLI-393064` ejecuta `ADR-KVD-CLI-64CD49`. La secuencia es incremental y cada capa es **opt-in**; el default permanece en `basic`.

### Fase 0 — quick-wins (sin hardware, sin servidor)

Endurecimientos que no necesitan release mayor ni infra nueva:

> **Protection-level UX** — el CLI dice en qué nivel estás (`basic` por defecto) y qué lo sube. Materializa `../security/protection-levels.md`.
>
> **A3 — backoff** en reintentos de master password para frenar bruteforce local.
>
> **A2 — pin de paths absolutos** de las herramientas invocadas (los plants relativos ya se bloquean; el residual es un plant por path absoluto mismo-uid). `ISSUE-KVD-CLI-625A66`.
>
> **N4 — anchor del audit** para detectar el truncado por la cola del log (hoy se detecta inserción/reordenado/edición, pero no la truncación del final). `ISSUE-KVD-CLI-DA52A0`.
>
> **S1a — v2 del blob de sesión** — endurecer el binding del `active.blob` de sesión (residual **C3**, wrap key derivada de inputs públicos).

### Fase 1 — hardware-backed keys (opt-in, sin servidor)

> Atar la clave del vault a un chip que **nunca la libera** y exigir presencia en cada uso: **Secure Enclave** (macOS), **TPM 2.0** (Linux), **FIDO2** (Yubikey).
>
> Cierra localmente el Caso A (te roban los ficheros) y el Caso C (mismo-uid, vault bloqueado) sin necesidad de un servidor. Es la mitigación canónica del vector **O1** (RAM dump / claves a rest).

### Fase 2 — credenciales efímeras y scope-limited

> El broker acuña tokens **de vida corta y mínimo privilegio por operación**, de modo que una filtración es un token de 15 minutos y un solo permiso en vez de la clave raíz.

### Fase 3 — server-assist (opt-in, online)

> Una segunda mitad de clave la custodia el KB Engine, añadiendo primero **detección + revocación + rate-limiting**; con un segundo factor fresco pasa de detección a **prevención** frente a un atacante con token robado.

### Fase 4 — remote broker (Team / Enterprise)

> La operación con la credencial corre **server-side**; el secreto en claro nunca llega a tu máquina. Es lo único que cierra por completo el **Caso B** (mismo-uid con el vault desbloqueado).

## Otras tracks identificadas (sin fecha)

> **Cloud sync avanzado (Pro+)** — más allá de `kvendra backup`: sync incremental cifrado client-side entre máquinas del mismo usuario. El plaintext jamás cruza la red.
>
> **Marketplace de primitives** — primitives contribuidas por la comunidad (`kvendra.linear`, `kvendra.notion`, …) con pipeline PR → security review → versión firmada, en el repo `kvendra-skills` (Apache-2.0).
>
> **Workspaces multi-user (Team tier)** — RBAC intra-workspace, audit dashboard cross-machine, policy enforcement org-wide.
>
> **Enterprise tier** — SSO/SAML, Nitro Enclaves cloud (Nivel 3 zero-knowledge real, attestation verificable client-side), compliance reports (SOC 2 / ISO 27001 / HIPAA), repo privado `kvendra-enterprise`.
>
> **Pre-commit hook `kvendra git secret-scan`** — extensión de la detection layer.

## Estado de recuperación (`kvendra recover`)

> **Advertencia (0.6.4):** la recuperación por mnemónica BIP-39 (`kvendra recover`) está **temporalmente deshabilitada / fail-closed** mientras se construye una implementación segura mnemonic-bound. El comando existe pero rechaza. Hasta entonces, **el camino de recuperación recomendado es un `kvendra backup` cifrado** — guárdalo, y conserva también tu mnemónica por escrito para cuando la recuperación vuelva. Ver `../security/protection-levels.md` y el [capítulo 10](./10-recuperacion.md).

## Política de versionado

- **`0.6.x`** patches: bug fixes y security patches. Pueden introducir **behaviour changes de seguridad** documentados (p. ej. `0.6.4` pasó a rechazar `config.toml`/allowlist sin firma). No cambian el shape de `tools/list` ni del allowlist YAML sin aviso.
- **`0.x.0`** menor: nuevas capacidades opt-in (cross-platform, Pro tier, capabilities, break-glass). Cambios aditivos.
- **`x.0.0`** mayor: posible breaking. Se documenta migration path.

## Política de soporte

- **Versión actual stable** (`0.6.x`) — soporte completo. Tras actualizar a `0.6.4`, cada perfil credential-bound **debe** tener un allowlist firmado (`kvendra secret validate --all`).
- **`0.1.x`–`0.5.x`** — best-effort; se anima a actualizar a `0.6.4` por los fixes de seguridad.
- **Pre-stable (`0.0.x`)** — sin soporte; eran placeholders de namespace.

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

> **Nota:** Las versiones publicadas en crates.io son **inmutables**. `cargo publish` de una versión solo puede hacerse una vez. Si descubres un bug crítico tras publish, la ruta es la siguiente patch con el fix — no es posible re-publicar la misma versión. Solo `cargo yank` (deprecación), nunca borrado.

> **Advertencia:** El roadmap es vivo. Las prioridades pueden cambiar según señales del owner y del cluster competidor. Las capas de `ROAD-KVD-CLI-393064` son **secuenciales pero opt-in**: ninguna cambia el default `basic`. Para timeline operacional real, consulta el Kvendra KB.
