# 18. Threat model

## Descripción

El threat model formal de Kvendra CLI es **Nivel 2 zero-knowledge**, formalizado en `ADR-KVD-010` y publicado en el root del repo como `THREAT-MODEL.md`. Este capítulo es la versión narrada del documento canónico — útil para entender el modelo sin leer el ADR completo. Para referencia oficial, consulte `THREAT-MODEL.md`.

La promesa de marca, citada literal:

> *Even with full access to your filesystem (excluding the running process memory while unlocked), the only thing visible is encrypted blobs that are mathematically useless without your master password.*

Esa frase es la promesa Nivel 2. El resto del capítulo desglosa qué vectores cubre, qué vectores acepta explícitamente y por qué.

> **Corrección importante (0.6.4).** La promesa de arriba es cierta para el vault **bloqueado** y para los **ficheros en reposo** (te roban `~/.kvendra`), pero **no** mientras el vault está **desbloqueado** frente a un proceso con tu mismo uid. El blob de sesión (`~/.kvendra/sessions/active.blob`) se cifra con una wrap key derivada de datos **públicos** (hostname + uid + ruta canónica; IKM constante `kvendra-session-wrap-sentinel-v1`), así que un proceso como tú, con el vault abierto, recupera la clave del vault **sin la master password** (finding **C3**, reproducido en vivo). Lo señaló la auditoría externa de **Salva Ferrer** (avtn.es); `THREAT-MODEL.md` §Promise/§V2 y `../security/protection-levels.md` lo corrigen. El fix real es *hardware-backed key wrapping* (roadmap, opt-in). Ver «Casos A/B/C» justo debajo.

## Casos de atacante A / B / C (0.6.4)

Para el usuario, el modelo se resume en tres situaciones (versión en lenguaje llano en `../security/protection-levels.md`):

- **Caso A — tienen tus ficheros, no tu máquina** (backup robado, snapshot de disco). Vault bloqueado. **Protegido**: los blobs son opacos sin la master password (Argon2id 64 MiB/t3 + AES-256-GCM).
- **Caso C — tu mismo uid, vault bloqueado** (leen/intercambian ficheros; no han visto tu password). **Protegido** en confidencialidad; la integridad de `config.toml` y de los allowlists se detecta y se rechaza (0.6.4, A5/A6).
- **Caso B — tu mismo uid, vault desbloqueado** (leen tu RAM/sesión). **No protegido**: leen lo que tú puedes leer. Es el límite honesto de cualquier vault local software-only; **C3** vive aquí. El agente, en cambio, **sigue sin ver el plaintext** ni saltarse el allowlist (todo fail-closed).

## Vectores cubiertos por Nivel 2

```mermaid
graph LR
    subgraph Cubiertos[Vectores cubiertos]
        V1[V1 Pasive observer<br/>repo público]
        V2[V2 Read access<br/>~/.kvendra/]
        V3[V3 Kvendra-team<br/>insider]
        V4[V4 AWS breach<br/>post-MVP]
        V5[V5 External<br/>auditor]
        V6[V6 Compromised<br/>primitive]
        V7[V7 Malicious<br/>AI agent]
        V8[V8 Remote<br/>bruteforce]
    end

    subgraph Aceptados[Vectores aceptados]
        O1[O1 RAM dump<br/>unlocked session]
        O1env[O1.env-var<br/>process listing]
        O2[O2 Persistent<br/>malware root]
        O3[O3 Side-channel<br/>timing]
        O4[O4 Legal<br/>coercion]
        O5[O5 External<br/>service breach]
        O6[O6 Accidental<br/>logging]
    end

    style Cubiertos fill:#dfd
    style Aceptados fill:#fdd
```

| # | Atacante | Capacidades | Plaintext expuesto | Mitigación canónica |
|---|----------|-------------|-------------------|---------------------|
| **V1** | Pasive observer del repo público (Apache-2.0) | Lee todo el código fuente | Ninguno | Auditabilidad como feature |
| **V2** | Lectura de `~/.kvendra/` (backup leak, snapshot disco) | Lee blobs cifrados + audit.db | Ninguno sin master password | Argon2id high-cost + AES-256-GCM client-side |
| **V3** | Kvendra-team malicioso (insider) | Acceso total a infra Kvendra | Ninguno — la key del vault nunca cruza red | Cifrado client-side antes de cualquier upload (el Pro backup sube el vault **ya cifrado**; la key nunca sale de tu máquina) |
| **V4** | AWS breach (post-MVP cloud sync) | Acceso completo a S3 + Lambda + KMS Kvendra-internal | Solo blobs cifrados; KMS Kvendra-internal NO toca secrets de user | Cifrado client-side; KMS solo para infra Kvendra |
| **V5** | Auditor externo | Acceso a código + (post-MVP) infra cloud | Verificable: ningún codepath imprime/persiste plaintext | Auditabilidad |
| **V6** | Compromised primitive (bug en allowlist parser) | Ejecuta acción fuera de scope | Token usado contra endpoint no permitido | Sandbox + review proceso primitives + audit log HMAC inmutable |
| **V7** | Agente AI malicioso/comprometido | Invoca primitives arbitrarias por MCP | Solo resultado de operaciones permitidas | Allowlist DSL restrictivo + escape hatch segregado |
| **V8** | Bruteforce remoto del master password vía blob exfiltrated | Computa Argon2id en su hardware | Compute-bound (~1s/intento) | Argon2id m=64MiB cost ~1s/intento |

## Vectores L1 enumerados (Sesión 3 threat modeling)

Cuatro GAPs L1 enumerados en la Sesión 3 post `ROAD-007` cierre. **Todos cerrados estructuralmente en alpha.7 / 0.1.0**:

| # | Vector | Status | Mitigación canónica |
|---|--------|--------|---------------------|
| **GAP_1** | mcp-password fetch superficie expuesta | **CLOSED** alpha.4 | Inline keychain ACL `userPresence` en `mcp serve --use-keychain`; wrapper + fetch removidos (`REQ-KVD-005`) |
| **GAP_2** | mcp-password wrapper script en filesystem | **CLOSED** alpha.4 | Wrapper eliminado; subprocess invocado directamente vía `command + args` en `~/.claude.json` |
| **GAP_3** | TTY hijack en MCP-via-Desktop con mode `ask-destructive` | **CLOSED** alpha.5 | Transport-based approval separation (CLI=TTY, MCP=biometric reusando keychain ACL) (`REQ-KVD-006`) |
| **GAP_4** | allowlist YAML modificable por atacante L1 + cache TOCTOU | **CLOSED** alpha.6 | HMAC `kvendra/allowlist-hmac/v1` + composite cache key con HMAC del YAML (`REQ-KVD-007`) |
| **GAP_5** | `KVENDRA_HOME` env var redirect a copia del vault | **CLOSED** alpha.7 | `home_canonical` signed dentro del config.toml HMAC'd + canonicalize riguroso ambos lados (`REQ-KVD-008`) |
| **GAP_6** | mcp-password wrapper integridad sin firmar | **CLOSED** alpha.4 | Wrapper eliminado (no aplica) |
| **GAP_7** | config.toml sin firma — atacante baja `approval.mode` a silent | **CLOSED** alpha.7 | HMAC sidecar `~/.kvendra/config.toml.hmac` con sub-key `kvendra/config-hmac/v1` |
| **TTY-HIJACK** | TTY del owner secuestrada al primer `tools/call` destructive | **CLOSED** alpha.5 | Transport separation (Transport::Mcp nunca toca TTY) |

**Status global L1**: structurally complete. `0.1.0` ships con todos los vectores enumerados mitigados. Los DIFERIDOS (GAP 2 mcp transport auth, supply chain, mcp elicit) siguen out of L1 scope (no son L1 strictly — son L2/L3 / supply chain / protocol).

## 0.6.4 — la capa de autorización, fail-closed (auditoría externa + pentest interno)

La auditoría estática de 0.6.3 (**Salva Ferrer**, avtn.es) confirmó que la base cripto (Argon2id, AES-256-GCM, firma ed25519 de grants, OAuth PKCE) era sólida; los defectos explotables eran **caminos fail-open en el enforcement** — justo **V6** (primitive comprometido) y **V7** (agente malicioso). Todos cerrados fail-closed en 0.6.4:

- **C1** — `profile_id` vacío saltaba allowlist + approval → deny duro.
- **C2 / N7 / N10** — el enforcer leía campos que el primitive no manda (`bin`/`binary`, `repo`/`{cwd,remote,ref}`, `tag`/`name`) → `binaries`/`repos`/`tag_pattern` inertes. Ahora nombre de campo compartido + resolución real + fail-closed (ver [cap. 15](./15-allowlist-enforcer.md)).
- **C4** — perfil con secreto y sin allowlist → deny duro.
- **H2** — los predicados destructivos leían el envelope, no `inner_args` → `s3 sync --delete` / `git tag --force` / HTTP mutante se saltaban `ask-destructive`; ahora approval lee el payload interno.
- **H4** — la cuota del escape-hatch (`unsafe_max_uses_per_session`) no se aplicaba → ahora sí (default 1/sesión).
- **H5 / N2** — `git clone` con `ext::` (RCE) e inyección de opción → validación de esquema + `--` + `protocol.ext.allow=never`; `npm publish` ejecutaba lifecycle scripts → `--ignore-scripts`.
- **N1 / N5 / N6** — master password filtrada al entorno de subprocesos (scrub `KVENDRA_*`), inyección de opción en aws/npm/pypi (guard de `-`), `npm publish` sin fijar registry → `--registry` pinned a npmjs.org.
- **A5 / A6** — integridad de `config.toml` / allowlist bypasseable (append tras la firma / HMAC nulo, auto-re-firmado) → ahora **rechazo fail-closed** (tratado como tamper). **Behaviour change.**
- **N8 / N9 / N11** — guardrail de scope amplio de `kvendra.http` literalizado, cabeceras de respuesta sin sanitizar, redactor sin cubrir PEM/JWT/`ya29.` → cerrados (ver [cap. 16](./16-detection-layer.md)).

### Behaviour changes (0.6.4)

- `config.toml` sin firma o manipulado → **rechazado** (antes se adoptaba y re-firmaba en silencio).
- Allowlist sin firma → **rechazada** (antes se auto-firmaba).
- Perfil credential-bound sin allowlist → **denegado** (antes fail-open).
- `profile_id` vacío → denegado.
- `unlock --extend` → exige master password (finding **A1**).
- `npm publish` → corre con `--ignore-scripts`.

Tras actualizar, cada perfil credential-bound **debe** tener un allowlist firmado (`kvendra secret validate --all`).

### Residuales documentados (mismo-uid, trazados en el KB)

- **C3** — blob de sesión desbloqueada descifrable/forjable por un proceso mismo-uid (wrap key de inputs públicos). Trade-off que deja correr `mcp serve` sin re-pedir password. Fix: hardware-backed key wrapping. `ISSUE-KVD-CLI-B12B18`, `ADR-KVD-029`.
- **N4** — truncado por la **cola** del audit log no detectado aún (inserción/reordenado/edición sí). `ISSUE-KVD-CLI-DA52A0`.
- **A2** — hijack de tool por PATH de directorio absoluto (mismo-uid); los plants relativos ya se bloquean. `ISSUE-KVD-CLI-625A66`.
- **H1** — el bundle de export de audit incrusta la seed HMAC → integridad offline ≠ autenticidad; el bundle lleva ahora un `security_note`. `ISSUE-KVD-CLI-945698`.
- **H3** — approval con presencia solo en macOS; en Linux hay que operar con `KVENDRA_APPROVAL_MODE=silent`. `ISSUE-KVD-CLI-A508C8`.

Detalle: `../security/advisory-cli-0.6.4.md`. Reporte original: `ISSUE-KVD-CLI-B78ED5` (cerrado). Roadmap de endurecimiento por capas: `ROAD-KVD-CLI-393064` (ejecuta `ADR-KVD-CLI-64CD49`).

## Vectores explícitamente aceptados (out of Nivel 2)

| # | Vector | Por qué aceptado | Mitigación post-MVP |
|---|--------|------------------|---------------------|
| **O1** | RAM dump durante sesión unlocked | Mientras el vault está unlocked, la derived key vive en RAM. Atacante con root + ptrace puede dumpearla. Trade-off de la categoría de producto. | Hardware-backed wrapping (Secure Enclave / TPM 2.0 / Yubikey FIDO2) |
| **O1.env-var** | `KVENDRA_PASSWORD` env var visibility | El password plaintext es visible en `/proc/<pid>/environ` y `ps eww` durante la duración del comando que lo consume. Trade-off de UX vs threat model aceptado por owner para enable CI/scripts. Users en máquinas multi-tenant deben preferir `--password-stdin`. | El binary lee la env var **una vez** al inicio y `unsetenv()` antes de cualquier exec subsidiario. |
| **O2** | Malware persistente en máquina del user con privilegios root | Si el atacante puede sustituir el binario, puede lograr cualquier cosa | Reproducible builds + SLSA-signed releases (post-MVP) |
| **O3** | Side-channel timing attacks en CPU compartida | Argon2id es resistente pero no perfecto | `subtle` crate para constant-time ops |
| **O4** | Coercion legal del user ("rubber-hose attack") | El user tiene la key | Recovery codes permiten reset; no es problema técnico |
| **O5** | Compromiso de un servicio externo (GitHub, npm, AWS) | Out of Kvendra's scope | Rotation manual + revocación en el servicio |
| **O6** | Logging accidental del plaintext por un primitive maltrazado | Aceptado como riesgo de implementación | Audit log automático + review primitives + `zeroize` |

## Promesa final formalizada

**Nivel 2 zero-knowledge (0.6.4)** — con la corrección de C3 al principio del capítulo:

> Ningún codepath del binario `kvendra` (Apache-2.0, auditable) imprime ni persiste a disco el master password ni la derived key. La derived key vive solo en RAM del proceso `kvendra mcp serve` durante la sesión unlocked, y es zeroizada (`zeroize` crate) al `kvendra lock` o al timeout configurable. Los blobs en `~/.kvendra/secrets/*.blob` son AES-256-GCM con clave derivada Argon2id (cost ≥1 s/intento) — opacos sin master password.

**Nivel 2 ampliado a filesystem integrity** (alpha.4..alpha.7 / 0.1.0):

> Todos los artefactos de configuración persistentes están firmados HMAC con sub-keys derivadas via HKDF de la session key (ADR-KVD-022). Atacante L1 (sin master password, con perms del user) NO puede modificar `config.toml`, allowlist YAMLs ni redirigir el vault home sin que el binario lo detecte y rechace al startup.

## Sub-keys HKDF vivas (0.1.0 + añadidas en 0.6.0/0.6.4)

| Sub-key | Constant Rust | Info HKDF | Propósito |
|---------|---------------|-----------|-----------|
| Audit HMAC | `vault::session::HKDF_INFO_AUDIT_HMAC` | `kvendra/audit-hmac/v1` | Firma de la audit chain |
| Allowlist HMAC | `vault::session::HKDF_INFO_ALLOWLIST_HMAC` | `kvendra/allowlist-hmac/v1` | Sidecar de cada YAML allowlist |
| Config HMAC | `vault::session::HKDF_INFO_CONFIG_HMAC` | `kvendra/config-hmac/v1` | Sidecar de `config.toml` + `home_canonical` |
| Grant sign (ed25519) | `grant::HKDF_INFO_GRANT_SIGN` | `kvendra/grant-sign/v1` | Sella el seed del par ed25519 de break-glass bajo la clave **maestra** del vault (v0.6.0) — ver [cap. 23](./23-break-glass.md) |
| Session wrap | `session::wrap_key::HKDF_INFO_SESSION_WRAP` | `kvendra/session-wrap/v1` | Wrap key del blob de sesión (machine-bound; IKM = `SESSION_WRAP_SENTINEL_IKM`, salt de inputs públicos — **C3**) |
| Backup cipher | `backup::BACKUP_HKDF_INFO` | `kvendra/backup-cipher/v1` | Cifra el bundle de `kvendra backup` |

> **Distinción de seguridad clave:** el seed del grant (break-glass) se sella bajo la **clave maestra** del vault, así que a rest está protegido y **el agente no puede forjar grants**. El blob de sesión, en cambio, usa una wrap key derivada de **inputs públicos** (machine-bound, sin master password) — ese es exactamente el residual **C3**.

Patrón formalizado en `ADR-KVD-022`: domain separation via HKDF info string. El sufijo `/v1` permite rotación de versión de la sub-key sin breaking change si la binding cambia.

## Ejecutables de la promesa

Cualquier reviewer externo puede:

1. Clonar `kvendra-cli` (Apache-2.0).
2. Auditar el path crypto (Argon2id → AES-256-GCM → zeroize) en una sesión de lectura razonable (≤2h).
3. Confirmar que ningún codepath imprime/persiste plaintext del master password ni del derived key.

Esto es uno de los success metrics canónicos del `REQ-KVD-002`.

## Tests que respaldan el threat model

`AC-VAULT-1..5`, `AC-MCP-3`, `AC-AUDIT-2` son los criterios de aceptación que aterrizan los invariantes del threat model en código. La testsuite los valida E2E:

> **AC-VAULT-2** — cualquier `~/.kvendra/secrets/*.blob` inspeccionado fuera de la sesión consiste en bytes opacos.
>
> **AC-VAULT-3** — tras `kvendra lock`, no existe ningún proceso ni fichero temporal en disco con la encryption key derivada.
>
> **AC-MCP-3** — una llamada `tools/call` con `profile_id` ejecuta la acción y devuelve el resultado **sin que el plaintext del secret aparezca en ningún campo de respuesta**.
>
> **AC-AUDIT-2** — una row manipulada manualmente en `audit.db` rompe la cadena HMAC y `kvendra audit --verify` lo detecta señalando la primera row corrupta.

## Política de divulgación

`SECURITY.md` en root del repo sigue **RFC 9116** (`security.txt`). Reporting de vulnerabilidades:

```
security@kvendra.ai
```

Acuse en 72 h, plan de remediación en 7 días, divulgación coordinada (30–90 días tras el fix), crédito al reporter salvo que prefiera anonimato. Vulnerabilidades L1 (no-respect del threat model) son SECURITY/HIGH severity y se priorizan sobre features. (`hello@kvendra.ai` es solo para consultas generales.)

## Notas importantes

> **Nota:** El threat model **no** cubre security ops de tu workspace (rotación de tokens, revocación tras incident, audit external). Eso es responsabilidad operacional. Kvendra te da las herramientas (audit log, expiration policy, detection layer) — usarlas con disciplina sigue siendo decisión tuya.

> **Advertencia:** Si encuentras un caso donde el threat model parece roto, **no** abras issue público. Reporta a `security@kvendra.ai` siguiendo `SECURITY.md`. La divulgación coordinada minimiza el window de explotación entre fix y publicación.
