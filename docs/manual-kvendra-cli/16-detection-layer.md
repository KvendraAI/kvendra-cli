# 16. Detection layer

## Descripción

El **detection layer** es la red de seguridad **post-allowlist**: si por error un primitive devuelve algo que matchea pattern de token (ej. una API response que incluye un token raw), o si el agente envía un body con un token plaintext, el detection layer flagea o bloquea según la severidad configurada.

Es opt-in en el sentido de que la severidad por defecto (`warn`) no interrumpe operaciones — solo educa. El usuario puede subirla a `error` o `block` cuando quiera disciplina más estricta.

Este capítulo describe los patterns canónicos, las severidades workspace, la integración en el pipeline del broker y las heurísticas anti-falsos-positivos.

## Cuándo se ejecuta

```mermaid
flowchart LR
    Input[Input del agente<br/>tools/call args] --> InputDetect{Detection<br/>en input?}
    InputDetect -->|match| InputAction[warn / error / block]
    InputDetect -->|no match| Primitive[Ejecuta primitive]
    Primitive --> Response[Response sanitizada]
    Response --> OutputDetect{Detection<br/>en output?}
    OutputDetect -->|match| OutputAction[warn / error / block]
    OutputDetect -->|no match| Return[Return al agente]

    style InputAction fill:#fdd
    style OutputAction fill:#fdd
```

Dos puntos de inspección:

> **Input** — antes de ejecutar el primitive. Detecta si el agente está mandando un token plaintext en el body de una request HTTP, en el commit message, en el argv del shell, etc.
>
> **Output** — tras `build_sanitized_payload`, justo antes del return al agente. Detecta si la response del servicio externo contiene un token (raro pero posible).

## Patterns canónicos

`detection::patterns::PROVIDER_PATTERNS` enumera los regex con su clase de token. **19 patterns** en 0.6.4 (la doc-comment del módulo que dice «7 providers» es previa y quedó stale):

| Provider (id) | Regex |
|---------------|-------|
| `github_pat_classic` | `ghp_[A-Za-z0-9]{36}` |
| `github_oauth` | `gho_[A-Za-z0-9]{36}` |
| `github_app_server` | `ghs_[A-Za-z0-9]{36}` |
| `github_user_to_server` | `ghu_[A-Za-z0-9]{36}` |
| `github_pat_fine` | `github_pat_[A-Za-z0-9_]{82}` |
| `npm_token` | `npm_[A-Za-z0-9]{36}` |
| `pypi_token` | `pypi-AgEI[A-Za-z0-9_-]{30,}` |
| `hf_token` | `hf_[A-Za-z0-9]{34}` |
| `aws_akid` | `AKIA[0-9A-Z]{16}` |
| `aws_secret_env` | `(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}` |
| `anthropic_key` | `sk-ant-[A-Za-z0-9_-]{60,}` |
| `openai_key` | `sk-[A-Za-z0-9]{48,}` |
| `slack_token` | `xox[baprs]-[0-9A-Za-z-]{10,}` |
| `stripe_secret_key` | `(?:sk\|rk)_live_[0-9A-Za-z]{24,}` — los `sk_test_` NO se matchean (no sensibles por guía de Stripe) |
| `google_api_key` | `AIza[0-9A-Za-z_-]{35}` |
| `gitlab_pat` | `glpat-[0-9A-Za-z_-]{20,}` |
| `google_oauth_token` | `ya29\.[0-9A-Za-z_-]{20,}` |
| `jwt` | `eyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}` |
| `private_key_pem` | `(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----\|\z)` — bloque completo, o hasta EOF si el footer está truncado |

Los añadidos en el hardening 0.6.4 (`slack_token`, `stripe_secret_key` live, `google_api_key`, `gitlab_pat`, `google_oauth_token`, `private_key_pem`, más los `gho_/ghs_/ghu_`) amplían la cobertura de proveedores. **No hay un pattern genérico catch-all**: la entropía de Shannon no es un matcher, sino un **filtro** que descarta falsos positivos sobre los matches de los patterns anteriores (identificadores normales, UUIDs, hashes git de baja entropía).

## Severidades workspace

Se lee del bloque `[detection]` de `~/.kvendra/config.toml` (`severity`, enum `warn|error|block`, default `warn`). El fichero está firmado con HMAC sidecar (`kvendra/config-hmac/v1`) y en 0.6.4 se **rechaza fail-closed** si está manipulado o sin firmar (A5). En 0.6.4 **no** hay un subcomando `kvendra config set` para la severidad — se lee de `config.toml`; `kvendra config` gestiona keychain/approval/mcp-password/rebind-home/recovery-codes/telemetry.

| Severity | Comportamiento input | Comportamiento output | Audit row |
|----------|---------------------|----------------------|-----------|
| `warn` | Loguea warning, deja pasar | Loguea warning, devuelve al agente | `severity: warn`, `flags: ["detection_match"]` |
| `error` | Loguea + agrega `isError: true` al MCP response | Idem | `severity: error` |
| `block` | Rechaza con `DetectionBlock`, no ejecuta primitive | Rechaza response, devuelve `DetectionBlock` | `severity: error`, `flags: ["detection_block"]` |

Default `warn`. Para developers sólos en alpha cerrada, `warn` es suficiente — educa sin imponer fricción. Para entornos compartidos o equipos con disciplina más alta, `error` o `block`.

## Heurística anti-falsos-positivos

Cubre **AC-DETECT-3** del REQ-KVD-002:

1. **Longitud mínima**: matches de menos de 20 chars se ignoran salvo que el pattern lo exija (ej. `ghp_*` exige 36).
2. **Entropy check**: para `generic_high_entropy`, calcula Shannon entropy. Strings con entropy <4.5 bits/char se descartan (típico para hashes git que matchean `[A-Za-z0-9]{40}` pero tienen entropy más baja).
3. **Allowlist contextual**: strings que aparecen rodeados de `<example>`, `// example`, `<placeholder>` o markers similares se ignoran (común en docs y readmes).

Si una primitive genera matches falsos positivos repetidos, la lección se documenta en `PAT-KVD-*` y el regex se ajusta.

## Mensaje educativo

Cuando un match dispara warning, el log y la audit row incluyen un mensaje human-readable:

> *"This looks like a `<provider>` token. Want to store it via `kvendra secret add <profile>` and use the capability broker instead?"*

Tono: educativo, no punitivo. Sugiere la alternativa (importar al vault), no se limita a bloquear.

## Integración en el pipeline

`mcp::server` invoca el detection layer en dos puntos:

```rust
// Input check
if let Some(matches) = detection::scan(&request_args) {
    apply_severity(matches, &workspace.severity, AuditPoint::Input).await?;
}

let response = primitive::invoke(...).await?;

// Output check (después de sanitize_output)
if let Some(matches) = detection::scan(&response.content) {
    apply_severity(matches, &workspace.severity, AuditPoint::Output).await?;
}

Ok(response)
```

`apply_severity` es el dispatcher que decide warn/error/block según la config y escribe la audit row apropiada.

## Pre-commit hook (post-MVP)

Future: `kvendra git secret-scan` como pre-commit hook que escanea el diff antes de permitir el commit. Documentado como out-of-scope del REQ-KVD-002 — extension natural cuando llegue Pro tier.

## Tests del detection layer

Conjunto típico:

- Cada pattern canónico tiene happy-path (token sintético matchea) y edge-case (no falso positivo en string parecido pero no-token).
- Heurística generic_high_entropy: tests con UUIDs, hashes git SHA-1/SHA-256 (no deben matchear con entropy real) y tokens random (sí deben matchear).
- Severity dispatch: cada nivel produce el comportamiento correcto end-to-end.

## Relación con sanitize_output

`detection` y `sanitize_output` son complementarios:

> `sanitize_output` redacta el plaintext **conocido** (el secret del profile activo) en el response.
>
> `detection` busca patterns **genéricos** de tokens en input/output, sin saber cuál es el secret activo.

Si una response del servicio externo contiene un token de **otro** servicio (ej. la API de GitHub devuelve un body con un AWS key embebido por error), `sanitize_output` no lo redactará (no es el plaintext del profile actual), pero `detection` sí lo flageará si la severidad es `error` o `block`.

### 0.6.4 — cobertura del redactor de salida ampliada

La auditoría de 0.6.3 encontró dos huecos en el redactor de salida:

- **N9** — `sanitize_output` redactaba el **cuerpo** de las respuestas HTTP pero devolvía las **cabeceras** sin sanitizar (el agente controla `auth_scheme`/cabeceras de request, y un endpoint puede reflejar una cabecera o devolver un token en una). En 0.6.4 los valores de cabecera pasan por el mismo redactor que el cuerpo.
- **N11** — el redactor no cubría **claves privadas PEM**, **JWT** ni **tokens OAuth de Google (`ya29.`)**; una clave o un JWT en la salida de un comando se devolvía en claro. Se añadieron los tres.

Dos políticas de redacción declaradas en `detection::patterns`:

> **`ALWAYS_REDACT_PROVIDERS`** (`private_key_pem`) — se redacta siempre, saltándose el filtro de entropía: el *framing* `BEGIN … PRIVATE KEY` es señal suficiente y un cuerpo de baja entropía forzado no debe colar una clave real. Redacta el bloque `BEGIN…END` **completo** (o hasta EOF si el footer está truncado), no solo el header.
>
> **`REDACT_ONLY_PROVIDERS`** (`jwt`, `google_oauth_token`) — se redactan en la **salida** pero NO bloquean/marcan como *finding* en el **input**: un JWT o un `ya29.` es a menudo un argumento legítimo (un `Authorization: Bearer` que el agente debe mandar), así que tratarlo como smuggling en modo `block` denegaría llamadas válidas. Se redactan sin fricción falsa.

Además, `sanitize_output` redacta por **valor exacto** el secret del profile activo (capturado antes de la ejecución), no solo por pattern.

## Notas importantes

> **Nota:** El detection layer **no sustituye** la disciplina de allowlist. Es defense-in-depth. Si tu allowlist YAML está bien escrito, los tokens no deberían cruzar el broker en plaintext en ninguna dirección — el detection layer es el avisador de cuando algo se ha colado.

> **Advertencia:** No pongas severidad `block` si tu workflow incluye operaciones legítimas que generan strings de alta entropía (ej. signatures HMAC visibles en debug logs, IDs de transactions criptográficos largos). El detection layer puede dar falsos positivos sobre strings legítimos pero "token-like". El balance default (`warn`) es deliberado.
