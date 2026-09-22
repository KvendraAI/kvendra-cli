# 8. Audit log

## Descripción

Cada invocación MCP que pasa por el broker — incluyendo invocaciones que fallan por `AllowlistViolation`, `ProfileExpired` o cualquier otra razón — produce **una row** en `~/.kvendra/audit.db`. Las rows están encadenadas con HMAC: cada una incluye en su firma el HMAC de la row anterior. Manipular una row rompe la chain de forma detectable por `kvendra audit --verify`.

Este capítulo cubre el lado de uso del comando `kvendra audit`. La estructura interna de la base de datos, el HMAC chain y la derivación de la sub-key viven en el [capítulo 17](./17-audit-internals.md).

## Subcomandos y flags disponibles

```
kvendra audit                 # TUI viewer (default, requires feature `tui`)
kvendra audit --watch         # live tail (TUI), AC-TUI-2  [+ --profile / --primitive / --since]
kvendra audit --json          # export completo a stdout en JSON (flag legacy)
kvendra audit --verify        # validar HMAC chain cross-process, AC-AUDIT-2 (flag legacy)
kvendra audit export          # export firmado: PDF + CSV + JSON canónico (REQ-KVD-CLI-007)
kvendra audit verify-export   # verifica un export JSON canónico previo
```

> **Nota:** `--json` y `--verify` son **flags** de `kvendra audit`, no subcomandos — `kvendra audit verify` **no existe** (el binario sugiere `verify-export`). Los subcomandos reales son `export` y `verify-export`, añadidos en la **audit v3** (0.6.2).

## TUI viewer — `kvendra audit`

El comando sin argumentos abre un viewer TUI que muestra las últimas N rows con paginación.

Layout típico:

```
┌─ kvendra audit ─────────────────────────────────────────────────────────────┐
│ ROW    TIMESTAMP             PROFILE                  PRIMITIVE         OK  │
│ 1234   2026-05-10 12:34:56   github.kvendraai.org-... kvendra.github    ✓   │
│ 1233   2026-05-10 12:34:42   aws.kvendra-web-deplo... kvendra.aws       ✓   │
│ 1232   2026-05-10 12:32:11   github.kvendraai.org-... kvendra.git       ✗   │
│ ...                                                                         │
│                                                                             │
│ ↑↓ navigate · ENTER detail · / search · q quit                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

ENTER sobre una row abre el detalle:

```
┌─ Audit Event #1232 ─────────────────────────────────────────────────────────┐
│ Timestamp:   2026-05-10 12:32:11.421 UTC                                    │
│ Profile:     github.kvendraai.org-admin                                     │
│ Primitive:   kvendra.git                                                    │
│ Action:      push                                                           │
│ Status:      error (AllowlistViolation)                                     │
│ Severity:    error                                                          │
│ Args hash:   sha256:7a4f...3c91                                             │
│ Reason:      ref "refs/heads/release/v0.2" not in allowed refs              │
│ Flags:       allowlist_denied                                               │
│ HMAC:        a1b2c3d4...                                                    │
│ Prev HMAC:   f3e2d1c0...                                                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

Atajos:

> **`↑` / `↓`** — navegar.
>
> **`ENTER`** — abrir detalle.
>
> **`/`** — buscar (substring sobre profile, primitive, action).
>
> **`f`** — filtrar por status (ok/error).
>
> **`q`** — salir.

> **Nota:** El viewer requiere feature Cargo `tui` (default-on). Builds compiladas `--no-default-features` no incluyen el binario TUI; en ese caso usa `--json` con `jq` o herramienta equivalente.

## Live tail — `kvendra audit --watch`

Para observación en tiempo real (útil mientras un agente está ejecutando una tarea larga):

```bash
kvendra audit --watch                                      # todo el flujo
kvendra audit --watch --profile aws.kvendra-web-deployer   # filtra por profile_id
kvendra audit --watch --primitive kvendra.git              # filtra por primitive
kvendra audit --watch --since 1h                           # ventana temporal (5m, 1h, ...)
```

Los filtros `--profile`, `--primitive` y `--since` se combinan y solo aplican al watcher. Polling al WAL de SQLite con latencia <500 ms (AC-TUI-2). Cada nueva row aparece coloreada por severidad:

> Verde — `severity: info`, `status: ok`.
>
> Amarillo — `severity: warn` (ej. `unsafe_escape_hatch`).
>
> Rojo — `severity: error`.

Sale con Ctrl+C o `q`.

## Export JSON — `kvendra audit --json`

Para auditing scriptable (CI checks, integraciones SIEM, análisis post-mortem):

```bash
kvendra audit --json > audit-2026-05-10.json
```

Schema documentado:

```json
[
  {
    "id": 1234,
    "ts": "2026-05-10T12:34:56.789Z",
    "profile_id": "github.kvendraai.org-admin",
    "primitive": "kvendra.github",
    "action": "update_repo",
    "args_hash": "sha256:...",
    "status": "ok",
    "severity": "info",
    "flags": [],
    "prev_hmac": "...",
    "hmac": "..."
  },
  ...
]
```

> **Nota:** `kvendra audit --json` no requiere unlock — las rows del audit log son texto plain. Solo el HMAC chain check (`--verify`) requiere acceso a la sub-key derivada del master password. Esta separación es deliberada: permite inspección rápida del log con `jq` sin friction de password.

Filtros típicos con `jq`:

```bash
# Errores de allowlist en las últimas 24h
kvendra audit --json | jq '.[] | select(.flags[]? == "allowlist_denied")'

# Calls al escape hatch
kvendra audit --json | jq '.[] | select(.primitive == "kvendra.unsafe.raw_token")'

# Calls por profile
kvendra audit --json | jq 'group_by(.profile_id) | map({profile: .[0].profile_id, count: length})'
```

Para el patrón canónico de inspección sin password (acceso directo SQLite), ver `CLAUDE.md` del workspace o el [capítulo 17](./17-audit-internals.md).

## Export firmado — `kvendra audit export`

Mientras `--json` es un volcado rápido a stdout, `kvendra audit export` (audit v3, `REQ-KVD-CLI-007`) genera un **paquete firmado** para compliance/SIEM: PDF legible + CSV + JSON canónico, con la semilla de la cadena HMAC embebida y una URL de verificación.

```bash
kvendra audit export \
  --from 2026-05-01 --to 2026-05-10 \
  --filter "profile_id=github.kvendraai.org-admin,primitive=kvendra.git" \
  --format pdf,csv,json \
  --out ./exports \
  --password-stdin < master.pw
```

Flags reales en 0.6.4 (`kvendra audit export --help`):

> **`--from <ISO-8601>`** — límite inferior inclusivo. Default: hace 30 días.
>
> **`--to <ISO-8601>`** — límite superior inclusivo. Default: ahora.
>
> **`--filter <expr>`** — expresión `clave=valor` separada por comas, p. ej. `profile_id=alice,primitive=kvendra.git`.
>
> **`--format <lista>`** — subconjunto de `pdf,csv,json` separado por comas. Default: `pdf,csv,json` (los tres).
>
> **`--out <DIR>`** — directorio de salida. Default: directorio actual.
>
> **`--include-raw-args`** — desactiva la redacción por defecto e incluye los summaries de args crudos (imprime un warning; revisa antes de compartir).
>
> **`--password-stdin`** — lee la master password de stdin, necesaria para derivar la semilla de la cadena HMAC. Si el vault ya está desbloqueado, usa la clave de sesión.

Los ficheros se escriben como `kvendra-audit-<fecha>.{pdf,csv,json}` y el comando imprime el conteo, el rango, la `Verify online:` URL y el comando exacto de `verify-export`.

## Verificación offline de un export — `kvendra audit verify-export`

Re-verifica la integridad de un JSON canónico generado por `audit export`, sin tocar la `audit.db` original (útil para un tercero que recibe el export):

```bash
kvendra audit verify-export kvendra-audit-2026-05-10.json
```

El argumento es la **ruta posicional** al `*.json` canónico. Devuelve `Pass` (con el número de eventos) o `Fail` con el detalle del primer mismatch.

## Verificación de integridad — `kvendra audit --verify`

Cubre **AC-AUDIT-2**: detectar manipulación retroactiva del log.

```bash
kvendra audit --verify --password-stdin
```

Tres canales de password (en orden de preferencia):

> **`--password-stdin`** (recomendado) — leer del stdin, una línea, sin echo.
>
> **`KVENDRA_PASSWORD`** env var — útil para CI / scripts. **Sub-vector O1.env-var documentado**: visible en `/proc/<pid>/environ` y `ps eww` durante la ejecución del comando. Trade-off aceptado para automation.
>
> **TTY prompt** — modo interactivo. Falla en non-TTY contexts.

Flujo:

1. El binario re-deriva la sub-key HMAC del audit log (info `kvendra/audit-hmac/v1`) desde el master password.
2. Recorre `audit.db` en orden ascendente.
3. Para cada row, recalcula HMAC esperado a partir de `prev_hmac` + payload de la row.
4. Compara contra `hmac` persistido.
5. Primer mismatch detecta la row corrupta y aborta con código de salida no-cero.

Ejemplo de éxito:

```
Verifying audit chain (1234 rows)...
✓ Chain valid. First row: 2026-05-06 21:18:43. Latest: 2026-05-10 12:34:56.
```

Ejemplo de mismatch:

```
✗ Chain broken at row 567 (timestamp 2026-05-08 14:22:11).
   Expected HMAC: a1b2c3...
   Found HMAC:    99ff00...
   Possible causes: row tampered, schema migration applied without re-sign, file corruption.
```

## Tipos de row más comunes

| `primitive` | `action` | Cuándo aparece |
|-------------|----------|----------------|
| `kvendra.git` | `clone`, `push`, `pull`, `commit`, `tag` | Invocaciones del agente vía MCP |
| `kvendra.github` | `update_repo`, `release`, `read_issue`, ... | Invocaciones del agente |
| `kvendra.aws` | `s3_sync`, `cloudfront_invalidate`, ... | Invocaciones del agente |
| `kvendra.http` | `request` | Invocaciones del agente |
| `kvendra.shell` | `exec` | Invocaciones del agente |
| `kvendra.unsafe.raw_token` | `get` | Cada uso del escape hatch (severity: warn) |
| `(internal)` | `secret.add`, `secret.rotate`, `secret.revoke` | Operaciones del usuario |
| `(internal)` | `vault.unlock`, `vault.lock` | Sesiones |
| `(internal)` | `allowlist_hmac_migrated` | Migraciones automáticas (post alpha.11) |
| `(internal)` | `recovery_code_replay_attempted` | Intento de re-uso de un recovery code |

## Troubleshooting

### "Chain broken at row N" en `--verify`

Causas posibles:

1. **Manipulación deliberada o accidental** — alguien editó `audit.db` con `sqlite3` y modificó valores.
2. **Schema migration applied without re-sign** — entre versiones del binario que cambian el schema, las rows antiguas pueden quedar desincronizadas. La migración canónica (alpha.11+) loggea `allowlist_hmac_migrated` para evidencia.
3. **File corruption** — fallo de disco, snapshot de fs en estado inconsistente.

Para investigar:

```bash
sqlite3 ~/.kvendra/audit.db \
  "SELECT id, ts_unix_ms, profile_id, primitive, action, status FROM audit_events WHERE id BETWEEN <N-2> AND <N+2>"
```

### "VaultLocked" en `--verify`

`--verify` requiere el master password para re-derivar la sub-key. Si `--password-stdin` no está siendo alimentado, se recurre a TTY prompt. Si tampoco hay TTY, falla.

### Rows con `status: error` que no esperabas

Lo más común es `AllowlistViolation` por un PR que modificó el YAML del allowlist sin re-firmar el HMAC (con `secret set-allowlist`), o una operación que el agente intentó ejecutar fuera de scope. Inspecciona la row con detail TUI o con `jq` para ver el `reason`.

El endurecimiento fail-closed de 0.6.4 añadió flags de denegación propios que verás en estas rows (ver [capítulo 7](./07-allowlist-dsl.md) y [capítulo 15](./15-allowlist-enforcer.md)):

> **`empty_profile_denied`** — `profile_id` ausente/vacío en un primitive credential-bound.
>
> **`invalid_profile_denied`** — `profile_id` con `..` o `/` (fuera del patrón `[A-Za-z0-9._-]`).
>
> **`missing_allowlist_denied`** — profile con secreto pero sin allowlist YAML.

## Notas importantes

> **Nota:** El audit log no rota automáticamente en `0.6.4`. Si crece mucho, puedes archivarlo manualmente: `mv ~/.kvendra/audit.db ~/.kvendra/audit-archive-2026-05.db && kvendra <restart broker>`. La rotación gestionada con retention policy es post-MVP (Team tier).

> **Advertencia:** No borres `audit.db` para "limpiar". Si lo haces, pierdes la cadena histórica. El siguiente arranque del broker creará un nuevo `audit.db` con genesis row, pero ese archivo tendrá una cadena nueva, sin relación criptográfica con la anterior.
