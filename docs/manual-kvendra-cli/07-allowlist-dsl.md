# 7. Allowlist DSL

## Descripción

El **allowlist** es el contrato declarativo entre el agente AI (caller) y el broker. Un fichero YAML por profile que especifica qué *operations* + parameters son permitidos. Defaults restrictivos y **fail-closed** (0.6.4): cualquier ambigüedad se rechaza salvo el meta-campo explícito `accept_broad_scope: true` en el propio allowlist. Un profile **sin allowlist**, o con `profile_id` vacío o inválido, se **deniega** de raíz (ver [Fail-closed en 0.6.4](#fail-closed-en-064)).

Este capítulo cubre la sintaxis YAML desde el lado del usuario. La implementación interna del enforcer (22 fields runtime) está en el [capítulo 15](./15-allowlist-enforcer.md). El concepto de profile vive en `GLO-KVD-002` y el de allowlist en `GLO-KVD-004`.

## Estructura general

Un allowlist se ubica en `~/.kvendra/allowlists/<profile_id>.yaml` y tiene este shape canónico:

```yaml
profile_id: github.kvendraai.org-admin
secret:
  type: github_pat
  encrypted_blob: <base64 ciphertext>   # rellenado por kvendra secret add
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - <operation_name>:
            <parameter_1>: [...]
            <parameter_2>: [...]
        - <operation_name>:
            ...
    - name: kvendra.git
      operations:
        - ...
expiration: 2026-08-04
audit_level: full
```

Cada `primitive` se referencia por nombre canónico (`kvendra.git`, `kvendra.github`, `kvendra.npm`, `kvendra.pypi`, `kvendra.aws`, `kvendra.http`, `kvendra.shell`, `kvendra.unsafe.raw_token`). Cada `operation` toma parámetros específicos del primitive — están definidos en cada `IF-KVD-CLI-NNN` y resumidos en el [capítulo 14](./14-primitives.md).

## Defaults restrictivos

Estas combinaciones se **rechazan en setup** (`secret set-allowlist`) sin `accept_broad_scope: true` en el allowlist:

> `methods: []` o `methods` ausente en `kvendra.http`.
>
> `url_pattern_regex: ".*"` o `^.*$` en `kvendra.http`.
>
> `repos: ["*"]` con scope amplio en `kvendra.git` o `kvendra.github`.
>
> `binaries: ["*"]` en `kvendra.shell`.
>
> Cualquier campo que efectivamente conceda scope global cuando un campo restrictivo se omite.

El header `Authorization` está **siempre** forbidden al caller — el broker lo construye server-side desde el `auth_scheme` del profile (ver `IF-KVD-CLI-006`).

## Fail-closed en 0.6.4

El endurecimiento de 0.6.4 cerró una familia de fallos *fail-open* de la capa de autorización (detalle en el [capítulo 15](./15-allowlist-enforcer.md)). Para el allowlist, las reglas efectivas hoy son:

> **Perfil sin allowlist → denegado.** Un profile con secreto pero sin YAML de allowlist ya no es *allow*: cada `tools/call` se rechaza (`missing_allowlist_denied`).
>
> **`profile_id` vacío → denegado.** Todo primitive del catálogo es *credential-bound*; un `profile_id` ausente/vacío es deny duro (`empty_profile_denied`), nunca un salto de allowlist+approval.
>
> **`profile_id` inválido → denegado.** Un id con `..` o `/` se rechaza (`invalid_profile_denied`); el patrón aceptado es `[A-Za-z0-9._-]`.
>
> **Operación destructiva sin opt-in → rechazada.** Las operaciones que el catálogo marca destructivas (p. ej. `push`, `s3_sync` con borrado, `exec`, o `POST/PUT/PATCH/DELETE` en `kvendra.http`) exigen `accept_destructive: true` junto a la operación; sin él, `secret set-allowlist` rechaza el allowlist (decisión D7, ver [capítulo 15](./15-allowlist-enforcer.md)).

Cada rechazo queda registrado en el audit log con su flag correspondiente ([capítulo 8](./08-audit-log.md)).

## Glob semantics

Los campos `refs`, `buckets`, `distributions`, `functions`, `packages`,
`projects`, `org` y `repos`/`repo` aceptan patterns con el wildcard `*`:

- `*` matchea cualquier secuencia de caracteres que **no contenga `/`**
  (single-segment). Es la semántica de bash glob estándar.
- El match es **anclado full-string**: el pattern debe cubrir el
  candidato completo, no sólo un prefijo.
- Caracteres con significado en regex (`.`, `+`, `?`, `(`, `)`, `|`,
  `[`, `]`, `{`, `}`, `^`, `$`, `\`) se tratan **literalmente**.
- Para cubrir múltiples segmentos (cruce de `/`) hay que listar
  patterns explícitos o entries por nivel.

Ejemplos:

| Pattern | Matchea | NO matchea |
|---|---|---|
| `refs/tags/v*` | `refs/tags/v0.4.0-alpha.3`, `refs/tags/v1` | `refs/tags/v0/sub` |
| `refs/heads/release/*` | `refs/heads/release/v1` | `refs/heads/release/v1/sub` |
| `kvendra-*-prod` | `kvendra-com-prod`, `kvendra-x-prod` | `kvendra-com-staging` |
| `KvendraAI/*` | `KvendraAI/kvendra-cli` | `KvendraAI/foo/extra`, `OrgX/KvendraAI/foo` |

> ℹ️ Los campos `tag_pattern` y `url_pattern_regex` usan **regex completa**
> (no glob). El campo `args_constraints` token-level acepta `*` per-slot
> (consulta el capítulo 15).

## Ejemplos por servicio

### `kvendra.git` (operaciones git locales)

```yaml
profile_id: github.kvendraai.org-admin
secret:
  type: github_pat
  encrypted_blob: <base64>
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - clone:
            repos: ["github.com/KvendraAI/*"]
        - push:
            repos: ["github.com/KvendraAI/*"]
            refs: ["refs/heads/main", "refs/heads/feat/*"]
            forbidden_args: ["--force", "--force-with-lease"]
        - pull:
            repos: ["github.com/KvendraAI/*"]
            refs: ["refs/heads/main"]
        - tag:
            repos: ["github.com/KvendraAI/*"]
            tag_pattern: ["v[0-9]+\\.[0-9]+\\.[0-9]+"]
expiration: 2026-08-04
audit_level: full
```

### `kvendra.github` (REST + GraphQL)

```yaml
profile_id: github.kvendraai.org-admin
allowlist:
  primitives:
    - name: kvendra.github
      operations:
        - update_repo:
            org: ["KvendraAI"]
            repo: ["kvendra-cli", "kvendra-web", "kvendra-platform"]
            fields_allowed: ["description", "homepage", "topics", "has_wiki"]
            forbidden_fields: ["default_branch", "archived"]
        - read_issue:
            org: ["KvendraAI"]
            repo: ["*"]
        - update_issue:
            org: ["KvendraAI"]
            repo: ["kvendra-cli"]
            fields_allowed: ["title", "body", "labels", "state"]
        - add_topics:
            org: ["KvendraAI"]
            repo: ["*"]
        - release:
            org: ["KvendraAI"]
            repo: ["kvendra-cli"]
            tag_pattern: ["v[0-9]+\\.[0-9]+\\.[0-9]+(\\.\\w+)?"]
expiration: 2026-08-04
```

> **Nota:** El parámetro `repo` del primitive `kvendra.github` acepta dos formatos: forma corta `"owner/name"` y forma URL `"github.com/owner/name"`. El parser canónico stripea el prefix. Documentado en `IF-KVD-CLI-002`.

### `kvendra.npm`

```yaml
profile_id: npm.kvendra-publisher
allowlist:
  primitives:
    - name: kvendra.npm
      operations:
        - publish:
            packages: ["@kvendra/*", "kvendra"]
            accept_destructive: true
        - deprecate:
            packages: ["@kvendra/*"]
            accept_destructive: true
        - read_metadata:
            packages: ["*"]
expiration: 2026-12-31
```

### `kvendra.pypi`

```yaml
profile_id: pypi.kvendraai-publisher
allowlist:
  primitives:
    - name: kvendra.pypi
      operations:
        - upload:
            projects: ["kvendra"]
            accept_destructive: true
        - read_metadata:
            projects: ["*"]
```

### `kvendra.aws`

```yaml
profile_id: aws.kvendra-web-deployer
allowlist:
  primitives:
    - name: kvendra.aws
      operations:
        - s3_sync:
            buckets: ["kvendra-com-prod"]
            accept_destructive: true
        - cloudfront_invalidate:
            distributions: ["E2MSK8NR0QTV9W"]
            accept_destructive: true
        - s3_cp:
            buckets: ["kvendra-com-prod"]
            accept_destructive: true
expiration: 2026-09-30
audit_level: full
```

> **Nota:** La región no se declara en el allowlist: viene del propio secret (ver la nota siguiente y `IF-KVD-CLI-005`).

> **Nota:** El secret de tipo `aws_credentials` acepta dos shapes documentados en `IF-KVD-CLI-005`: JSON canónico (`{"access_key_id": ..., "secret_access_key": ..., "session_token": ..., "region": ...}`) y colon-form legacy (`"AKIA...:secret"` o `"AKIA...:secret:session"`).

### `kvendra.http`

```yaml
profile_id: hf.kvendra-readonly
auth_scheme: bearer
allowlist:
  primitives:
    - name: kvendra.http
      operations:
        - request:
            url_pattern_regex: ["^https://huggingface\\.co/api/(models|datasets)(/.*)?$"]
            methods: ["GET"]
            forbidden_methods: ["POST", "PUT", "DELETE", "PATCH"]
expiration: 2026-12-31
```

`auth_scheme` enum (definido en `IF-KVD-CLI-006`):

| Valor | Header inyectado por el broker |
|-------|-------------------------------|
| `bearer` | `Authorization: Bearer <plaintext>` |
| `header_<NAME>` | `<NAME>: <plaintext>` (ej. `header_X-Api-Key`) |
| `basic_<USER>` | `Authorization: Basic base64(<USER>:<plaintext>)` |
| `none` | (sin auth header — requiere allowlist estricto) |

### `kvendra.shell`

```yaml
profile_id: github.kvendraai.org-admin
allowlist:
  primitives:
    - name: kvendra.shell
      operations:
        - exec:
            binaries: ["gh"]
            args_constraints:
              - allowed:
                  - "release"
                  - "create"
                  - "v[0-9]+\\.[0-9]+\\.[0-9]+(\\.\\w+)?"
                  - "--repo"
                  - "KvendraAI/.+"
                  - "--title"
                  - ".+"
                  - "--notes"
                  - ".+"
              - allowed:
                  - "release"
                  - "view"
                  - "v[0-9]+\\.[0-9]+\\.[0-9]+(\\.\\w+)?"
                  - "--repo"
                  - "KvendraAI/.+"
            cwd_pattern: "^/Users/[^/]+/Develop/.*"
            env_vars_to_inject:
              - GH_TOKEN
            forbidden_env_export_to_agent:
              - GH_TOKEN
audit_level: full
```

> **Advertencia:** `kvendra.shell` no usa `sh -c`. Es `Command::new(binary).args(...)` directo, sin expansión de variables ni glob. Esto elimina inyección via `;`, `&&`, `|`, `$()`, backticks. Detalle de seguridad en `IF-KVD-CLI-007`.

### `kvendra.unsafe.raw_token` (escape hatch)

```yaml
profile_id: exotic-provider.api
allowlist:
  primitives:
    - name: kvendra.unsafe.raw_token
      unsafe_raw_token_allowed: true
      unsafe_max_uses_per_session: 3
      unsafe_reason_min_length: 10
expiration: 2026-06-30
audit_level: full
```

Defaults restrictivos:

> `unsafe_raw_token_allowed` default `false`. Sin este `true` explícito, `UnsafeNotEnabled`.
>
> `unsafe_max_uses_per_session` default `1`. Aumentar conscientemente.
>
> `kvendra secret add` requiere el flag `--unsafe-raw-token-enabled` para permitir el escape hatch en ese profile.
>
> Recomendación: `expiration` corto (semanas, no meses).

## Campos comunes a todos los profiles

> **`expiration: <YYYY-MM-DD>`** — opcional pero recomendado. Profiles con `expiration < now` rechazan toda operación con `ProfileExpired` (AC-ALLOW-3).
>
> **`audit_level: full | summary`** — `full` (default) loggea cada call con args_hash. `summary` (agregar calls por minuto en una sola row) sigue **sin implementarse en 0.6.4**.

## Validación y HMAC del allowlist

El allowlist va firmado con un HMAC (sub-key HKDF, info `kvendra/allowlist-hmac/v1`) para que el broker detecte manipulaciones. Quien **firma y persiste** ese HMAC es `kvendra secret set-allowlist <profile_id> --file <yaml>` (REQ-KVD-007 / ISSUE-018), no `secret validate`:

1. Parsea el YAML con `serde_yaml_ng` y **`deny_unknown_fields`**: una clave desconocida es error duro (con pista *"did you mean"* para los typos comunes — p. ej. `args_exact` → `args_constraints`, `cwd_allowed` → `cwd_pattern`).
2. Valida estructura, tipos y defaults restrictivos (incluidos `accept_broad_scope` y `accept_destructive`).
3. Desbloquea el vault (la sub-key HMAC solo existe con sesión activa), escribe el YAML en `~/.kvendra/allowlists/<profile_id>.yaml` (mode 0600) y **persiste el HMAC junto a la metadata del profile**.

`kvendra secret validate <profile_id>` (o `--all`) es **read-only**: re-verifica el HMAC y el schema e imprime el desglose, pero **no re-firma**. Al startup, antes de aceptar `tools/call`, el broker re-verifica el HMAC; mismatch → rechazo del profile con error explícito. Esto cierra el vector L1 GAP_4 (atacante con perms de user que amplía scope editando el YAML).

> **Advertencia:** No edites el YAML "a mano" y lo dejes ahí — el HMAC quedaría desincronizado y el broker rechazaría el profile al arrancar. La forma canónica de cambiar un allowlist es:
>
> 1. Editar tu copia del YAML.
> 2. Ejecutar `kvendra secret set-allowlist <profile_id> --file <yaml>` — re-firma y persiste el HMAC.
>
> `secret validate` te dice *si* está sincronizado; `set-allowlist` es el único que lo **re-firma**.

## Notas importantes

> **Nota:** El HMAC se calcula sobre los **bytes crudos** del YAML (`compute_allowlist_hmac(key, raw)`), no sobre una serialización normalizada. Por tanto los comentarios (`# ...`) **sí** cuentan para la firma: tocar un comentario invalida el HMAC igual que tocar una regla, y hay que re-firmar con `kvendra secret set-allowlist`.

> **Nota:** Para auditar qué autoriza un allowlist sin ejecutarlo, `kvendra secret validate <profile_id>` imprime el desglose human-readable. Útil para reviews antes de aprobar PRs que modifiquen allowlists en repos compartidos.
