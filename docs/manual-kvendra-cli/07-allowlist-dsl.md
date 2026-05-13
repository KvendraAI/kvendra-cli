# 7. Allowlist DSL

## Descripción

El **allowlist** es el contrato declarativo entre el agente AI (caller) y el broker. Un fichero YAML por profile que especifica qué *operations* + parameters son permitidos. Defaults restrictivos: cualquier ambigüedad se rechaza salvo flag explícito `--accept-broad-scope`.

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

Estas combinaciones se **rechazan en setup** sin `--accept-broad-scope`:

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
            access: ["public"]
            forbidden_tags: ["@latest"]
        - deprecate:
            packages: ["@kvendra/*"]
            version_pattern: ["0\\..*"]
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
            dist_pattern:
              - "kvendra-[0-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?(\\.tar\\.gz|\\-py3\\-none\\-any\\.whl)"
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
            prefix_pattern: ["/*"]
            delete_allowed: true
        - cloudfront_invalidate:
            distributions: ["E2MSK8NR0QTV9W"]
            paths_pattern: ["/*"]
        - s3_cp:
            buckets: ["kvendra-com-prod"]
            prefix_pattern: ["/*"]
region_default: us-west-1
expiration: 2026-09-30
audit_level: full
```

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
            url_pattern_regex: "^https://huggingface\\.co/api/(models|datasets)(/.*)?$"
            methods: ["GET"]
            forbidden_headers: ["Authorization", "Cookie", "X-API-Key"]
            max_body_size_kb: 1024
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
> `kvendra secret add` requiere `--accept-unsafe-escape-hatch` cuando un profile activa esto.
>
> Recomendación: `expiration` corto (semanas, no meses).

## Campos comunes a todos los profiles

> **`expiration: <YYYY-MM-DD>`** — opcional pero recomendado. Profiles con `expiration < now` rechazan toda operación con `ProfileExpired` (AC-ALLOW-3).
>
> **`audit_level: full | summary`** — `full` (default) loggea cada call con args_hash. `summary` agrega calls por minuto en una sola row (post-MVP, no implementado en `0.1.0`).
>
> **`region_default`** — solo aplicable a profiles `aws`. Usado cuando el secret en colon-form no incluye region.

## Validación y HMAC sidecar

Cada vez que ejecutas `kvendra secret add` o `kvendra secret validate`, el binario:

1. Parsea el YAML con `serde_yml`.
2. Valida estructura, tipos y defaults restrictivos.
3. Calcula HMAC del YAML completo con sub-key derivada via HKDF (info `kvendra/allowlist-hmac/v1`).
4. Persiste el HMAC en `~/.kvendra/allowlists/<profile_id>.yaml.hmac`.

Al startup del broker, antes de aceptar `tools/call`, se re-verifica el HMAC. Mismatch → rechazo del profile con error explícito. Esto cierra el vector L1 GAP_4 (atacante con perms de user que modifica el YAML para ampliar scope).

> **Advertencia:** No edites el YAML manualmente con un editor que no respete el HMAC. La forma canónica de cambiar un allowlist es:
>
> 1. Editar el YAML.
> 2. Ejecutar `kvendra secret validate <profile_id>` — recalcula y persiste el HMAC.
>
> Cualquier otro flujo deja el sidecar desincronizado y el siguiente arranque del broker rechaza el profile.

## Notas importantes

> **Nota:** El YAML soporta comentarios (`# ...`) y se preservan al validate, pero no se incluyen en el cálculo del HMAC (el HMAC se calcula sobre el YAML normalizado vía `serde_yml::to_string`). Aporta robustez contra "diff cosmético" y permite documentar el allowlist sin invalidar la firma.

> **Nota:** Para auditar qué autoriza un allowlist sin ejecutarlo, `kvendra secret validate <profile_id>` imprime el desglose human-readable. Útil para reviews antes de aprobar PRs que modifiquen allowlists en repos compartidos (post-MVP).
