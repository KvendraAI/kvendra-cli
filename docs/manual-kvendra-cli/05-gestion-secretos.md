# 5. Gestión de secretos y profiles

## Descripción

Una vez inicializado el vault, el día-a-día consiste en crear profiles (`secret add`), revisarlos (`secret list`), rotar tokens cuando expiran (`secret rotate`) y revocar los que ya no se usan (`secret revoke`). Cada profile asocia un secret cifrado a una *allowlist* declarativa — la capability mínima que el agente puede ejecutar con ese token.

Este capítulo cubre el subcomando `kvendra secret <action>` desde el lado del usuario. La sintaxis del DSL allowlist está en el [capítulo 7](./07-allowlist-dsl.md); el modelo conceptual de profile vive en `GLO-KVD-002`.

## Prerrequisitos

- Vault inicializado ([capítulo 4](./04-bootstrap-vault.md)).
- Sesión unlocked: `kvendra unlock`.
- Token plaintext del servicio externo (GitHub PAT, npm token, AWS keys, etc.) que quieres importar.
- Allowlist YAML preparada (puedes empezar con un template — ver [capítulo 7](./07-allowlist-dsl.md)).

## Subcomandos disponibles

```
kvendra secret
├── add <profile_id>       # importar un secret nuevo
├── list                   # listar profiles existentes
├── rotate <profile_id>    # reemplazar el plaintext, conservar allowlist
├── revoke <profile_id>    # borrar profile + audit row
├── export [--format=json] # exportar metadata (NO plaintext)
├── import <provider>      # asistente para flows típicos
└── validate <profile_id>  # AC-ALLOW-2 — comprueba allowlist sintaxis y contradicciones
```

## Crear un profile — `secret add`

### Paso 1 — Decida el `profile_id`

Convención recomendada: dot-namespace `<servicio>.<contexto>.<rol>`. Ejemplos en uso:

> `github.kvendraai.org-admin` — PAT con scope full sobre la org KvendraAI.
>
> `github.kvendraai.read-only` — PAT con scope `read:org`, `repo:read`.
>
> `aws.kvendra-web-deployer` — keys IAM con scope acotado a `s3_sync` + `cloudfront_invalidate` del bucket `kvendra-com-prod`.
>
> `npm.kvendra-publisher` — npm token para `@kvendra/*` packages.
>
> `pypi.kvendraai-publisher` — PyPI token project-scoped.
>
> `hf.kvendra-readonly` — HuggingFace token read-only.

El ID lo eliges tú. Lo único que el binario impone es: caracteres `[a-z0-9._-]`, longitud entre 3 y 128.

### Paso 2 — Lance `secret add`

```bash
kvendra secret add github.kvendraai.read-only \
  --type github_pat \
  --allowlist ./allowlists/github-readonly.yaml
```

Argumentos:

> **Posicional:** `<profile_id>` — el ID que has decidido.
>
> **`--type`** — uno de `github_pat`, `aws_credentials`, `npm_token`, `pypi_token`, `hf_token`, `api_token`. Determina cómo se parsea el plaintext y qué env vars se inyectan en el subprocess (ver [capítulo 14](./14-primitives.md)).
>
> **`--allowlist <path>`** — ruta al YAML de allowlist. Si lo omite, el binario abre `$EDITOR` con un template. Si tampoco hay editor, falla con instrucciones.
>
> **`--accept-broad-scope`** — necesario si el allowlist tiene `methods: []` o `url_pattern_regex: ".*"` u otros patrones laxos. Defaults restrictivos rechazan estos cases sin el flag.
>
> **`--accept-unsafe-escape-hatch`** — necesario si el allowlist activa `kvendra.unsafe.raw_token` (ver [capítulo 14](./14-primitives.md)).

### Paso 3 — Pegue el plaintext del token

Tras validar el allowlist, el binario pide:

```
Paste the plaintext for profile "github.kvendraai.read-only":
```

La entrada va sin echo (vía `rpassword`). El plaintext no aparece en stdout, no se loggea, no se persiste. Solo se usa para:

1. Validarlo según `--type` (formato esperado: `ghp_*`, `github_pat_*`, etc.).
2. Cifrarlo con AES-256-GCM con clave derivada del master password.
3. Persistirlo como blob en `~/.kvendra/secrets/<profile_id>.blob`.

Tras la validación, el plaintext se zeroiza en RAM.

### Paso 4 — Verifique la creación

```bash
kvendra secret list
```

Salida típica:

```
PROFILE_ID                          TYPE          EXPIRATION    PRIMITIVES
github.kvendraai.org-admin          github_pat    2026-08-04    git, github
github.kvendraai.read-only          github_pat    2026-12-31    github
aws.kvendra-web-deployer            aws           2026-09-30    aws
npm.kvendra-publisher               npm_token     —             npm
```

`EXPIRATION` viene del campo `expiration` del allowlist YAML. Si no se setea, `—`.

## Rotar un secret — `secret rotate`

Cuando un token expira o sospechas compromiso, rotas el plaintext sin tocar el allowlist:

```bash
kvendra secret rotate github.kvendraai.org-admin
```

Flujo:

1. El binario pide el nuevo plaintext (sin echo).
2. Lo valida contra `--type` del profile original.
3. Genera nuevo nonce AES-GCM, cifra, sobrescribe el blob.
4. Audit log: `action: secret.rotate`, `profile_id: github.kvendraai.org-admin`.

El allowlist YAML no cambia. Si quieres cambiar también el scope, edita el YAML y luego `secret validate <profile_id>` para refrescar el HMAC sidecar.

## Revocar un secret — `secret revoke`

```bash
kvendra secret revoke github.kvendraai.read-only
```

Flujo:

1. El binario muestra resumen del profile y pide confirmación.
2. Si confirmas, borra `secrets/<profile_id>.blob` y `allowlists/<profile_id>.yaml` (con sidecar).
3. Audit log: `action: secret.revoke` con `profile_id` preservado.

> **Advertencia:** `revoke` borra el cifrado en disco. **No** revoca el token en el servicio externo (GitHub, AWS, npm). Ese paso es manual y obligatorio. La razón: Kvendra no asume que tenga capability sobre el servicio externo para hacerlo automáticamente — es decisión consciente del owner.

Si necesitas revocar el token GitHub a la vez:

```bash
# Primero revoca en GitHub vía API (requiere otro profile con permisos):
kvendra <invoke vía agente AI o manual>
# Luego en Kvendra:
kvendra secret revoke github.kvendraai.read-only
```

## Validar un allowlist — `secret validate`

Cubre **AC-ALLOW-2** del REQ-KVD-002:

```bash
kvendra secret validate github.kvendraai.org-admin
```

El binario:

1. Lee el YAML del allowlist.
2. Valida sintaxis (`serde_yml`).
3. Comprueba que cada `primitive.operations.<op>` referenciado existe en el catálogo.
4. Comprueba defaults restrictivos: rechaza `methods: []`, `url_pattern_regex: ".*"`, etc. salvo `--accept-broad-scope`.
5. Comprueba expiración: si `expiration < now`, muestra warning explícito.
6. Reporta operaciones permitidas/denegadas en formato human-readable.
7. Recalcula el HMAC sidecar y lo persiste si es válido.

Salida típica:

```
Profile: github.kvendraai.org-admin
Allowlist: /Users/<you>/.kvendra/allowlists/github.kvendraai.org-admin.yaml
HMAC sidecar: ✓ valid (kvendra/allowlist-hmac/v1)
Expiration: 2026-08-04 (84 days remaining)

Permitted operations:
  kvendra.git
    - clone(repos: KvendraAI/*)
    - push(repos: KvendraAI/*, refs: refs/heads/main, refs/heads/feat/*)
    - tag(repos: KvendraAI/*, tag_pattern: v[0-9]+\.[0-9]+\.[0-9]+)
  kvendra.github
    - update_repo(org: KvendraAI, repo: kvendra-cli|kvendra-web|kvendra-platform,
                  fields_allowed: description|homepage|topics|has_wiki)
    - read_issue(org: KvendraAI, repo: *)
    - add_topics(org: KvendraAI, repo: *)

Denied (default):
  kvendra.git push --force, --force-with-lease (forbidden_args)
  kvendra.github.update_repo: default_branch, archived (forbidden_fields)
```

## Importar — `secret import <provider>`

Asistente para flows típicos. Cubre la pareja "ya tengo el token + necesito el allowlist correcto":

```bash
kvendra secret import github
```

El asistente:

1. Pregunta `profile_id` y orgs/repos a cubrir.
2. Genera un YAML allowlist mínimo basado en patterns canónicos de la primitive (`kvendra.github`).
3. Pide el plaintext del PAT.
4. Valida + cifra + persiste.

Providers soportados en `0.1.0`: `github`, `aws`, `npm`, `pypi`, `hf`. Para servicios fuera de esta lista, usa `secret add` con `--type api_token` y allowlist manual.

## Exportar — `secret export`

```bash
kvendra secret export --format json > profiles.json
```

Exporta **metadata** (profile_id, type, expiration, allowlist resumen). **No exporta el plaintext** — el blob cifrado vive solo en `~/.kvendra/secrets/`. Útil para inventory, CI checks, transferencia entre máquinas (acompañando los blobs cifrados; el destino aún necesita el master password para descifrarlos).

## Notas importantes

> **Nota:** Los profiles se identifican siempre por su `profile_id`. Si renombras un profile (ej. `github.read-only` → `github.kvendraai.read-only`), tendrás que `revoke` el viejo y `add` el nuevo. No hay rename atómico en `0.1.0` — es opt-in para futuras versiones si la fricción aparece en uso real.

> **Advertencia:** Antes de `secret add`, asegúrate de que el plaintext del token no queda en el scrollback de tu terminal. Si lo copiaste al clipboard, vacía el clipboard tras pegarlo. Si lo tienes en un fichero `.env`, considera moverlo a `~/.kvendra/` y borrar el original — el detection layer flageará nuevos `.env` con tokens conocidos (ver [capítulo 16](./16-detection-layer.md)).
