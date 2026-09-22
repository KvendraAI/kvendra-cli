# 5. Gestión de secretos y profiles

## Descripción

Una vez inicializado el vault, el día-a-día consiste en crear profiles (`secret add`), revisarlos (`secret list`), rotar tokens cuando expiran (`secret rotate`) y revocar los que ya no se usan (`secret revoke`). Cada profile asocia un secret cifrado a una *allowlist* declarativa — la capability mínima que el agente puede ejecutar con ese token.

Este capítulo cubre el subcomando `kvendra secret <action>` desde el lado del usuario. La sintaxis del DSL allowlist está en el [capítulo 7](./07-allowlist-dsl.md); el modelo conceptual de profile vive en `GLO-KVD-002`.

## Prerrequisitos

- Vault inicializado ([capítulo 4](./04-bootstrap-vault.md)).
- Sesión unlocked: `kvendra unlock`.
- Token plaintext del servicio externo (GitHub PAT, npm token, AWS keys, etc.) que quieres guardar en el vault.
- Allowlist YAML preparada (puedes empezar con un template — ver [capítulo 7](./07-allowlist-dsl.md)). Se adjunta al profile con `secret set-allowlist`, en un segundo paso.

## Subcomandos disponibles

Superficie real de `kvendra secret` en `0.6.4` (`kvendra secret --help`):

```
kvendra secret
├── add <profile_id>            # crea el profile y cifra el plaintext en el vault
├── list                        # listar profiles existentes
├── get-meta <profile_id>       # imprimir metadata de un profile (sin plaintext)
├── rotate <profile_id>         # reemplazar el plaintext, conservar allowlist
├── revoke <profile_id>         # borrar blob + metadata + allowlist
├── validate [<profile_id>]     # AC-ALLOW-2 — valida el allowlist (o `--all`)
└── set-allowlist <profile_id>  # fijar/actualizar el YAML allowlist del profile
```

> **Nota:** En `0.6.4` **no** existen `secret import` ni `secret export`. El flujo real para un profile nuevo es `secret add` (crea + cifra) seguido de `secret set-allowlist` (adjunta la policy); para inventariar metadata sin plaintext se usa `secret get-meta`; para copiar el vault entre máquinas se usa `kvendra backup` (Pro tier, ver [capítulo 10](./10-recuperacion.md)).

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
  --secret-type github_pat \
  --expiration 2026-12-31
```

Argumentos y flags reales (`kvendra secret add --help`):

> **Posicional:** `<PROFILE_ID>` — el ID que has decidido.
>
> **`--secret-type <LABEL>`** — etiqueta libre del tipo de secreto (p. ej. `github_pat`, `npm_token`, `aws_credentials`…). Por defecto `generic`. Es **metadata**: no cambia el cifrado del blob.
>
> **`--secret-env <VAR>`** — lee el plaintext de esa variable de entorno (en vez del prompt interactivo).
>
> **`--secret-file <PATH>`** — lee el plaintext de ese fichero UTF-8.
>
> **`--expiration <ISO-8601>`** — fecha de expiración opcional del profile (se muestra en `secret list` / `secret get-meta`).
>
> **`--unsafe-raw-token-enabled`** — habilita el escape hatch `kvendra.unsafe.raw_token` en este profile (ver [capítulo 14](./14-primitives.md)). Actívalo solo si de verdad lo necesitas.
>
> **`--password-stdin`** — lee el master password de stdin (recomendado para scripts).

> **Nota:** `secret add` **crea el profile y cifra el plaintext**, pero no adjunta el allowlist. La policy declarativa se fija en un segundo paso con `secret set-allowlist` (ver más abajo). En `0.6.4` no hay flag `--allowlist` en `secret add`.

### Paso 3 — Aporte el plaintext del token

Si no ha pasado `--secret-env` ni `--secret-file`, el binario lo pide por prompt:

```
Paste the plaintext for profile "github.kvendraai.read-only":
```

La entrada va sin echo (vía `rpassword`). El plaintext no aparece en stdout, no se loggea, no se muestra. El binario:

1. Lo cifra con AES-256-GCM con clave derivada del master password.
2. Lo persiste como blob en `~/.kvendra/secrets/<profile_id>.blob`.
3. Registra la metadata (incluida la etiqueta `--secret-type` y la `--expiration`).

Tras cifrar, el plaintext se zeroiza en RAM. `--secret-type` es una etiqueta de inventario: el binario **no** valida el formato del token contra ella.

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

`EXPIRATION` viene del flag `--expiration` de `secret add`. Si no se setea, `—`. La columna `PRIMITIVES` refleja las primitives que autoriza el allowlist adjunto (vacía hasta que ejecutes `secret set-allowlist`).

## Rotar un secret — `secret rotate`

Cuando un token expira o sospechas compromiso, rotas el plaintext sin tocar el allowlist:

```bash
kvendra secret rotate github.kvendraai.org-admin
```

Flujo:

1. El binario pide el nuevo plaintext (sin echo), o lo lee de `--secret-env <VAR>` / `--secret-file <PATH>`.
2. Genera nuevo nonce AES-GCM, cifra, sobrescribe el blob.
3. Audit log: `action: secret.rotate`, `profile_id: github.kvendraai.org-admin`.

Flags de `secret rotate` (`--help`): `--secret-env`, `--secret-file`, `--password-stdin`. El allowlist YAML no cambia. Si quieres cambiar también el scope, aplica el YAML nuevo con `secret set-allowlist <profile_id> --file <yaml>` (refresca el HMAC sidecar) y verifica con `secret validate <profile_id>`.

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
# 1) Primero revoca el token en el servicio externo (GitHub),
#    a mano en su UI/API o vía un agente con otro profile que tenga permiso.
# 2) Luego borra la copia cifrada en Kvendra:
kvendra secret revoke github.kvendraai.read-only
```

## Validar un allowlist — `secret validate`

Cubre **AC-ALLOW-2** del REQ-KVD-002:

```bash
kvendra secret validate github.kvendraai.org-admin
# o, para validar todos los profiles presentes en disco:
kvendra secret validate --all
```

El posicional `<PROFILE_ID>` es opcional; con `--all` valida cada profile del disco. El binario:

1. Lee el YAML del allowlist.
2. Valida sintaxis (`serde_yaml_ng`).
3. Comprueba que cada `primitive.operations.<op>` referenciado existe en el catálogo.
4. Aplica los defaults restrictivos del DSL: los patrones excesivamente laxos (p. ej. `methods: []` o un `url_pattern_regex: ".*"`) se rechazan salvo que el YAML los declare explícitamente permitidos según las reglas del [capítulo 7](./07-allowlist-dsl.md) / [capítulo 15](./15-allowlist-enforcer.md).
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

## Adjuntar el allowlist — `secret set-allowlist`

Fija (o actualiza) el YAML allowlist de un profile. Es el segundo paso del alta de un profile y también la vía para cambiar el scope después:

```bash
kvendra secret set-allowlist github.kvendraai.read-only \
  --file ./allowlists/github-readonly.yaml
```

Argumentos (`kvendra secret set-allowlist --help`):

> **Posicional:** `<PROFILE_ID>` — el profile cuyo allowlist se fija.
>
> **`--file <FILE>`** (obligatorio) — ruta al YAML del allowlist.
>
> **`--password-stdin`** — lee el master password de stdin (recomendado para scripts).

El binario valida el YAML, lo persiste como `~/.kvendra/allowlists/<profile_id>.yaml` y recalcula su HMAC sidecar. La sintaxis del DSL (claves `args_constraints`, `cwd_pattern`, etc.) está en el [capítulo 7](./07-allowlist-dsl.md); el enforcement, en el [capítulo 15](./15-allowlist-enforcer.md).

> **Advertencia:** El orden del `argv` importa cuando el broker re-firma un allowlist. Si `set-allowlist` o el broker rechaza con `argv does not match` pero acepta el `cwd`, es el **orden de los argumentos** del YAML, no drift de firma: replica el `argv` exacto antes de teorizar una re-firma.

## Inventariar metadata — `secret get-meta`

Imprime la metadata de un profile **sin** revelar el plaintext:

```bash
kvendra secret get-meta github.kvendraai.org-admin
```

Devuelve `profile_id`, la etiqueta `secret-type`, la expiración, el resumen del allowlist y flags como el escape hatch. Útil para inventario, checks de CI y auditoría. El plaintext nunca sale del blob cifrado en `~/.kvendra/secrets/`.

> **Nota:** Para **mover o copiar el vault entre máquinas** no hay un `secret export`: en Pro tier se usa `kvendra backup push` / `pull` / `restore`, que sube el vault cifrado a la nube de Kvendra (el destino sigue necesitando el master password para descifrarlo). Ver [capítulo 10](./10-recuperacion.md).

## Notas importantes

> **Nota:** Los profiles se identifican siempre por su `profile_id`. Si renombras un profile (ej. `github.read-only` → `github.kvendraai.read-only`), tendrás que `revoke` el viejo y `add` + `set-allowlist` el nuevo. No hay rename atómico en `0.6.4` — es opt-in para futuras versiones si la fricción aparece en uso real.

> **Advertencia:** Antes de `secret add`, asegúrate de que el plaintext del token no queda en el scrollback de tu terminal. Si lo copiaste al clipboard, vacía el clipboard tras pegarlo. Si lo tienes en un fichero `.env`, considera moverlo a `~/.kvendra/` y borrar el original — el detection layer flageará nuevos `.env` con tokens conocidos (ver [capítulo 16](./16-detection-layer.md)).
