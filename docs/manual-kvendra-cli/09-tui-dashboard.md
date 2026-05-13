# 9. TUI dashboard

## Descripción

`kvendra dashboard` ofrece una vista global del estado del vault — profiles, sesión, audit recent, severidad detection — en una sola pantalla TUI. Útil para una rápida sanity check mientras se trabaja con un agente, sin tener que ejecutar varios `secret list / audit / config get` en sucesión.

La feature Cargo `tui` está activa por defecto. Builds headless (`--no-default-features`) no incluyen este subcomando.

## Prerrequisitos

- Binario compilado con feature `tui` (default).
- Terminal moderna con soporte truecolor preferred (256-color como fallback aceptable).
- Vault inicializado.

## Layout principal

```
┌─ kvendra dashboard ─────────────────────────────────────────────────────────┐
│ Vault: ~/.kvendra/                                                          │
│ Status: UNLOCKED · session expires in 18m 42s                               │
│ Detection severity: warn                                                    │
│                                                                             │
├─ Profiles (5) ──────────────────────────────────────────────────────────────┤
│ github.kvendraai.org-admin     github_pat   exp 2026-08-04   ✓              │
│ github.kvendraai.read-only     github_pat   exp 2026-12-31   ✓              │
│ aws.kvendra-web-deployer       aws          exp 2026-09-30   ✓              │
│ npm.kvendra-publisher          npm_token    no exp           ⚠              │
│ pypi.kvendraai-publisher       pypi_token   no exp           ⚠              │
│                                                                             │
├─ Recent activity (last 5) ──────────────────────────────────────────────────┤
│ 12:34:56  kvendra.github update_repo    github.kvendraai...   ✓             │
│ 12:34:42  kvendra.aws    s3_sync         aws.kvendra-web-...   ✓             │
│ 12:32:11  kvendra.git    push            github.kvendraai...   ✗             │
│ 12:30:55  kvendra.github read_issue      github.kvendraai...   ✓             │
│ 12:30:21  kvendra.git    clone           github.kvendraai...   ✓             │
│                                                                             │
├─ Audit chain ──────────────────────────────────────────────────────────────┤
│ Total rows: 1234                                                            │
│ First: 2026-05-06 21:18:43                                                  │
│ Latest: 2026-05-10 12:34:56                                                 │
│ Last verify: 2026-05-09 (chain valid)                                       │
│                                                                             │
│ TAB switch panel · ENTER detail · l lock · q quit                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Atajos globales

> **`TAB`** — saltar entre paneles (Profiles / Recent activity / Audit chain).
>
> **`ENTER`** — abrir detalle del item seleccionado.
>
> **`/`** — buscar dentro del panel activo.
>
> **`l`** — `kvendra lock` desde el dashboard (zeroiza derived key, status pasa a LOCKED).
>
> **`u`** — `kvendra unlock` (pide master password si LOCKED).
>
> **`r`** — refresh forzado (la TUI ya hace polling cada 1 s).
>
> **`q`** — salir limpiamente, restaurando terminal (AC-TUI-3).

## Estados del vault

> **`UNLOCKED · session expires in <hh:mm:ss>`** — derived key en RAM, idle timer activo. El timer se resetea con cada `tools/call` o cualquier comando `kvendra <subcommand>`.
>
> **`LOCKED`** — sin derived key. Cualquier intento de invocar primitive falla con `VaultLocked`. Pulsa `u` para unlockar.
>
> **`UNLOCKED (keychain)`** — sesión active vía OS keychain ACL (modo `--use-keychain` del broker). El idle timer sigue aplicando, pero el siguiente unlock pedirá Touch ID / Windows Hello / libsecret en lugar de master password textual.

## Indicadores de profile

Columna final de cada profile:

> **`✓`** — válido y listo para uso.
>
> **`⚠`** — sin `expiration` declarado. No es error, pero el dashboard te lo marca como sugerencia para añadirlo. Tokens sin expiración acumulan riesgo en el tiempo.
>
> **`✗`** — `expiration < now`. Cualquier `tools/call` con este profile devolverá `ProfileExpired`. Rota el secret (`kvendra secret rotate <profile_id>`) y re-edita el `expiration` en el allowlist YAML.
>
> **`!`** — HMAC sidecar mismatch detectado al startup del broker. El profile está deshabilitado hasta que ejecutes `kvendra secret validate <profile_id>` y verifiques.

## Detection severity

Línea superior `Detection severity: <warn | error | block>`. Cambiable desde el dashboard (atajo futuro) o vía:

```bash
kvendra config set detection.severity warn
```

Detalles en el [capítulo 16](./16-detection-layer.md).

## Live tail integrado — `kvendra audit --watch`

Para observación en tiempo real focused (sin la vista global del dashboard):

```bash
kvendra audit --watch
```

Cubierto en el [capítulo 8](./08-audit-log.md). El dashboard y el watch tail son **mutuamente excluyentes** en el mismo terminal — cada uno pinta pantalla completa.

## Salida limpia del TUI

`q` o Ctrl+C restauran la terminal correctamente: cursor visible, modos `alternate screen` y `raw mode` desactivados, color reset (AC-TUI-3). Si por alguna razón terminas con la terminal en estado raro (ej. SIGKILL al binario, no SIGINT), `reset` o `tput sgr0; clear` la deja sana.

## Notas importantes

> **Nota:** El dashboard hace polling — no tiene websocket interno con el broker. Si arrancas un `kvendra mcp serve` en otro terminal, el dashboard reflejará la actividad en el siguiente refresh (≤1 s).

> **Nota:** En sistemas con monitor pequeño o terminal estrecha, el layout colapsa a vista compacta (oculta paneles secundarios). Mínimo recomendado: 80 columnas × 24 filas. Por debajo, usa `kvendra audit` y `kvendra secret list` directos.

> **Advertencia:** No te apoyes en el dashboard como única fuente de verdad para decisiones críticas (revocar profile, rotar tokens). El dashboard refleja el estado en disco; para verificación criptográfica completa usa `kvendra audit --verify` y `kvendra secret validate <profile_id>`.
