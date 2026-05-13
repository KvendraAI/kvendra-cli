# 22. FAQ y troubleshooting

## Descripción

Catálogo de errores comunes, patterns conocidos (`PAT-KVD-*` en KB v3) y preguntas que aparecen recurrentemente. La fuente canónica para incidentes y postmortems es el KB v3 (`PAT-KVD-*`, `ISSUE-KVD-CLI-*`); este capítulo recopila los más frecuentes para acceso rápido.

## Errores comunes

### "VaultLocked" en `tools/call`

> **Síntoma**: el agente recibe `VaultLocked` en respuesta a una invocación que antes funcionaba.
>
> **Causas posibles**:
>
> 1. **Idle timeout** — la sesión expiró por inactividad (default 30 min).
> 2. **Lock manual** — alguien ejecutó `kvendra lock` (o `l` en el TUI dashboard).
> 3. **Reinicio del subprocess** — el cliente MCP relanzó `kvendra mcp serve` y la sesión nueva está locked.
>
> **Fix**:
>
> - Modo TTY: ejecutar `kvendra unlock`.
> - Modo `--use-keychain`: el siguiente `tools/call` debería disparar el biometric prompt automáticamente.
> - Si la sesión sigue bloqueada tras unlock, ver el patrón `PAT-KVD-009` más abajo.

### "ProfileExpired"

> **Síntoma**: `ProfileExpired` en `tools/call`.
>
> **Causa**: el field `expiration` del allowlist YAML está antes de la fecha actual.
>
> **Fix**:
>
> 1. Rotar el secret en el servicio externo (ej. genera un PAT nuevo en GitHub).
> 2. `kvendra secret rotate <profile_id>` con el nuevo plaintext.
> 3. Editar el YAML del allowlist, actualizar `expiration: <YYYY-MM-DD>`.
> 4. `kvendra secret validate <profile_id>` para refrescar el HMAC sidecar.

### "AllowlistViolation"

> **Síntoma**: `AllowlistViolation` con detail `<field>` denied.
>
> **Causa**: el agente está intentando una operación fuera de scope del allowlist.
>
> **Fix**:
>
> - Revisar el YAML del allowlist y comparar con la operación intentada.
> - `kvendra secret validate <profile_id>` muestra qué está y qué no permitido.
> - Si la operación es legítima, ampliar el allowlist (con cuidado — los defaults restrictivos están por algo).
> - Si no es legítima, el rechazo es el comportamiento correcto.

### "Chain broken at row N" en `audit --verify`

Cubierto en el [capítulo 8](./08-audit-log.md). Causas posibles: tampering, schema migration sin re-sign, file corruption.

### Binario macOS bloqueado por Gatekeeper

> **Síntoma**: `"kvendra" cannot be opened because the developer cannot be verified.`
>
> **Fix**:
>
> 1. *System Settings → Privacy & Security → Allow Anyway* sobre la entrada de `kvendra`.
> 2. Reintenta — macOS pedirá confirmación final, ya pasa.
>
> Alternativa CLI: `xattr -d com.apple.quarantine ~/.local/bin/kvendra` (saltarse Gatekeeper consciente).
>
> Track de signing canónico: `ROAD-KVD-CLI-002` (`0.2.0`).

### `kvendra mcp serve` no aparece como connected en el cliente

> **Síntoma**: `/mcp` en Claude Code no lista `kvendra`.
>
> **Causas posibles**:
>
> 1. **`PATH` issue** — el cliente MCP no encuentra el binario. Algunos clientes lanzan subprocess con `PATH` reducido.
> 2. **Permisos** — el binario no tiene execute bit (raro tras `cargo install`).
> 3. **Sintaxis mal en `~/.claude.json`** — JSON inválido.
>
> **Fix**:
>
> - Usar ruta absoluta en `command`: `"command": "/Users/<you>/.cargo/bin/kvendra"`.
> - Verificar que `kvendra --version` corre desde el shell del cliente.
> - Validar el JSON con `jq < ~/.claude.json`.

## Patterns conocidos (`PAT-KVD-*`)

### `PAT-KVD-009` — restart Claude Code es el fix

> **Contexto**: tras un periodo prolongado sin actividad, el agente AI (Claude Code) sigue mostrando `kvendra` como connected pero los `tools/call` fallan o cuelgan. Hace `kvendra unlock` no resuelve.
>
> **Causa raíz**: el cliente MCP cachea el handshake con el subprocess. Cuando el subprocess sale por idle timeout y vuelve a arrancar, el handshake del cliente puede quedar desincronizado. Es un patrón observado del lado del cliente, no de Kvendra.
>
> **Fix canónico**: **reiniciar Claude Code** (no solo unlockar Kvendra). Una vez Claude Code rearranca, abre un subprocess `kvendra mcp serve` fresh y el handshake va limpio.
>
> **Follow-up**: `ISSUE-KVD-CLI-029` traquea un subcomando para forzar restart desde Kvendra side. No bloqueante.
>
> **Trazabilidad**: la fuente canónica de este patrón es `PAT-KVD-009` en KB v3, también referenciada en memoria local del workspace.

### `PAT-KVD-CLI-001` — approval gate funciona sin Apple Dev ID

> **Contexto**: previo a `0.1.0` se consideraba que el approval gate ("Touch ID-protected MCP password") requería Apple Developer ID para funcionar como advertencia visual.
>
> **Realidad**: el modal macOS consent-only (sin Touch ID) funciona igual de bien para el threat model L1. La diferencia es **factor humano de marketing**, no técnico.
>
> **Consecuencia**: `ROAD-KVD-CLI-001` se rebranded para no bloquear `0.1.0` en Apple Dev ID. Track separado `ROAD-CLI-002` (`0.2.0`) para "Mac compatible" canonical signed.

### `PAT-KVD-004` — shape MCP envelope mismatch

> **Contexto**: el bug original que rompió 22 fields del enforcer silenciosamente. Las 3 branches enforced miraban al envelope completo en lugar de a los inner args (`arguments.args`).
>
> **Lección**: cualquier branch del enforcer debe usar el helper TIER 0 `inner_args(envelope)` antes de evaluar campos. Patrón canónico documentado inline en `src/allowlist/enforcer.rs` y formalizado en doc-comment.
>
> **Test de regresión**: `tests/integration_aws_allowlist_boundary.rs` con regression canónico AC-M2-6.

## Preguntas frecuentes

### ¿Por qué el binario es Apache-2.0 y no MIT?

`ADR-KVD-004`: Apache-2.0 incluye **patent grant explícito** (Section 3) — más seguro para código que toca cripto. MIT no lo tiene. La mayoría de corporate compliance acepta ambos sin diferencia, pero Apache da un nivel extra de protección legal.

### ¿Puedo usar Kvendra CLI offline?

Sí. El binario no tiene telemetry ni hace ninguna llamada a kvendra.com durante operación normal. Las únicas llamadas a red son las que **tú** disparas vía primitives (`kvendra.github.read_issue` llama a `api.github.com`, etc.).

### ¿Y si quiero un primitive que no existe?

Tres opciones:

> **Si es genérico HTTP** — usa `kvendra.http` con allowlist estricto del URL pattern.
>
> **Si es genérico shell** — usa `kvendra.shell` con `args_constraints` específicos.
>
> **Si nada de lo anterior cubre** — `kvendra.unsafe.raw_token` es el escape hatch documentado. Audit-flagged unsafe; opt-in explícito en el profile.

A futuro, el marketplace (`kvendra-skills`, post-MVP) permitirá primitives community-contributed (`kvendra.linear`, `kvendra.notion`, etc.).

### ¿Por qué el master password no se puede recuperar por email?

Por diseño. La promesa zero-knowledge implica que ningún canal externo (incluido Kvendra) tiene capacidad para descifrar tu vault. El recovery vive en la **recovery phrase BIP-39** que tú anotaste offline en `kvendra init`. Si la pierdes también, el vault se va — feature, no bug. Ver [capítulo 10](./10-recuperacion.md).

### ¿Por qué `serde_yml` y no `serde_yaml`?

`serde_yaml` está sin mantenimiento upstream desde 2024. `serde_yml` es el fork que recoge security fixes. Trade-off documentado en `ADR-KVD-008`.

### ¿Por qué Argon2id y no scrypt o bcrypt?

Argon2id es el ganador de Password Hashing Competition 2015 y la recomendación canónica de OWASP / IETF para password hashing en 2026. scrypt es viable pero menos parametrizable. bcrypt es legacy. Detalle en el [capítulo 12](./12-vault-criptografia.md).

### ¿Por qué AES-256-GCM y no ChaCha20-Poly1305?

Performance comparable; AES-256-GCM tiene aceleración hardware en CPU modernas (AES-NI). En contextos donde no hay AES-NI (algunos ARM low-power), ChaCha20-Poly1305 sería más rápido — pero el target de Kvendra es laptop/desktop con AES-NI presente. ChaCha20-Poly1305 está en `Cargo.toml` como alternative_aead documentado en `REQ-KVD-002`; no usado en `0.1.0`.

### ¿Cómo audito que el binario no tiene backdoors?

Apache-2.0 te da el código fuente completo. La auditoría canónica:

1. Clonar `KvendraAI/kvendra-cli`.
2. `cargo install --path . --locked` (build local desde fuente).
3. Comparar checksum del binario con el de GitHub Releases (deben coincidir si `cargo` y toolchain son las mismas — reproducible builds **no** garantizadas en `0.1.0`, llegan en `0.3.0`).
4. Auditar el path crypto: `vault::session`, `vault::kdf`, `vault::crypto`, `mcp::server::build_sanitized_payload`. La promesa REQ-KVD-002 dice que un reviewer externo lo hace en ≤2h.

### ¿Hay paquete oficial en Homebrew / apt / yum?

No en `0.1.0`. Track:

> Homebrew: `0.2.0` (`ROAD-KVD-CLI-002`).
>
> apt / yum: futuro, sin fecha.
>
> AUR / Snap / Flatpak / Nix: post-Beta, mantenido por community.

Por ahora: `cargo install kvendra` o GitHub Releases.

## Cómo reportar un bug

> **Bug normal**: GitHub issue en `KvendraAI/kvendra-cli`.
>
> **Security bug**: NO public issue. Email a `hello@kvendra.ai` siguiendo `SECURITY.md` (RFC 9116).

Para bugs reproducibles, incluye:

- Versión del binario: `kvendra --version`.
- OS y arquitectura: `uname -a`.
- Cliente MCP usado (Claude Code, Cursor, Cline, ...).
- Pasos para reproducir.
- Si aplica: row de audit del intento fallido (`kvendra audit --json | jq '.[-1]'`).

## Notas importantes

> **Nota:** Si encuentras un patrón nuevo que merece documentación, este manual `internal` es buen sitio para anotarlo provisionalmente, pero la fuente canónica del proyecto es el KB v3 (`PAT-KVD-*`). Pasar de "anotación local" a "PAT en KB v3" es el step correcto cuando el patrón se valida en uso real.

> **Advertencia:** No conviertas este capítulo en un dump de errores efímeros. Cada entry debe tener: síntoma, causa, fix. Los errores que solo aplican a una versión vieja del binario o a un setup específico no escalan — viven mejor como issue cerrada o changelog entry.
