# 10. Recuperación

## Descripción

Kvendra CLI genera en `kvendra init` **dos mecanismos independientes** — mostrados al usuario una sola vez — y en 0.6.4 los complementa con un **backup cifrado** (Pro tier), que es hoy el camino de recuperación operativo:

> **Recovery phrase BIP-39 (12 words)** — pensada para el *reset completo* del master password (`kvendra recover`). Se memoriza/anota offline; no vive en la máquina. **En 0.6.4 este reset está fail-closed** (ver abajo): guárdala igualmente para cuando se reactive.
>
> **Recovery codes numéricos (8 codes)** — barrera **adicional** sobre el master password para *autenticar acciones críticas* (p. ej. `config rebind-home`). Argon2id-hashed en `~/.kvendra/recovery_codes.json`, single-use.
>
> **Backup cifrado (`kvendra backup`, Pro tier)** — el camino de recuperación **recomendado hoy** mientras la mnemónica está deshabilitada.

Este capítulo explica cuándo se usa cada uno, los flujos paso a paso y las garantías de seguridad. La diferencia conceptual entre phrase y codes está en `GLO-KVD-010` (phrase) y `GLO-KVD-011` (codes); qué te protege y qué no, en llano, en [`../security/protection-levels.md`](../security/protection-levels.md).

## Recovery phrase BIP-39 — reset del master password

> **Advertencia (0.6.4):** La recuperación por mnemónica (`kvendra recover`) está **temporalmente deshabilitada / fail-closed** en esta versión. El comando **existe**, pero **rechaza** mientras se construye una implementación segura *mnemonic-bound* (antes aceptaba cualquier frase BIP-39 válida; ese fail-open se cerró). **No cuentes con `recover` para restaurar hoy.** El camino de recuperación real en 0.6.4 es un `kvendra backup` cifrado (ver abajo). Guarda igualmente tu mnemónica anotada, para cuando la recuperación se reactive. Detalle en llano: [`../security/protection-levels.md`](../security/protection-levels.md).

### Cuándo usarla (diseño previsto)

- Has olvidado el master password.
- Sospechas que el master password fue comprometido y quieres rotar.

En ambos casos, **hoy** la vía operativa es restaurar desde `kvendra backup` (o re-init si no tienes backup); ver «El camino real de recuperación hoy — `kvendra backup`».

### El comando `kvendra recover`

```bash
kvendra recover
```

Reset del master password usando la mnemónica BIP-39 (ADR-KVD-011). Flags reales (`kvendra recover --help`):

> **`--mnemonic-env <VAR>`** (env: `KVENDRA_RECOVERY_MNEMONIC`) — lee la mnemónica de esa variable de entorno (testing/CI) en vez de pedirla por prompt.
>
> **`--new-password-env <VAR>`** (env: `KVENDRA_NEW_PASSWORD`) — lee el nuevo master password de esa variable de entorno (testing/CI).

> **Nota:** En 0.6.4 este comando **rechaza fail-closed** aunque introduzcas la mnemónica correcta. El diseño previsto (cuando se reactive) descifra `recovery.blob`, deriva la nueva clave Argon2id del nuevo master password, re-cifra los blobs de `~/.kvendra/secrets/`, regenera `sentinel.blob`, re-firma `config.toml` y los allowlists, y registra `vault.recovery_completed` en el audit log. Ninguna de esas escrituras ocurre hoy: el comando aborta antes.

## El camino real de recuperación hoy — `kvendra backup`

Mientras la mnemónica está fail-closed, el **backup cifrado en la nube (Pro tier)** es la ruta fiable de recuperación. El vault se sube cifrado; el destino sigue necesitando tu master password para descifrarlo.

```bash
# autenticación Pro (persiste el JWT en ~/.kvendra/sessions/pro.token)
kvendra login --pro

# subir el vault cifrado
kvendra backup push --label "pre-migracion-portatil"

# en la máquina nueva (o tras un desastre): listar y restaurar
kvendra backup list
kvendra backup pull                 # trae y restaura el último
kvendra backup restore <BACKUP_ID>  # restaura una versión concreta
```

Subcomandos de `kvendra backup` (`--help`): `push` (con `--force`, `--label`, `--password-stdin`), `list` (`--limit`), `pull` (`--id`, `--yes`, `--out`, `--password-stdin`), `restore <BACKUP_ID>` (`--yes`, `--password-stdin`) y `prune <BACKUP_ID>` (`--yes`). Requiere Pro tier y `kvendra login --pro`.

> **Nota:** Guarda **igualmente** tu mnemónica BIP-39 anotada offline. Cuando la recuperación mnemónica se reactive en una versión futura, volverá a ser el segundo mecanismo independiente. Hasta entonces, backup + master password es la combinación operativa.

## Recovery codes — autenticar acciones críticas

### Cuándo usarlos

Los recovery codes autentican **acciones críticas** como barrera adicional sobre el master password. La acción canónica que **consume un código** en `0.6.4` es:

> **`kvendra config rebind-home --new-path <PATH>`** — re-anclar el vault a una nueva ubicación tras mover `~/.kvendra/` (REQ-KVD-008). Verificación de **triple barrera**: master password + **un recovery code** + confirmación por TTY.

No confundir con `kvendra config recovery-codes regenerate`, que **no** consume un código: usa **doble barrera** (master password + teclear el acknowledge `REGENERATE-RECOVERY-CODES`) — ver «Regenerar el set de recovery codes».

### Paso 1 — Inicie la acción crítica

```bash
kvendra config rebind-home --new-path /Volumes/EncryptedDisk/.kvendra
```

El binario, tras pedir el master password, muestra:

```
This action requires a recovery code to confirm.
You have 6 recovery codes remaining.

Enter recovery code:
```

### Paso 2 — Introduzca un código

Pegue uno de los 8 códigos generados en `kvendra init`. Format esperado: `NNNN-NNNN-NNNN` (digits + hyphens). El binario:

1. Hashes el input con Argon2id usando el salt del code candidato (busca por iteración en los 8 hashes guardados).
2. Compara con `subtle::ConstantTimeEq`.
3. Match → marca el código como `used_at: <now>`, ejecuta la acción.
4. No match → falla con error genérico (no revela cuál no matcheó), incrementa contador anti-bruteforce.

### Garantías

> **Single-use enforced** — un código consumido queda marcado `used_at`; el siguiente intento con el mismo número falla con `RecoveryCodeAlreadyUsed`.
>
> **Audit log** — fila `recovery_code_consumed` con el `code_id` (1-8), `action` que se autorizó. Intentos fallidos generan `recovery_code_replay_attempted` (post alpha.11).
>
> **Argon2id cost** — los codes son single-use y de longitud fija; el cost se calibra para no penalizar UX en confirmation flows pero suficiente para resistir bruteforce offline si el `recovery_codes.json` se exfiltra.
>
> **Storage** — `~/.kvendra/recovery_codes.json` con permissions `0600`, hashes Argon2id+salt-per-code, no contiene los códigos en plaintext.

### Paso 3 — Tras la acción

El binario muestra advertencia si quedan ≤2 códigos sin usar:

```
✓ Action completed.
⚠ You have 2 recovery codes remaining. Consider regenerating:
  kvendra config recovery-codes regenerate
```

Esta advertencia también aparece como warning en `kvendra dashboard`.

## Regenerar el set de recovery codes

Disponible en `0.6.4` (REQ-KVD-CLI-003). Comando:

```bash
kvendra config recovery-codes regenerate
```

**Doble barrera** (`kvendra config recovery-codes regenerate --help`): master password + teclear por TTY el acknowledge exacto `REGENERATE-RECOVERY-CODES`. Flujo:

1. Pide el master password (autenticación; **no** consume un recovery code).
2. Pide teclear literalmente `REGENERATE-RECOVERY-CODES` para confirmar.
3. Genera 8 códigos numéricos nuevos y los Argon2id-hashea con salt-per-code nuevo.
4. Sobrescribe `~/.kvendra/recovery_codes.json`.
5. Muestra los nuevos códigos una sola vez. Confírmalos guardados offline antes de continuar (mismo patrón que `kvendra init`).
6. Audit log: row `recovery_codes_regenerated`.

> **Advertencia:** Regenerar invalida el set anterior **completamente**. Si tenías códigos no usados anotados offline y los pierdes, has perdido esos códigos para siempre — el nuevo set los reemplaza.

## Diferencias entre los dos mecanismos

| | Recovery phrase | Recovery codes |
|---|---|---|
| **Cantidad** | 12 BIP-39 words | 8 numeric codes |
| **Storage** | Solo offline (tú) | `~/.kvendra/recovery_codes.json` (Argon2id-hashed) |
| **Uso** | Reset completo del master password (**fail-closed en 0.6.4**; ver arriba) | Confirmar acciones críticas como `config rebind-home` (single-use) |
| **Reutilizable** | Sí, hasta nuevo `init` desde cero | No, single-use |
| **Regenerable** | Solo con re-init (destructive) | Sí: `kvendra config recovery-codes regenerate` |
| **Reset implícito de**: | Master password, todas las sub-keys, todos los blobs (re-cifrados) | Solo confirma una acción puntual |

## Casos de pérdida total

### He perdido master password Y recovery phrase

> **No hay recovery posible.** Es feature, no bug — exactamente la promesa zero-knowledge.
>
> Opciones:
>
> 1. **Restaurar desde `kvendra backup`** (Pro tier), si mantienes uno: `kvendra login --pro && kvendra backup pull`. Recuperas el vault cifrado, pero **sigues necesitando el master password** para descifrarlo — así que esto solo ayuda si perdiste la máquina, no el password. Es el camino de recuperación recomendado hoy (la mnemónica está fail-closed).
> 2. Re-init desde cero: `rm -rf ~/.kvendra/ && kvendra init`. Pierdes todos los profiles y allowlists. Tendrás que rehacerlos. Los tokens originales en los servicios externos (GitHub, AWS, npm) **siguen siendo válidos** — solo has perdido las copias cifradas que tenías guardadas.

### He perdido todos los recovery codes pero recuerdo el master password

Sin problema directo — los recovery codes solo son necesarios para acciones marcadas como críticas. Las operaciones normales (`secret add/list/rotate`, `mcp serve`, `audit`) funcionan solo con master password.

Para regenerar:

```bash
kvendra config recovery-codes regenerate
```

(Disponible en `0.6.4` con doble barrera: master password + acknowledge `REGENERATE-RECOVERY-CODES`.)

## Notas importantes

> **Nota:** Las dos garantías clave son: (1) la recovery phrase **no vive en la máquina** — es responsabilidad tuya guardarla offline; (2) los recovery codes **single-use enforced** — Kvendra no aceptará el mismo código dos veces, ni siquiera si te equivocas tecleando.

> **Advertencia:** Si guardas la recovery phrase en un fichero `recovery-phrase.txt` en la misma máquina, has anulado la garantía zero-knowledge (esto es distinto del `kvendra backup` cifrado, que sí es seguro porque va cifrado con tu master password). La phrase debe vivir físicamente fuera del dispositivo (papel, gestor de contraseñas offline, caja fuerte, dispositivo separado). En entornos enterprise, política recomendada: phrase + codes en *split knowledge* — phrase a un custodian, codes a otro.
