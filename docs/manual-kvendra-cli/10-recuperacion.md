# 10. Recuperación

## Descripción

Kvendra CLI ofrece **dos mecanismos independientes** de recuperación, generados ambos en `kvendra init` y mostrados al usuario una sola vez:

> **Recovery phrase BIP-39 (12 words)** — para *reset completo* del master password. La phrase se memoriza/anota offline; no vive en la máquina.
>
> **Recovery codes numéricos (8 codes)** — para *autenticar acciones críticas* sin proporcionar el master password. Argon2id-hashed en `~/.kvendra/recovery_codes.json`, single-use.

Este capítulo explica cuándo se usa cada uno, los flujos paso a paso y las garantías de seguridad. La diferencia conceptual entre ambos está en `GLO-KVD-010` (phrase) y `GLO-KVD-011` (codes).

## Recovery phrase BIP-39 — reset del master password

### Cuándo usarla

- Has olvidado el master password.
- Sospechas que el master password fue comprometido y quieres rotar.

### Paso 1 — Lance el flow de recovery

```bash
kvendra unlock --recover
```

El binario muestra:

```
Recovery mode. You will need:
  - Your 12-word BIP-39 recovery phrase (saved offline at kvendra init).

Type "yes" to continue:
```

### Paso 2 — Introduzca las 12 palabras

```
Enter word #1: abandon
Enter word #2: ability
...
Enter word #12: accident
```

Cada palabra se valida contra el wordlist BIP-39 estándar (autocompletion en clientes con tab support cuando se invoca interactivo). Una palabra fuera del wordlist aborta con error.

### Paso 3 — Set el nuevo master password

Tras validar la phrase:

```
✓ Recovery phrase verified.

Set new master password:
Confirm new master password:
```

El binario:

1. Deriva una key alternativa via BIP-39 → seed → derive scheme.
2. Descifra `recovery.blob` (que contiene una copia de la real master-password-derived key cifrada con la BIP-39 key).
3. Re-cifra todos los blobs de `~/.kvendra/secrets/` con la **nueva** clave Argon2id derivada del nuevo master password.
4. Re-genera el sentinel.blob.
5. Re-firma `config.toml` y los allowlists con las nuevas sub-keys HKDF.
6. Audit log: row `vault.recovery_completed`.

### Paso 4 — Verifique

```bash
kvendra unlock
```

Introduce el nuevo master password. Debe abrir sin error. La recovery phrase original sigue siendo válida (no se regenera salvo nuevo `kvendra init` desde cero).

## Recovery codes — autenticar acciones críticas

### Cuándo usarlos

Acciones que requieren confirmación adicional sobre el master password. En `0.1.0`:

> **`kvendra secret revoke <profile_id> --force`** — saltar la confirmación interactiva.
>
> **`kvendra config recovery-codes regenerate`** — invalidar el set actual y generar uno nuevo (post `0.1.0` patch — verifique disponibilidad con `kvendra config --help`).

Casos de uso futuros (post-MVP): re-key del audit chain, re-enable de keychain opt-in tras un reset, confirmación de operaciones destructive del broker.

### Paso 1 — Inicie la acción crítica

```bash
kvendra secret revoke github.kvendraai.org-admin --force
```

El binario muestra:

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

Disponible en patch post `0.1.0`. Comando:

```bash
kvendra config recovery-codes regenerate
```

Flujo:

1. Pide master password (autenticación, no recovery code — tienes que tenerlo).
2. Genera nuevos 8 códigos numéricos.
3. Argon2id-hashea con salt-per-code nuevo.
4. Sobrescribe `~/.kvendra/recovery_codes.json`.
5. Muestra los nuevos códigos una sola vez. Confirma offline-saved antes de continuar (mismo patrón que `kvendra init`).
6. Audit log: row `recovery_codes_regenerated`.

> **Advertencia:** Regenerar invalida el set anterior **completamente**. Si tenías códigos no usados anotados offline y los pierdes, has perdido esos códigos para siempre — el nuevo set los reemplaza.

## Diferencias entre los dos mecanismos

| | Recovery phrase | Recovery codes |
|---|---|---|
| **Cantidad** | 12 BIP-39 words | 8 numeric codes |
| **Storage** | Solo offline (tú) | `~/.kvendra/recovery_codes.json` (Argon2id-hashed) |
| **Uso** | Reset completo del master password | Confirmar acciones críticas (single-use) |
| **Reutilizable** | Sí, hasta nuevo `init` desde cero | No, single-use |
| **Regenerable** | Solo con re-init (destructive) | Sí: `kvendra config recovery-codes regenerate` |
| **Reset implícito de**: | Master password, todas las sub-keys, todos los blobs (re-cifrados) | Solo confirma una acción puntual |

## Casos de pérdida total

### He perdido master password Y recovery phrase

> **No hay recovery posible.** Es feature, no bug — exactamente la promesa zero-knowledge.
>
> Opciones:
>
> 1. Re-init desde cero: `rm -rf ~/.kvendra/ && kvendra init`. Pierdes todos los profiles y allowlists. Tendrás que rehacerlos. Los tokens originales en los servicios externos (GitHub, AWS, npm) **siguen siendo válidos** — solo has perdido las copias cifradas que tenías guardadas.
> 2. Restaurar desde backup propio (si lo mantienes — Kvendra `0.1.0` no gestiona backups).

### He perdido todos los recovery codes pero recuerdo el master password

Sin problema directo — los recovery codes solo son necesarios para acciones marcadas como críticas. Las operaciones normales (`secret add/list/rotate`, `mcp serve`, `audit`) funcionan solo con master password.

Para regenerar:

```bash
kvendra config recovery-codes regenerate
```

(Disponible post `0.1.0` patch; en `0.1.0` exacto, el flow es re-init si necesitas un set nuevo.)

## Notas importantes

> **Nota:** Las dos garantías clave son: (1) la recovery phrase **no vive en la máquina** — es responsabilidad tuya guardarla offline; (2) los recovery codes **single-use enforced** — Kvendra no aceptará el mismo código dos veces, ni siquiera si te equivocas tecleando.

> **Advertencia:** Si guardas la recovery phrase en un fichero `kvendra-backup.txt` en la misma máquina, has anulado la garantía zero-knowledge. La phrase debe vivir físicamente fuera del dispositivo (papel, gestor de contraseñas offline, caja fuerte, dispositivo separado). En entornos enterprise, política recomendada: phrase + codes en *split knowledge* — phrase a un custodian, codes a otro.
