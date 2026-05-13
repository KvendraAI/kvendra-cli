# 3. Instalación

## Descripción

`kvendra` `0.1.0` se distribuye por dos canales: **crates.io** (`cargo install`) y **GitHub Releases** (binarios `cargo-dist` cross-platform sin firma). Otros canales (Homebrew, npm wrapper, pip wrapper, winget, scoop) son post-MVP — están planificados pero no entregados en esta versión.

Existe una guía corta complementaria en `docs/install.md` del repo. Este capítulo cubre la decisión de canal por sistema operativo, requisitos y validación post-instalación.

## Canales disponibles en `0.1.0`

> **crates.io**
> - Comando: `cargo install kvendra`
> - Requiere: toolchain Rust estable, MSRV 1.85.
> - Plataformas: cualquiera donde haya `cargo` y compile el árbol de deps (macOS arm64+x86_64, Linux x86_64, Windows x86_64).
> - Tamaño: la build local del binario release dura entre 2 y 6 minutos según hardware.
>
> **GitHub Releases (`KvendraAI/kvendra-cli`)**
> - Comando: descarga del archivo `.tar.gz` o `.zip` para tu plataforma desde el tag `v0.1.0`.
> - Requiere: nada — son binarios precompilados sin firma.
> - Plataformas: `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`.
> - Caveat macOS: el binario no está firmado con Apple Developer ID. Tendrás que aprobar el primer arranque desde *System Settings → Privacy & Security*. Ver [capítulo 20](./20-roadmap.md) para la track `0.2.0` que añade signing.

## Requisitos por plataforma

### macOS

> **Arquitecturas soportadas:** Apple Silicon (`aarch64`) y x86_64 (Intel).
>
> **Versión mínima:** macOS 13 (Ventura) por requisito de `security-framework` 3 (keyring nativo).
>
> **Dependencias del sistema:** ninguna — `keyring` linka contra el framework `Security` de Apple, ya presente.

### Linux

> **Arquitectura soportada:** `x86_64-unknown-linux-gnu` en `0.1.0`. ARM Linux no se distribuye binario; usar `cargo install`.
>
> **Versión mínima del kernel:** la que requiera `secret-service` (libsecret). Distros modernas con GNOME / KDE lo traen.
>
> **Dependencias del sistema:** `libsecret` para integración con keyring del sistema (modo opt-in). Si no instalas `libsecret`, el binario funciona en modo RAM-only sin pérdida de funcionalidad — sólo se pierde la opción biométrica/keychain.

### Windows

> **Arquitectura soportada:** `x86_64-pc-windows-msvc`.
>
> **Versión mínima:** Windows 10 / Windows Server 2016 por requisito de `windows-credentials` (Credential Manager).
>
> **Dependencias del sistema:** ninguna — el keyring usa la API nativa de Windows.

## Pasos de instalación

### Paso 1 — Elija el canal

| Caso | Canal recomendado |
|------|-------------------|
| Tienes toolchain Rust instalado y aceptas un build local | `cargo install kvendra` |
| No tienes Rust o quieres instalación inmediata | GitHub Releases |
| Vas a usar el binario en CI matrix | GitHub Releases (artefacto reproducible) |

### Paso 2 — Ejecute la instalación

**Vía crates.io:**

```bash
cargo install kvendra --locked
```

El flag `--locked` instala respetando `Cargo.lock`. Recomendado para reproducibilidad.

**Vía GitHub Releases (macOS arm64 ejemplo):**

```bash
curl -fsSL https://github.com/KvendraAI/kvendra-cli/releases/download/v0.1.0/kvendra-aarch64-apple-darwin.tar.gz \
  | tar -xz -C ~/.local/bin/
```

Asegúrese de que `~/.local/bin/` está en su `PATH`.

### Paso 3 — Verifique la instalación

```bash
kvendra --version
```

Salida esperada:

```
kvendra 0.1.0
```

Si ve `0.1.0-alpha.<n>`, está usando una build pre-stable; actualice a `0.1.0`.

### Paso 4 — Compruebe los subcomandos

```bash
kvendra --help
```

Debe enumerar al menos: `init`, `unlock`, `lock`, `secret`, `primitive`, `mcp`, `dashboard`, `audit`, `config`, `completion`. Cada subcomando tiene `--help` propio con ejemplos.

### Paso 5 — Configure shell completion (opcional)

`clap_complete` genera scripts para bash, zsh y fish:

```bash
# bash
kvendra completion bash > /usr/local/etc/bash_completion.d/kvendra

# zsh
kvendra completion zsh > "${fpath[1]}/_kvendra"

# fish
kvendra completion fish > ~/.config/fish/completions/kvendra.fish
```

Reinicie su shell para activar el autocompletado.

## Aprobación del binario unsigned en macOS

El primer intento de ejecutar el binario descargado de GitHub Releases en macOS produce un mensaje del tipo:

> *"kvendra" cannot be opened because the developer cannot be verified.*

Hay dos formas de aprobar la ejecución:

**Vía System Settings (recomendado):**

1. Ejecute el binario una vez (recibirá el mensaje de bloqueo).
2. Vaya a *System Settings → Privacy & Security*.
3. Pulse *Allow Anyway* sobre la entrada de `kvendra`.
4. Vuelva a ejecutar el binario; macOS pedirá confirmación final.

**Vía CLI (saltarse Gatekeeper para ese binario):**

```bash
xattr -d com.apple.quarantine ~/.local/bin/kvendra
```

> **Advertencia:** Saltarse Gatekeeper es una decisión consciente. Hágalo solo después de comprobar que el binario coincide con los checksums publicados en el GitHub Release. La track de signing canónico llega en `0.2.0` (ver [capítulo 20](./20-roadmap.md)) y desactivará la necesidad de aprobación manual.

## Próximos pasos

Una vez instalado y verificado el binario, continúe con el [capítulo 4](./04-bootstrap-vault.md) para inicializar su vault con `kvendra init`.

## Notas importantes

> **Nota:** Los placeholders `kvendraai` y `kvendra-cli` también existen en crates.io como squat-prevention defensivo, pero el package canónico es siempre `kvendra` (per `ADR-KVD-005` y registro en `DOC-KVD-001`).

> **Nota:** Si su sistema no aparece en la lista de targets de GitHub Releases, `cargo install kvendra --locked` es la ruta universal. La compilación local genera un binario nativo equivalente al publicado.
