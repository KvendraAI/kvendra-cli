# 19. Stack técnico

## Descripción

Inventario canónico del stack de `0.6.4`: crates Rust con versiones reales (`Cargo.toml`), features Cargo activas, MSRV, decisiones de licencia/edition. Las decisiones detrás están en `ADR-KVD-005` (Rust como lenguaje), `ADR-KVD-006` (MCP layer thin propio), `ADR-KVD-007` (rusqlite bundled), `ADR-KVD-008` (fork YAML mantenido) y `ADR-KVD-009` (MSRV).

## Lenguaje y toolchain

> **Lenguaje:** Rust
>
> **Edition:** 2024
>
> **MSRV:** 1.88 (`rust-version` en `Cargo.toml`; edition 2024 requiere ≥1.85, el resto del stack eleva el mínimo efectivo a 1.88)
>
> **Toolchain:** stable
>
> **License:** Apache-2.0
>
> **Crate name:** `kvendra` (canónico) en crates.io
>
> **Binary name:** `kvendra`

## Dependencias principales

Todas las versiones reflejan el `Cargo.toml` real de `0.6.4`:

| Crate | Versión | Features | Uso |
|-------|---------|----------|-----|
| `clap` | 4 | `derive`, `env` | CLI parsing |
| `clap_complete` | 4 | — | Shell completions (bash, zsh, fish) |
| `rpassword` | 7 | — | Password prompt sin echo |
| `tokio` | 1 | `macros`, `rt-multi-thread`, `sync`, `io-std`, `io-util`, `time`, `fs`, `process`, `signal` | Async runtime |
| `serde` | 1 | `derive` | Serialization |
| `serde_json` | 1 | — | JSON-RPC, audit JSON export |
| `serde_yaml_ng` | 0.10 | — | Allowlist YAML parser (fork mantenido de `serde_yaml`, deprecated upstream) |
| `toml` | 0.8 | — | `config.toml` |
| `argon2` | 0.5 | — | KDF (master password → derived key) |
| `aes-gcm` | 0.10 | — | AEAD AES-256-GCM (blobs) |
| `zeroize` | 1 | `zeroize_derive` | Memory clearing en `Drop` |
| `subtle` | 2 | — | Constant-time comparisons |
| `hmac` | 0.12 | — | Audit chain, sidecars HMAC |
| `sha2` | 0.10 | — | Hash subyacente de HMAC/HKDF |
| `hkdf` | 0.12 | — | Domain separation de sub-keys (audit, allowlist, config, session-wrap, backup) |
| `rand` | 0.8 | — | RNG |
| `ed25519-dalek` | 2 | `rand_core`, `zeroize` | Firma asimétrica de grants break-glass ([cap. 23](./23-break-glass.md)) |
| `serde_jcs` | 0.1 | — | Canonicalización JCS (RFC 8785) del grant antes de firmar |
| `bip39` | 2 | `rand` | Recovery phrase 12 words |
| `rusqlite` | 0.31 | `bundled` | SQLite (audit.db) |
| `keyring` | 3 | `apple-native`, `windows-native`, `linux-native-sync-persistent` | OS keychain integration |
| `reqwest` | 0.12 | `rustls-tls`, `json`, `stream`, `multipart` | HTTP client (primitives, workspace, backup) |
| `ratatui` | 0.29 | feature-gated `tui` | TUI layer |
| `crossterm` | 0.28 | feature-gated `tui` | TUI backend |
| `thiserror` | 1 | — | Error definitions |
| `anyhow` | 1 | — | Error context propagation |
| `tracing` | 0.1 | — | Structured logging |
| `tracing-subscriber` | 0.3 | `env-filter` | Tracing init |
| `regex` | 1 | — | Detection layer + URL allowlist matcher |
| `time` | **0.3.47** | `formatting`, `macros`, `parsing` | Date/time helpers — pinned post `RUSTSEC-2026-0009` |
| `hex` | 0.4 | — | Hex encoding (audit dump, hashes) |
| `base64` | 0.22 | — | Base64 encoding (blobs, audit export) |

### Crates de modo workspace y export/backup (M1/M2 Sprint 4-5)

| Crate | Versión | Uso |
|-------|---------|-----|
| `async-trait` | 0.1 | `SecretResolver` trait async (local vs remote broker) |
| `chrono` | 0.4 (`clock`, `serde`, `default-features=false`) | Timestamps del modo workspace |
| `url` | 2 | Parsing de endpoints OIDC / broker |
| `urlencoding` | 2 | Encoding de parámetros del flujo PKCE |
| `fs2` | 0.4 | `flock` sobre blobs de sesión / grants |
| `tiny_http` | 0.12 | Loopback listener del redirect OIDC PKCE |
| `webbrowser` | 1 | Abre el navegador para el login workspace |
| `serde_jcs` | 0.1 | Export de audit firmado (JSON canónico) + grants |
| `csv` | 1.3 | Export de audit en CSV (`kvendra audit export`) |
| `printpdf` | 0.7 | Export de audit en PDF (`kvendra audit export`) |
| `tar` | 0.4 | Empaquetado del bundle de `kvendra backup` |

### Dependencias platform-specific

| Plataforma | Crate | Versión | Uso |
|-----------|-------|---------|-----|
| macOS | `security-framework` | 3 | SecAccessControl + SecItem* (biometric ACL, REQ-KVD-005 / ISSUE-KVD-CLI-017) |
| macOS | `security-framework-sys` | 2 | Direct deps para lo anterior |
| macOS | `core-foundation` | 0.10 | macOS FFI |
| macOS | `core-foundation-sys` | 0.8 | macOS FFI |
| Unix (Linux + macOS) | `libc` | 0.2 | SIGPIPE handler (ISSUE-KVD-CLI-042 — instala `SIG_DFL` para evitar el panic default de Rust) y `gethostname`/`getuid` del session-wrap |

### Dev-dependencies

| Crate | Versión | Uso |
|-------|---------|-----|
| `assert_cmd` | 2 | E2E tests del binario |
| `predicates` | 3 | Assertion combinators |
| `tempfile` | 3 | Tests con `~/.kvendra/` aislado |

## Cargo features

| Feature | Default | Gates |
|---------|:-------:|-------|
| `tui` | **on** | `ratatui` 0.29 + `crossterm` 0.28 (TUI dashboard + audit watch). Disable para builds headless / minimal. |

`0.6.4` expone una sola feature pública (`default = ["tui"]`). Las capacidades macOS (biometric ACL) y Unix (SIGPIPE) se activan por `cfg(target_os)` / `cfg(unix)`, no por feature flag.

## Build reproducibility

`Cargo.lock` está committeado (decisión estándar para binarios). `cargo install kvendra --locked` respeta el lockfile. La CI matrix corre con `--locked` para garantizar reproducibilidad.

## Plataformas soportadas

| Target | Status `0.6.4` | Notas |
|--------|---------------|-------|
| `aarch64-apple-darwin` | binario en GitHub Releases | unsigned |
| `x86_64-apple-darwin` | binario en GitHub Releases | unsigned |
| `x86_64-unknown-linux-gnu` | binario en GitHub Releases | unsigned |
| `x86_64-pc-windows-msvc` | binario en GitHub Releases | unsigned |
| Otros (`aarch64-unknown-linux-gnu`, BSDs) | via `cargo install` | sin binario precompilado |

> **Nota:** las releases se distribuyen **sin firmar** en `0.6.4`. El code-signing (Apple Developer ID, Windows Authenticode, GPG) sigue siendo un item futuro **sin versión comprometida** — verifica la procedencia del binario hasta que las releases firmadas existan (ver [capítulo 18](./18-threat-model.md), vector O2).

## CI matrix

| Job | OS | Arch | Toolchain |
|-----|----|----|-----------|
| `build` + `test` | `ubuntu-latest` | x86_64 | stable |
| `build` + `test` | `macos-latest` | arm64 | stable |
| `build` + `test` | `windows-latest` | x86_64 | stable |

`AC-CLI-4` exige verde en los 3. La matrix está en `.github/workflows/ci.yml`. Smoke harness E2E (`scripts/e2e-smoke.sh`) se documenta en `docs/smoke.md`.

## Decisión yaml — fork mantenido vs `serde_yaml`

`ADR-KVD-008`: `serde_yaml` está sin mantenimiento upstream desde 2024, así que el CLI usa un fork drop-in mantenido con security fixes — `serde_yaml_ng` 0.10. Trade-off: depender de un fork, mitigado por la simplicidad del subset de YAML que usamos (el allowlist DSL es mostly key-value + arrays planos).

## Decisión MCP layer — thin propio

`ADR-KVD-006`: thin JSON-RPC propio en lugar de adoptar el SDK comunitario `rmcp`. Justificado en el [capítulo 13](./13-mcp-server.md). Coste eng: ~2-3 días de implementación inicial; mantenimiento: mínimo (subset estable de MCP).

## Decisión firma asimétrica — `ed25519-dalek` para break-glass

`ed25519-dalek` 2 (con `rand_core` sobre `rand` 0.8 `OsRng`, y `zeroize` del seed). El HMAC simétrico **no** sirve para el grant break-glass: el hook verifica **sin** unlock del vault, así que una clave simétrica visible al verificador permitiría forjar grants. La firma asimétrica deja la pubkey pinada en `.kvendra-protected` y el seed privado sellado bajo la clave maestra ([capítulo 23](./23-break-glass.md)).

## Crates ausentes deliberadamente

> **`sqlx`** — no aporta sobre `rusqlite` para el audit log local sync (decisión `ADR-KVD-007`).
>
> **`openssl`** — el stack es rustls-only (`reqwest` con `rustls-tls`). Evita complicaciones de FFI con OpenSSL del sistema.
>
> **`rmcp`** — se implementa un thin JSON-RPC propio (`ADR-KVD-006`); reevaluable si el SDK madura.
>
> **`tonic` / gRPC** — no necesitamos gRPC; MCP usa JSON-RPC sobre stdio.
>
> **`rocket` / `axum`** — no hay HTTP server-side persistente. Solo client (`reqwest`), stdio (MCP) y un `tiny_http` efímero para el redirect OIDC.
>
> **`ring`** — RustCrypto (`aes-gcm`, `argon2`, `hmac`, `sha2`, `hkdf`, `ed25519-dalek`) es suficiente. Evita FFI a `ring`.

## Versiones críticas pinneadas

| Crate | Versión exacta | Razón |
|-------|---------------|-------|
| `time` | `0.3.47` | Post RUSTSEC-2026-0009 fix; no descender |
| `serde_yaml_ng` | `0.10` | Fork mantenido de `serde_yaml`; verificar antes de bump |

## Decisión MSRV

`ADR-KVD-009`: MSRV `1.88` (`rust-version` en `Cargo.toml`). Edition 2024 requiere ≥1.85; el mínimo efectivo sube a 1.88 por el resto del stack. Coste: usuarios con toolchain antigua no pueden `cargo install`. Aceptable — cualquier dev activo en 2026 tiene una stable ≥1.88.

## Roadmap del stack

Cambios de stack previstos siguen la roadmap de endurecimiento del vault (`ROAD-KVD-CLI-393064`, ver [capítulo 20](./20-roadmap.md)). Ninguno cambia el default; todos son opt-in:

> **Hardware-backed keys** — Secure Enclave en macOS (via `security-framework`, ya en el árbol de deps), y crates auxiliares para TPM 2.0 (Linux) y FIDO2 (Yubikey) cuando se implementen las Fases 1+.
>
> **Firma de releases** — Apple Developer ID / Windows Authenticode / GPG puede requerir crates de attestation. Sin versión comprometida.
>
> **`rmcp`** — reevaluación si la madurez del SDK justifica la migración. Encapsulada en el módulo `mcp/` sin tocar primitives.

## Tabla resumen de decisiones plasmadas

| ADR | Decisión |
|-----|----------|
| `ADR-KVD-004` | Apache-2.0 license + Open Core boundary |
| `ADR-KVD-005` | Rust como lenguaje del CLI |
| `ADR-KVD-006` | MCP thin JSON-RPC propio (no `rmcp`) |
| `ADR-KVD-007` | `rusqlite` bundled (no `sqlx`) |
| `ADR-KVD-008` | Fork YAML mantenido (`serde_yaml_ng`) |
| `ADR-KVD-009` | MSRV 1.88 (edition 2024 + stack) |
| `ADR-KVD-010` | Threat model Nivel 2 zero-knowledge formal |
| `ADR-KVD-011` | Recovery codes UX pattern |
| `ADR-KVD-012` | Master password storage local (RAM-only default + opt-in keychain ACL) |
| `ADR-KVD-022` | HKDF sub-key naming convention (`kvendra/<purpose>/v<n>`) |
| `ADR-KVD-029` | Wrap key machine-bound del blob de sesión (residual C3) |

## Notas importantes

> **Nota:** El binario es **single-binary** sin runtime dependencies. No requiere instalar Python, Node, Rust runtime ni librerías compartidas (excepto `libsecret` opcional en Linux para keychain). Esta es decisión consciente — minimiza fricción de instalación y simplifica auditoría.

> **Advertencia:** Cambios en `Cargo.toml` que toquen crates criptográficos (`argon2`, `aes-gcm`, `hmac`, `sha2`, `hkdf`, `subtle`, `zeroize`, `bip39`, `ed25519-dalek`) requieren ADR explícito justificando el bump y verificación de que no introducen regression en el threat model. Las versiones major de estas crates históricamente han traído API breaking; bump cuidadoso.
