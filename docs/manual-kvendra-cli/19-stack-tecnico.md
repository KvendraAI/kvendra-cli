# 19. Stack técnico

## Descripción

Inventario canónico del stack de `0.1.0`: crates Rust con versiones reales, features Cargo activas, MSRV, decisiones de licencia/edition. Las decisiones detrás están en `ADR-KVD-005` (Rust como lenguaje), `ADR-KVD-006` (MCP layer thin propio), `ADR-KVD-007` (rusqlite bundled), `ADR-KVD-008` (serde_yml fork) y `ADR-KVD-009` (MSRV).

## Lenguaje y toolchain

> **Lenguaje:** Rust
>
> **Edition:** 2024
>
> **MSRV:** 1.85 (requerido para edition 2024)
>
> **Toolchain:** stable
>
> **License:** Apache-2.0
>
> **Crate name:** `kvendra` (canónico) en crates.io
>
> **Binary name:** `kvendra`

## Dependencias principales

Todas las versiones reflejan `Cargo.toml` real del `0.1.0`:

| Crate | Versión | Features | Uso |
|-------|---------|----------|-----|
| `clap` | 4.x | `derive`, `env` | CLI parsing |
| `clap_complete` | 4.x | — | Shell completions (bash, zsh, fish) |
| `rpassword` | 7.x | — | Password prompt sin echo |
| `tokio` | 1.x | `macros`, `rt-multi-thread`, `sync`, `io-std`, `io-util`, `time`, `fs`, `process`, `signal` | Async runtime |
| `serde` | 1.x | `derive` | Serialization |
| `serde_json` | 1.x | — | JSON-RPC, audit JSON export |
| `serde_yml` | 0.0.12 | — | Allowlist YAML parser (fork mantenido vs `serde_yaml` deprecated) |
| `toml` | 0.8 | — | `config.toml` |
| `argon2` | 0.5.x | — | KDF (master password → derived key) |
| `aes-gcm` | 0.10.x | — | AEAD AES-256-GCM (blobs) |
| `zeroize` | 1.x | `zeroize_derive` | Memory clearing en `Drop` |
| `subtle` | 2.x | — | Constant-time comparisons |
| `hmac` | 0.12.x | — | Audit chain, sidecars |
| `sha2` | 0.10.x | — | HMAC underlying hash |
| `rand` | 0.8.x | — | RNG |
| `bip39` | 2.x | `rand` | Recovery phrase 12 words |
| `rusqlite` | 0.31 | `bundled` | SQLite (audit.db) |
| `keyring` | 3.x | `apple-native`, `windows-native`, `linux-native-sync-persistent` | OS keychain integration |
| `reqwest` | 0.12.x | `rustls-tls`, `json`, `stream` | HTTP client |
| `ratatui` | 0.29 | feature-gated `tui` | TUI layer |
| `crossterm` | 0.28 | feature-gated `tui` | TUI backend |
| `thiserror` | 1.x | — | Error definitions |
| `anyhow` | 1.x | — | Error context propagation |
| `tracing` | 0.1 | — | Structured logging |
| `tracing-subscriber` | 0.3 | `env-filter` | Tracing init |
| `regex` | 1.x | — | Detection layer + URL allowlist matcher |
| `time` | **0.3.47** | `formatting`, `macros`, `parsing` | Date/time helpers — pinned post `RUSTSEC-2026-0009` |
| `hex` | 0.4 | — | Hex encoding (audit dump, hashes) |
| `base64` | 0.22 | — | Base64 encoding (blobs, OG/icons) |

### Dependencias platform-specific

| Plataforma | Crate | Versión | Uso |
|-----------|-------|---------|-----|
| macOS | `security-framework` | 3 | SecAccessControl + SecItem* (biometric ACL, REQ-KVD-005 / ISSUE-KVD-CLI-017) |
| macOS | `security-framework-sys` | 2 | Direct deps for above |
| macOS | `core-foundation` | 0.10 | macOS FFI |
| macOS | `core-foundation-sys` | 0.8 | macOS FFI |
| Unix (Linux + macOS) | `libc` | 0.2 | SIGPIPE handler (ISSUE-KVD-CLI-042 — install SIG_DFL para evitar Rust panic default) |

### Dev-dependencies

| Crate | Versión | Uso |
|-------|---------|-----|
| `assert_cmd` | 2.x | E2E tests del binario |
| `predicates` | 3.x | Assertion combinators |
| `tempfile` | 3.x | Tests con `~/.kvendra/` aislado |

## Cargo features

| Feature | Default | Gates |
|---------|:-------:|-------|
| `tui` | **on** | `ratatui` 0.29 + `crossterm` 0.28 (TUI dashboard + audit watch). Disable para builds headless / minimal. |

`0.1.0` solo expone una feature pública. Otras (ej. `keychain`, `legacy-serde-yaml`) son consideraciones futuras pero no garantizadas estables.

## Build reproducibility

`Cargo.lock` está committeado (decisión estándar para binarios). `cargo install kvendra --locked` respeta el lockfile. CI matrix corre con `--locked` para garantizar reproducibilidad.

## Plataformas soportadas

| Target | Status `0.1.0` | Notas |
|--------|---------------|-------|
| `aarch64-apple-darwin` | binario en GitHub Releases | unsigned (track signing → 0.2.0) |
| `x86_64-apple-darwin` | binario en GitHub Releases | unsigned |
| `x86_64-unknown-linux-gnu` | binario en GitHub Releases | unsigned |
| `x86_64-pc-windows-msvc` | binario en GitHub Releases | unsigned |
| Otros (`aarch64-unknown-linux-gnu`, BSDs) | via `cargo install` | sin binario precompilado |

## CI matrix

| Job | OS | Arch | Toolchain |
|-----|----|----|-----------|
| `build` + `test` | `ubuntu-latest` | x86_64 | stable |
| `build` + `test` | `macos-latest` | arm64 | stable |
| `build` + `test` | `windows-latest` | x86_64 | stable |

`AC-CLI-4` exige verde en los 3. La matrix está en `.github/workflows/ci.yml`. Smoke harness E2E (`scripts/e2e-smoke.sh`) se documenta en `docs/smoke.md`.

## Decisión yaml — `serde_yml` vs `serde_yaml`

`ADR-KVD-008`: elegido `serde_yml` 0.0.12 porque `serde_yaml` está sin mantenimiento upstream desde 2024. `serde_yml` es fork drop-in con security fixes. Trade-off: depender de un fork joven, mitigado por la simplicidad del subset de YAML que usamos (allowlist DSL es mostly key-value + arrays planos).

## Decisión MCP layer — thin propio

`ADR-KVD-006`: thin JSON-RPC propio en lugar de adoptar `rmcp` SDK comunitario. Justificado en el [capítulo 13](./13-mcp-server.md). Coste eng: ~2-3 días de implementación inicial; mantenimiento: mínimo (subset estable de MCP).

## Crates ausentes deliberadamente

> **`sqlx`** — no aporta sobre `rusqlite` para audit log local sync (decisión `ADR-KVD-007`).
>
> **`openssl`** — el stack es rustls-only (`reqwest` con `rustls-tls`). Evita complicaciones de FFI con OpenSSL del sistema.
>
> **`tonic` / gRPC** — no necesitamos gRPC; MCP usa JSON-RPC.
>
> **`rocket` / `axum`** — no hay HTTP server-side. Solo client (`reqwest`) y stdio (MCP).
>
> **`ring`** — `rustcrypto` (`aes-gcm`, `argon2`, `hmac`, `sha2`) es suficiente. Evita FFI a `ring`.

## Versiones críticas pinneadas

| Crate | Versión exacta | Razón |
|-------|---------------|-------|
| `time` | `0.3.47` | Post RUSTSEC-2026-0009 fix; no descender |
| `serde_yml` | `0.0.12` | Único fork mantenido; verificar antes de bump |

## Decisión MSRV

`ADR-KVD-009`: MSRV `1.85` para soportar edition 2024. Coste: usuarios con toolchain antigua no pueden `cargo install`. Aceptable — Rust stable 1.85 está disponible desde 2025; cualquier dev activo en 2026 lo tiene.

## Roadmap del stack

Cambios de stack previstos en versiones futuras (no `0.1.x`):

> **`0.2.0`** — possible bump de MSRV si una crate clave lo requiere. Apple Developer ID + signing pipeline introduce nuevos pasos en CI, no nuevas crates.
>
> **`0.3.0`** — Windows Authenticode + Linux GPG signing puede requerir crates auxiliares para attestation.
>
> **Post-Beta** — evaluación de `rmcp` si la madurez del SDK justifica migración. Si se hace, encapsulado en módulo `mcp/` sin tocar primitives.

## Tabla resumen de decisiones plasmadas

| ADR | Decisión |
|-----|----------|
| `ADR-KVD-004` | Apache-2.0 license + Open Core boundary |
| `ADR-KVD-005` | Rust como lenguaje del CLI |
| `ADR-KVD-006` | MCP thin JSON-RPC propio (no `rmcp`) |
| `ADR-KVD-007` | `rusqlite` bundled (no `sqlx`) |
| `ADR-KVD-008` | `serde_yml` (fork mantenido) |
| `ADR-KVD-009` | MSRV 1.85 (edition 2024) |
| `ADR-KVD-010` | Threat model Nivel 2 zero-knowledge formal |
| `ADR-KVD-011` | Recovery codes UX pattern |
| `ADR-KVD-012` | Master password storage local (RAM-only default + opt-in keychain ACL) |
| `ADR-KVD-022` | HKDF sub-key naming convention (`kvendra/<purpose>/v<n>`) |

## Notas importantes

> **Nota:** El binario es **single-binary** sin runtime dependencies. No requiere instalar Python, Node, Rust runtime ni librerías compartidas (excepto `libsecret` opcional en Linux para keychain). Esta es decisión consciente — minimiza fricción de instalación y simplifica auditoría.

> **Advertencia:** Cambios en `Cargo.toml` que toquen crates criptográficos (`argon2`, `aes-gcm`, `hmac`, `sha2`, `subtle`, `zeroize`, `bip39`) requieren ADR explícito justificando el bump y verificación de que no introducen regression en threat model. Las versiones major de estas crates históricamente han traído API breaking; bump cuidadoso.
