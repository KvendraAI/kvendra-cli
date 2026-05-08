# Smoke E2E pre-tag-push checklist

Suite ejecutable que ejercita las 7 fases T1/T1.5/T2/T3/D/E/F del flujo
end-to-end. Detecta regresiones tipo PAT-KVD-004 antes de tag-push.

## When to run

- Antes de cada `git tag v0.1.0-alpha.X` o `v0.1.X`.
- Tras cualquier merge a `main` que toque `src/mcp/`, `src/allowlist/`,
  `src/audit/`.
- Pre-flight de cualquier `cargo publish`.

## Prerequisites

- `cargo build --release` reciente (`target/release/kvendra` existe).
- Bash >= 4 (macOS default es 3.2 — `brew install bash` recomendado).
- `mkfifo` disponible (built-in en macOS/Linux; en Windows usar Git Bash o WSL).

## Automated steps (run script)

```bash
cargo build --release
./scripts/e2e-smoke.sh
```

Esperado: `=== ALL PHASES PASSED ===` y exit 0.

## Manual steps (Touch ID gated)

T1.5 (`kvendra config mcp-password enable`) está skipped por defecto. Para
validarlo manualmente en máquina con Touch ID + Apple Dev ID disponible:

```bash
SMOKE_SKIP_T1_5=0 ./scripts/e2e-smoke.sh
```

El script intentará la operación; en builds sin Apple Dev ID la macOS
keychain mostrará un modal consent-only (PAT-KVD-CLI-001). Si rechazas el
biometric prompt esperarás `fail T1.5 exit 20` — eso es testing del rejection path.

## Troubleshooting

| Exit code | Fase | Causa probable |
|---|---|---|
| 10-16 | T1 | bootstrap del vault — typically `KVENDRA_HOME` perms del padre |
| 20    | T1.5 | mcp-password enable falla (Touch ID rechazado o no disponible) |
| 30-34 | T2 | password mismatch o YAML inválido — check `secret validate` output |
| 40-46 | T3 | shape MCP envelope wrong (PAT-KVD-004 recurrence) o JSON-RPC framing roto |
| 50-51 | D | allowlist enforcer roto (ISSUE-KVD-CLI-032 recurrence) |
| 60-62 | E | audit HMAC chain corruption (ISSUE-KVD-CLI-009 recurrence) |

## Findings cazables

Tres findings del E2E manual del 2026-05-07 que el harness intenta destapar
si reaparecen:

- **E2E-D-2** — clap UX `--password-env <NAME>`: el harness usa env vars
  directas (`KVENDRA_*_PASSWORD`). Si el flag se reintroduce y rompe, abrir ISSUE.
- **E2E-D-3** — JSON-RPC response sin `id`: el harness assertea
  `"id":N` matching cada request en T3.
- **E2E-F-2** — `notifications/initialized` retorna response (viola spec):
  cazable extendiendo el harness; documentar pero NO crear ISSUE hasta
  validar con un cliente MCP real.

## Caveat operacional

`kvendra audit --json` requiere vault unlocked en su propio proceso.
Desde scripts externos sin master password en el process tree, leer
SQLite raw es la alternativa (rows en plain text, HMAC chain como
metadata aparte):

```bash
sqlite3 ~/.kvendra/audit.db "SELECT id, ts_unix_ms, profile_id, primitive, action, status, severity, flags FROM events ORDER BY id DESC LIMIT 10"
```

## Ownership

- Runs locales: owner (juanantonio.perez@winking-owl.com)
- CI (steps no-biométricos): GitHub Actions `e2e-smoke.yml` (macos-latest)

## References

- `REQ-KVD-CLI-001` — formal requirement specification.
- `ISSUE-KVD-CLI-037` — implementation tracking.
- `PAT-KVD-004` — shape MCP envelope lesson learned (motivation).
- `ROAD-KVD-CLI-001` — 0.1.0 stable readiness roadmap.
