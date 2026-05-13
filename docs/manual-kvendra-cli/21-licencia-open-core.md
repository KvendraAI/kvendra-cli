# 21. Licencia y Open Core boundary

## Descripción

Kvendra CLI se licencia bajo **Apache-2.0**. Es la pieza permisiva del modelo Open Core hybrid del producto Kvendra, formalizado en `ADR-KVD-004`. Este capítulo describe la elección de licencia, qué implica para usuarios y contribuidores, dónde está el boundary entre OSS y código privado, y por qué el modelo está diseñado así.

## La decisión en una frase

> **CLI Apache-2.0 + Server AGPL-3.0 + Enterprise closed.**

CLI permisivo para máxima adopción y trust. Server core con copyleft fuerte (AGPL) para bloquear fork-and-host commercial. Enterprise features genuinamente closed donde tiene sentido (Nitro Enclaves orchestration, SSO/SAML, compliance dashboards).

## Resumen del Open Core boundary

| Componente | Repo | Licencia |
|------------|------|----------|
| **`kvendra-cli`** (este binario) | `KvendraAI/kvendra-cli` | **Apache-2.0** |
| **`kvendra-platform`** (server cloud) | `KvendraAI/kvendra-platform` | **AGPL-3.0** |
| **`kvendra-skills`** (marketplace primitives) | `KvendraAI/kvendra-skills` | **Apache-2.0** |
| **`kvendra-helm`** (Helm chart self-host) | `KvendraAI/kvendra-helm` | **Apache-2.0** |
| **`kvendra-web`** (landing + docs portal) | `KvendraAI/kvendra-web` | **MIT** |
| **Enterprise features** | privado `KvendraAI/kvendra-enterprise` | **Proprietary (closed)** |

## Por qué Apache-2.0 para el CLI

`ADR-KVD-004` lista las razones:

> **Trust narrative.** Ningún developer sensato confía sus secrets a una caja negra. Los secret managers exitosos (Bitwarden, 1Password client, KeePass) son OSS por esto. Apache-2.0 permite auditar el path criptográfico.
>
> **Adopción máxima.** Cualquier IDE / competitor (Cursor, Cline, Continue, JetBrains) puede integrar Kvendra CLI sin fricción legal. Las licencias copyleft (GPL, AGPL) bloquearían algunas de estas integraciones por corporate policy.
>
> **Patent grant explícito.** Apache-2.0 incluye patent license expreso (Section 3) — más seguro que MIT para casos donde el código toca cripto patentable.
>
> **Compatibilidad.** Apache-2.0 es compatible con prácticamente cualquier licencia OSS y con muchas closed source. Mínima fricción de mixing.

## Por qué AGPL-3.0 para el server (cuando exista)

> **Bloquea fork-and-host commercial.** AWS no puede lanzar mañana "Amazon Kvendra Service" con nuestro código sin abrir todo su stack bajo AGPL — y no lo harán.
>
> **Self-host interno permitido.** Acme Bank puede self-hostear `kvendra-platform` modificado para integrar con su SIEM, sin obligación de abrir su modificación públicamente (siempre que no la oferten como servicio público).
>
> **Contribuciones evolutivas.** Si Acme Bank decide más tarde abrir su SIEM-integration patch a la comunidad, AGPL la admite naturalmente.

## Por qué Enterprise closed

`ADR-KVD-004` documenta la **política de demarcación**: una feature solo va a `kvendra-enterprise` (closed) si cumple **todas** estas condiciones:

> 1. **No es necesaria** para la propuesta core ("zero-knowledge vault + capability broker via MCP").
> 2. **Solo tiene sentido** en contextos enterprise/regulados (SSO/SAML, immutable audit, compliance reports, advanced policy engine cross-org).
> 3. **Tiene equivalente comunitario** documentado: si quieres self-hostear sin nuestras enterprise features, hay docs claras de cómo lograr una versión no-enterprise.

Esto evita "enshittification gradual" donde features útiles se mueven progresivamente del OSS al closed (caso típico que destruye goodwill).

## Capacidades por tier — `0.1.0` y futuro

| Capacidad | Free CLI (OSS) | Pro Cloud | Team Cloud | Enterprise Cloud |
|-----------|:-:|:-:|:-:|:-:|
| Vault local cifrado AES-256-GCM + Argon2id | ✅ | ✅ | ✅ | ✅ |
| MCP server local stdio | ✅ | ✅ | ✅ | ✅ |
| 7 primitives canónicas + escape hatch | ✅ | ✅ | ✅ | ✅ |
| Allowlist DSL completo | ✅ | ✅ | ✅ | ✅ |
| Audit log local SQLite (HMAC-signed) | ✅ | ✅ | ✅ | ✅ |
| Detection layer | ✅ | ✅ | ✅ | ✅ |
| OS keychain integration | ✅ | ✅ | ✅ | ✅ |
| TUI (`dashboard`, `audit`) | ✅ | ✅ | ✅ | ✅ |
| Self-host primitive registry intra-org | ✅ | ✅ | ✅ | ✅ |
| Export/import vault (portable, vendor-lock-free) | ✅ | ✅ | ✅ | ✅ |
| **Cross-device sync** (S3 backup encriptado) | ❌ | ✅ | ✅ | ✅ |
| **Identity centralizado** (Cognito OAuth + email recovery) | ❌ | ✅ | ✅ | ✅ |
| **Marketplace público hosted** | consume only | ✅ consume + publish | ✅ | ✅ |
| **Workspaces multi-user + RBAC** | ❌ | ❌ | ✅ | ✅ |
| **Cloud broker mode** (agentes CI/CD) | ❌ | ❌ | ✅ | ✅ |
| **Audit dashboard web consolidado** | ❌ | ❌ | ✅ | ✅ |
| **Policy enforcement cross-machine** | ❌ | ❌ | ✅ | ✅ |
| **SSO / SAML** | ❌ | ❌ | ❌ | ✅ |
| **Nitro Enclaves cloud (Nivel 3)** | ❌ | ❌ | ❌ | ✅ |
| **Audit log immutable + extended retention** | ❌ | ❌ | ❌ | ✅ |
| **Compliance reports** (SOC 2 / ISO 27001 / HIPAA) | ❌ | ❌ | ❌ | ✅ |

### Test crítico de freemium real

Un dev solo en Free tier puede:

> Hacer todo el flujo del escenario (deploys, pushes, publishes) ✅
>
> Trabajar con Claude Code/Cursor/Cline sin pegar tokens en chat ✅
>
> Vault zero-knowledge en su máquina ✅
>
> Audit trail local completo ✅
>
> **Sin limit artificial de profiles ni de uso** ✅
>
> Limitación legítima única: **una sola máquina** (sin sync). Si quiere su vault en laptop + desktop + iPad, paga Pro.

Eso es freemium genuino. Lo que pagas en Cloud no es "desbloquear features artificialmente cerradas", sino "cosas que por naturaleza requieren un servicio centralizado: sync, multi-user, dashboard cross-machine, compliance".

## Política de contribuciones

`ADR-KVD-004` formaliza:

> **DCO (Developer Certificate of Origin)** como punto de partida — cada commit firmado con `Signed-off-by: Name <email>`. Lightweight, sin paperwork, validable en CI.
>
> **CLA (Contributor License Agreement)** queda diferido. Se considera si:
> - >50 contributors externos.
> - Aparece necesidad de relicenciar.
> - Investor/M&A lo exige.

Para PRs:

```bash
git commit -s -m "fix: ..."   # -s adds Signed-off-by
```

CI valida la firma DCO antes de merge.

## Trademark

`ADR-KVD-004` nota que Apache-2.0 y AGPL **no protegen el nombre "Kvendra"**. La política de trademark se materializa en `TRADEMARK.md` separado cuando arranque P6.1 IP attorney clearance.

Política inicial:

> Code use unrestricted (per Apache-2.0).
>
> Name use restricted: forks pueden usar el código pero **deben rebrandearse** si distribuyen al público.

## Implicaciones para el usuario

Si usas Kvendra CLI como dev individual o en una empresa interna:

> Puedes inspeccionar el código completo. Auditar el path criptográfico es trivial.
>
> Puedes modificarlo para tu uso interno sin obligación de devolver al upstream (Apache-2.0 lo permite).
>
> Puedes redistribuir el binario modificado bajo Apache-2.0 (manteniendo notice de copyright original y NOTICE).
>
> No hay tracking, telemetry ni analytics en `0.1.0`. El binario no llama a ningún servidor de Kvendra durante operación normal.
>
> No hay licencia para activar. No hay key de seriado. No hay limit por máquina.

## Implicaciones para el contribuidor

Si quieres contribuir a `kvendra-cli`:

> Lee `CONTRIBUTING.md` (cuando exista — en `0.1.0` aún no es exhaustivo).
>
> Firma DCO en cada commit (`-s`).
>
> Tests E2E + tests del threat model son obligatorios para PRs que toquen path crypto / allowlist enforcer / sanitization.
>
> El review process del core team puede ser estricto especialmente sobre invariantes de seguridad.

## Implicaciones legales corporativas

> **Apache-2.0 es OSS-friendly** para enterprise compliance. La mayoría de corporate-policy permite Apache-2.0 sin special review.
>
> **No hay AGPL en el CLI** — esto es deliberado. AGPL en server `kvendra-platform` (cuando exista) puede activar corporate review en algunas empresas; opción es self-host o pasar a Enterprise tier (closed).
>
> **Patent grant Apache-2.0 (Section 3)** se aplica al código contribuido. Esto cubre patents que un contribuidor pudiera tener sobre código que aporta.

## Notas importantes

> **Nota:** El binario `kvendra` no incluye telemetry. Si en algún momento futuro se introduce telemetry opt-in (e.g. crash reports anonymous), será documentado y el flag por defecto `off`. Para `0.1.0` y `0.1.x`, no hay ningún canal de comunicación entre el binario y servidores de Kvendra durante operación normal.

> **Advertencia:** Si forkeas `kvendra-cli` y publicas tu fork bajo otro nombre (rebrandeado), respeta la política de trademark. La buena fe legal sugiere: rebrand efectivo, dejar credit a Kvendra como upstream, no aprovecharse del trademark "Kvendra" para vender competición directa.
