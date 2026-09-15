# Kvendra CLI Threat Model — Level 2 Zero-Knowledge

This document materializes ADR-KVD-010 ("Threat model target — Level 2
zero-knowledge formal"). It states explicitly which adversaries the
`kvendra` binary defends against in Alpha 0.1, which adversaries are out
of scope (and why), and which cryptographic primitives back the promise.

It is the source of truth a third-party reviewer should read before
trusting any "zero-knowledge" claim made by the project. It is versioned
alongside the source code and is updated whenever the crypto stack, the
KDF cost parameters, or the surfaces that touch credential plaintext
change.

## Promise

> Even with full access to your filesystem (excluding the running process
> memory while the vault is unlocked), the only thing visible is encrypted
> blobs that are mathematically useless without your master password.

> **Honest boundary (corrected v0.6.4, external audit finding C3).** The
> promise above holds **while the vault is LOCKED**. While the vault is
> UNLOCKED, `~/.kvendra/sessions/active.blob` stores the Argon2id-derived key
> encrypted under a *machine-bound* wrap key that is derived from **public**
> inputs (hostname + uid + the canonical `~/.kvendra` path) and a hardcoded
> sentinel IKM (`ADR-KVD-029`). A process running **as your uid** can therefore
> read that blob (mode 0600) and recover the derived key **without your master
> password**, for the lifetime of the session. This is the deliberate
> trade-off that lets `kvendra mcp serve` run without re-prompting; it does NOT
> break the at-rest guarantee (a locked vault exposes nothing), but it means an
> unlocked session's derived key is only as protected as your user account.
> The real fix is hardware-backed wrapping (Secure Enclave / TPM / FIDO2),
> deferred post-MVP — see O1 and "Future mitigation" below.

Concretely:
- No code path in the `kvendra` binary writes the master password, the
  Argon2id-derived key, or any decrypted secret to disk.
- The derived key lives only in process RAM during an unlocked session
  and is `zeroize`-cleared on `kvendra lock`, on idle timeout, or on
  process termination.
- Every blob in `~/.kvendra/secrets/*.blob` is AES-256-GCM ciphertext
  authenticated with a 96-bit random nonce and a 128-bit GCM tag, with
  the key derived per-blob from the master password via Argon2id with
  cost parameters targeting ≥ 1 second per attempt on modern hardware.

## Scope

The threat model applies to:
- The `kvendra` binary distributed under Apache-2.0 from
  `KvendraAI/kvendra-cli`.
- The local filesystem under `~/.kvendra/`.
- The MCP server (`kvendra mcp serve`) and its JSON-RPC 2.0 stdio
  surface, including the eight capability primitives.

Out of scope (handled in later phases):
- Cloud sync of the vault (Pro tier, post-MVP).
- Cloud broker mode running primitives in Lambda + KMS (Team tier).
- Hardware-backed key wrapping (Secure Enclave, TPM 2.0, FIDO2).
- Cross-machine policy enforcement and centralized identity.

## Threat vectors covered (V1–V8)

### V1 — Passive observer of the public repository

| Field | Detail |
|---|---|
| Attacker | Anyone with read access to GitHub. |
| Capabilities | Reads all source. |
| Plaintext exposed | None. |
| Mitigation | Auditability is a feature: any reviewer can verify the
  KDF / AEAD / zeroize path in a single reading session.

### V2 — Read access to `~/.kvendra/`

| Field | Detail |
|---|---|
| Attacker | Backup leak, disk snapshot, unprivileged malware. |
| Capabilities | Reads ciphertext blobs and the audit log. |
| Plaintext exposed | None without the master password **while the vault is
  locked**. See the caveat below for the unlocked-session blob. |
| Mitigation | Argon2id (m_cost = 64 MiB, t_cost = 3, p_cost = 1) +
  AES-256-GCM client-side (AC-VAULT-2, AC-VAULT-4).

> **Caveat — unlocked-session blob (audit finding C3, v0.6.4).** When the vault
> is unlocked, `sessions/active.blob` is decryptable by a process running as
> your uid **without** the master password (its wrap key comes from public,
> machine-bound inputs — `ADR-KVD-029`). So V2's "none without the master
> password" applies to the secret blobs and the at-rest state; it does NOT
> apply to the derived key while a session is live. An attacker who already has
> code execution as your user during an unlocked session is close to the O1
> boundary (RAM dump) anyway. Locking the vault (`kvendra lock`, idle timeout,
> or process exit) removes the blob's usefulness immediately.

### V3 — Malicious Kvendra-team insider (post-MVP cloud sync)

| Field | Detail |
|---|---|
| Attacker | Employee with infrastructure access. |
| Capabilities | Total access to Kvendra-side cloud storage. |
| Plaintext exposed | None — the derived key never leaves the user's
  machine. |
| Mitigation | Client-side encryption before any upload; the wire only
  carries the same opaque blobs that V2 already cannot decrypt.

### V4 — AWS breach (post-MVP cloud sync)

| Field | Detail |
|---|---|
| Attacker | Compromise of S3 + Lambda + Kvendra-internal KMS. |
| Capabilities | Full read of stored blobs. |
| Plaintext exposed | None. |
| Mitigation | Same as V3. KMS, when introduced, is used for
  Kvendra-internal services and never for user secret material.

### V5 — External auditor or third-party reviewer

| Field | Detail |
|---|---|
| Attacker | Cooperative auditor performing due diligence. |
| Capabilities | Source review and (later) infra inspection. |
| Plaintext exposed | None — the auditor confirms the promise rather
  than breaking it. |
| Mitigation | The CLI is Apache-2.0 specifically to make this kind of
  audit cheap. Success metric: an auditor can verify the path in ≤2 h.

### V6 — Compromised primitive (allowlist parser bug)

| Field | Detail |
|---|---|
| Attacker | Bug or supply-chain compromise of a primitive. |
| Capabilities | Could attempt operations outside the intended scope. |
| Plaintext exposed | Token usable against unintended endpoint. |
| Mitigation | Restrictive allowlist defaults (REQ-KVD-002 AC-ALLOW-1),
  audit log HMAC chain (AC-AUDIT-2), defense in depth: the broker rejects
  unknown operations and the primitive itself enforces argv constraints.

### V7 — Malicious or compromised AI agent

| Field | Detail |
|---|---|
| Attacker | The agent itself. |
| Capabilities | Issues arbitrary `tools/call` requests. |
| Plaintext exposed | Only the result of operations explicitly permitted
  by the profile's allowlist. |
| Mitigation | Capability primitives never return secret plaintext
  (AC-MCP-3). The escape hatch `kvendra.unsafe.raw_token` is the only
  exception and is opt-in, audit-flagged, and rate-limited per session
  (IF-KVD-CLI-008).

### V8 — Remote brute force of the master password via leaked blob

| Field | Detail |
|---|---|
| Attacker | Has obtained a vault blob and tries passwords offline. |
| Capabilities | Full Argon2id compute on their hardware. |
| Plaintext exposed | None unless the master password itself is weak. |
| Mitigation | Argon2id high-cost params (m_cost = 64 MiB, t_cost = 3)
  push the per-attempt cost ≥ 1 second. Users with elevated threat
  models can opt into stronger params via `kvendra config set`.

## Threat vectors explicitly accepted (O1–O6)

These vectors are out of scope for Alpha 0.1. They are documented here
because honest disclosure of accepted vectors is part of the trust
narrative — any product that claims "zero-knowledge" without naming its
limits is engaging in security theatre.

### O1 — RAM dump during unlocked session

While the vault is unlocked, the derived key lives in the `kvendra mcp
serve` process's memory. An attacker with `root` and `ptrace` (or
physical access) can dump that RAM. The optional OS-keychain integration
(ADR-KVD-012) expands this surface to the OS keychain itself, which is
why the opt-in requires an explicit disclosure.

Note: when scripting unattended flows, the master password may transit
through environment variables (`KVENDRA_PASSWORD` for `unlock` and
`audit --verify`, `KVENDRA_INIT_PASSWORD` for `init`,
`KVENDRA_NEW_PASSWORD` + `KVENDRA_RECOVERY_MNEMONIC` for `recover`,
`KVENDRA_MCP_PASSWORD` for `mcp serve`). Environment variables are
visible to the process tree and to `/proc/<pid>/environ` on Linux —
prefer the `--password-stdin` flag where available (currently
`audit --verify`) and clear the variable as soon as the process spawns.

Future mitigation: hardware-backed wrapping (Secure Enclave / TPM 2.0 /
Yubikey FIDO2) — deferred post-MVP.

### O2 — Persistent malware with privileges to replace the binary

If the attacker can substitute `kvendra` itself, they can do anything.

Future mitigation: reproducible builds and SLSA-signed releases.

### O3 — Side-channel timing on shared CPU

Argon2id is resistant to many side channels but cache-timing leaks can
expose bits of the master password on hostile multi-tenant hardware.

Mitigation: `subtle` is used for any constant-time comparison on
critical paths. Documentation warns against running the unlocked vault
on multi-tenant hardware you do not trust.

### O4 — Coercion ("rubber-hose" attack)

If a user is coerced, they will hand over the key. No cryptographic
scheme defends against this.

Mitigation: recovery codes (AC-VAULT-5) let the user reset access, and
they can stop using the affected profile.

### O5 — Compromise of an external service (GitHub, npm, AWS …)

If GitHub leaks PATs, no local vault prevents it.

Mitigation: Out of scope — the user rotates their token in the affected
service.

### O6 — Accidental plaintext logging by a primitive

A primitive that misuses logging could leak material. We accept this as
an implementation risk.

Mitigation: every `tools/call` is audited; primitives are reviewed
before merge; sensitive buffers use `zeroize`. The detection layer
(REQ-KVD-002 Bloque 7) is the safety net for tokens the agent
accidentally re-emits.

### O7 — Offline audit-export authenticity (audit finding H1, v0.6.4)

The signed audit export bundle is **self-contained** so it can be verified
offline. To do that it embeds `chain_key_seed_hex`, the **symmetric** HMAC key
of the chain. Offline `kvendra audit verify` therefore proves the rows are
internally **consistent** with that seed — it detects accidental corruption and
in-place tampering of a bundle you already trust — but it does **not** prove
**authenticity**: anyone holding the bundle can recompute the whole chain and
forge rows. Real authenticity requires server-side verification against the key
Kvendra retained at issue time (the bundle's `verifier_url`). As of v0.6.4 the
bundle carries an explicit `security_note` field stating this, so no reviewer
mistakes offline integrity for offline authenticity.

Future mitigation: asymmetric (public-key) signing of the bundle — sign with a
private key held only by the issuer, verify with a published public key — so an
offline verifier can confirm authenticity without being able to forge. Tracked
as a design follow-up.

### O8 — Presence-gated approval is macOS-only (audit finding H3)

The interactive per-`tools/call` approval prompt (`ask` / `ask-destructive`)
is backed by an OS-presence popup that exists only on macOS. On Linux/Windows
the backend returns `Unavailable`, which **fails closed** (the op is blocked),
so the only way to operate a broker on Linux today is
`KVENDRA_APPROVAL_MODE=silent` — i.e. turning the interactive confirmation off.
This is safe-by-default (deny on absence) but limits the protection available
to non-macOS users to the allowlist + audit layers.

Future mitigation: a Linux presence backend (polkit / D-Bus / a TTY-isolated
prompt) so `ask-destructive` is usable without disabling it. Tracked as a
future ROAD item.

## Cryptographic primitives

| Component | Choice | Crate | Notes |
|---|---|---|---|
| KDF | Argon2id | `argon2` | m_cost = 64 MiB, t_cost = 3, p_cost = 1 |
| AEAD | AES-256-GCM | `aes-gcm` | 96-bit random nonce per encryption |
| Memory clearing | `zeroize` | `zeroize` | `ZeroizeOnDrop` on derived keys |
| Constant-time ops | `subtle` | `subtle` | Compares for recovery codes |
| Audit chain | HMAC-SHA-256 | `hmac` + `sha2` | Hashes `(id, ts, profile_id, primitive, action, args_hash, status, severity, flags, prev_hmac)` |
| Recovery phrase | BIP-39 12 words | `bip39` | English wordlist, 132 bits entropy + checksum |

## Audit mechanism

Every `tools/call` writes one row to `~/.kvendra/audit.db` (SQLite WAL
mode) **before** invoking the primitive — guaranteeing AC-AUDIT-1 even
when the primitive crashes. The HMAC chain over rows lets `kvendra audit
--verify` detect any retroactive tampering at the row that breaks the
chain (AC-AUDIT-2).

## Versioning policy

This document is updated whenever:
- The crypto stack changes (KDF, AEAD, RNG).
- KDF cost parameters change.
- A new primitive is added.
- The MSRV changes (which can affect the cryptographic crates pulled in).

Every release notes any material change at the top of `CHANGELOG.md`
with a link back to this file.
