# Kvendra CLI — what protects you, and what does not

This page tells you, in plain terms, **what level of protection the `kvendra`
vault gives you today, what it does not, and how to raise it.** We would rather
you understand the limits than trust a slogan. For the full, formal threat model
see [`THREAT-MODEL.md`](../../THREAT-MODEL.md).

## The one-paragraph version

`kvendra` keeps your credentials in a local, client-side encrypted vault
(Argon2id + AES-256-GCM) and hands them to operations through a broker so your
AI agent never receives the plaintext. Against **your AI agent** and against
**someone who steals the encrypted files** this is strong. Against **an attacker
who has fully compromised your user account on your machine while the vault is
unlocked**, it is not: at that point they can read what your own process can
read. Raising protection past that point needs hardware or a remote broker,
which are on the roadmap and will be **opt-in**. Until you turn those on, you are
in the **basic protection level**, and the CLI tells you so.

## Who are we defending against? Three cases

Think of an attacker, "Eve", in three situations:

- **Case A — Eve has your files, not your machine.** A stolen laptop backup, a
  disk snapshot, a leaked `~/.kvendra` copy. The vault is locked.
- **Case C — Eve is on your machine as your user, but the vault is locked.** She
  can read and swap files but has not seen your password.
- **Case B — Eve is on your machine as your user, and the vault is unlocked.**
  She can read your live process memory and the session.

## What you get at the basic (default) level

| | Case A: your files | Case C: your user, locked | Case B: your user, unlocked |
|---|---|---|---|
| Your secrets' confidentiality | **Protected** — bounded by your master password strength and Argon2id (64 MiB, 3 passes) | **Protected** — no plaintext without the password | **Not protected** — Eve reads them from the live session |
| The AI agent seeing plaintext | n/a | n/a | **Protected** — the agent never receives the raw secret (except the audit-flagged, quota'd escape hatch) |
| Allowlist / approval bypass by the agent | n/a | **Protected** — fail-closed | **Protected** — fail-closed |
| Config / allowlist tampering | **Detected + refused** | **Detected + refused** | **Detected + refused** |
| Audit log | tamper-evident for edits | tamper-evident for edits; **truncation not yet detected** | same |

Plain reading: **your encrypted files are safe to lose or leak** as long as your
master password is strong. Your **AI agent cannot exfiltrate the plaintext** or
escape its allowlist. **But if an attacker owns your user account while your
vault is unlocked, they get what you can get.** That is the honest limit of a
local, software-only vault, and it is the same limit every local password
manager has.

## What compromises you (be clear-eyed)

- **A malicious process running as you, while the vault is unlocked**, can read
  your decrypted secrets. Lock the vault when you step away, keep session TTLs
  short, and do not run untrusted code as your user.
- **A trojan `git`/`aws`/`npm` planted in your `PATH`** can receive a credential
  the broker injects. We block relative-path plants; an absolute-path plant by
  an attacker who already owns your account is a documented residual.
- **Replacing the `kvendra` binary itself** defeats everything. Install from a
  trusted source and, when we ship signed releases, verify the signature.
- **Losing your vault backup AND your recovery mnemonic** means the secrets are
  gone. They are not irreplaceable: the vault holds tokens you can re-issue at
  GitHub, AWS, etc. Keep your `kvendra backup` and your written-down mnemonic in
  two separate safe places.

## What you can do TODAY to raise your protection

None of this needs a new release:

- **Use a strong, unique master password.** Everything offline rests on it.
- **Lock when away** (`kvendra lock`) and use **short session TTLs**
  (`kvendra unlock --ttl 1h`). This shrinks the Case-B window.
- **Keep allowlists minimal.** Grant each profile only the operations and
  targets it needs. The broker is only as tight as your allowlists.
- **Keep a backup + your mnemonic**, stored apart, so device loss is survivable.
- **Prefer short-lived provider credentials** where the provider offers them
  (for example, AWS STS session credentials over long-lived keys), so a leak is
  time-bounded.

## What is coming (so expectations are clear)

These are planned and will be **opt-in and configurable**. The default stays the
basic level so you are never blocked from starting; you turn on what you want:

1. **Hardware-backed keys** (Secure Enclave on macOS, TPM on Linux, FIDO2). Ties
   the vault key to a chip that never releases it and gates each use with a
   presence check. Closes Case A and Case C locally, no server needed.
2. **Ephemeral, scoped credentials.** The broker mints short-lived,
   least-privilege tokens per operation, so any leak is a 15-minute, one-permission
   token instead of your root key.
3. **Server-assisted unlock** (opt-in, online). A second key half held by the KB
   Engine adds detection, revocation, and rate-limiting; with a fresh second
   factor it becomes prevention against a stolen-token attacker.
4. **Remote broker (Team/Enterprise).** The credential operation runs
   server-side; the raw secret never reaches your machine. This is the only thing
   that fully closes Case B.

## Protection levels by tier (target)

- **Free / offline:** local vault. Basic by default; opt in to hardware for the
  strong local level. The Case-B residual is documented and shown to you.
- **Pro (CLI local):** hardware-backed key plus optional server-assisted unlock.
- **Team / Enterprise:** remote broker by default. The secret never touches your
  machine.

## The bottom line

Kvendra will not pretend a local vault can survive a full takeover of your user
account while it is unlocked. What it does is: keep your files safe at rest, keep
your agent from ever holding the plaintext, fail closed on every policy and
integrity check, and give you honest, opt-in ways to raise the bar with hardware
or a remote broker. You choose your level; the CLI always tells you which one you
are in.
