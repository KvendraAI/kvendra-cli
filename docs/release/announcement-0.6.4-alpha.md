# kvendra CLI 0.6.4 — Alpha, and open for your bug reports

The `kvendra` command-line tool is now in the open as an **alpha**. It is the
harness we use to drive Kvendra from the terminal: an **MCP capability broker**
that lets an AI agent run real operations (git, AWS, npm, PyPI, GitHub, HTTP,
shell) through a signed allowlist, plus a **client-side, zero-knowledge
credential vault** (Argon2id + AES-256-GCM) so your agent never holds the raw
secret. Rust, Apache-2.0, cross-platform (macOS, Linux, Windows).

## This is alpha — please try it and tell us what breaks

We use it every day, but it is early. Expect rough edges; the CLI surface and
on-disk formats may still change; we are actively hardening it. The most useful
thing you can do is **run it and report what you find**:

- Bugs and ideas → [open an issue](https://github.com/KvendraAI/kvendra-cli/issues).
- Anything security-sensitive → **security@kvendra.ai** (see [SECURITY.md](../../SECURITY.md)).

Your reports go straight into the roadmap.

## You do NOT need the CLI to use Kvendra

To be clear: **the CLI is optional.** Pro accounts and self-hosted / Enterprise
deployments work fully without it — nothing blocks or degrades if you never
install `kvendra`. This is a power tool for people who want a local MCP broker
and a local vault on their own machine. Install it if it helps; skip it if it
doesn't.

## Honest about the security model

We would rather you understand the limits than trust a slogan. Read
[**what protects you and what does not**](../security/protection-levels.md)
before relying on the vault. In short:

- **Strong:** your encrypted files are safe at rest (bounded by your master
  password + Argon2id), and your AI agent never receives the plaintext or
  escapes its allowlist — every policy and integrity check fails closed.
- **The honest limit:** a process that has fully taken over your user account
  **while the vault is unlocked** can read what you can. No local software-only
  vault survives that; raising the bar needs hardware-backed keys or a remote
  broker, which are on the roadmap and will be **opt-in**. Until you turn those
  on you are at the basic protection level, and the CLI tells you so.
- **In progress:** mnemonic-based password recovery is temporarily disabled
  while we build a secure, mnemonic-bound implementation; use an encrypted
  `kvendra backup` as your recovery path for now.

## What's in 0.6.4

This release is a **security-hardening** release. An external static audit by
**Salva Ferrer** (avtn.es) plus several in-house adversarial passes turned up a
family of fail-open paths in the authorization layer (the crypto core was
sound); all exploitable ones now fail closed. Highlights: empty/invalid
`profile_id` denied, the shell/git/http allowlists actually enforced, the
escape-hatch quota enforced, `git clone` RCE closed, config/allowlist tampering
refused, per-repo git enforcement fixed, secret redaction widened. Full detail
in the [0.6.4 advisory](../security/advisory-cli-0.6.4.md) and
[CHANGELOG](../../CHANGELOG.md).

## Try it in two minutes

```bash
cargo install --locked kvendra
kvendra init                 # creates the vault; SAVE the recovery material it prints
kvendra secret add <profile> # store a credential (then sign an allowlist for it)
kvendra mcp serve            # expose the broker to your MCP client (Claude Code, Cursor, …)
```

`kvendra secret validate --all` shows your profiles and their allowlists.

## Thanks

To **Salva Ferrer** (avtn.es) for the responsible, high-signal audit, and to
everyone kicking the tyres and filing issues. An open-core security tool only
stays honest under scrutiny — thank you for the scrutiny.
