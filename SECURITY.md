# Security Policy

## Kvendra CLI — what protection you have

If you use the `kvendra` CLI vault, read
[**what protects you and what does not**](docs/security/protection-levels.md)
before you rely on it. In short: your encrypted files are safe at rest (bounded
by your master password) and your AI agent never holds the plaintext, but a
process that has fully taken over your user account while the vault is unlocked
can read what you can read. That limit, and the opt-in ways to raise it
(hardware-backed keys, remote broker), are documented plainly. The most recent
security release is described in the
[0.6.4 advisory](docs/security/advisory-cli-0.6.4.md).

## Reporting a Vulnerability

We take security seriously. If you discover a vulnerability in any Kvendra product, please report it responsibly.

**Email:** security@kvendra.ai

Please include:

- A description of the vulnerability
- Steps to reproduce (if applicable)
- The affected version or commit
- Any proof-of-concept code or logs (if safe to share)
- Your contact information for follow-up

We will acknowledge your report within **72 hours** and provide a timeline for remediation within **7 days**.

## Disclosure Policy

We follow a **coordinated disclosure** model:

1. You report the issue privately to security@kvendra.ai
2. We acknowledge, investigate, and remediate
3. We coordinate a public disclosure date with you (typically 30–90 days after fix)
4. We credit you in the advisory unless you prefer to remain anonymous

## Scope

This policy applies to all Kvendra products and services, including but not limited to:

- The Kvendra platform (kvendra.com, kvendra.ai)
- Open-source SDKs and CLI tools published under github.com/KvendraAI
- Self-hosted distributions (Helm chart, Docker compose)

## Out of Scope

- Issues in third-party dependencies (please report upstream)
- Social engineering attacks against Kvendra employees
- Physical security
- Denial-of-service via excessive load (use rate limits, contact admin@kvendra.ai for testing)

## Safe Harbor

We will not pursue legal action against researchers who:

- Make a good-faith effort to follow this policy
- Avoid privacy violations, data destruction, and service degradation
- Do not access or modify data belonging to others

## Contact

- Security reports: security@kvendra.ai
- General inquiries: hello@kvendra.ai
- Admin: admin@kvendra.ai
