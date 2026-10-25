# Security policy

Velt is pre-1.0. Security fixes land on `main`; supported version: `0.1.x`.

## Reporting

Use GitHub's private vulnerability reporting / Security Advisories for
`AdarshJ173/velt`. Do not open a public issue, discuss the bug in chat, or post a
proof of concept before a fix is available. Include:

- affected version or commit;
- platform and threat model;
- minimal reproduction;
- whether the issue exposes plaintext, a master/team key, a session token, an
  authentication bypass, or a denial of service;
- any suggested fix.

We will acknowledge within 7 days and aim to triage within 14 days. A coordinated
disclosure date is agreed after triage, normally 90 days or sooner once a fix is
released.

There is **no public cash bug bounty**. Do not send automated low-severity
reports expecting payment. The project will credit reporters who want credit.

## In scope

- Vault format confidentiality/integrity failures: AES-256-SIV entry
  authentication, AAD binding, key derivation, migration from format 1.
- Keychain, recovery-share, lease-token, identity-key, and session-token
  handling.
- Relay authentication, RBAC/environment-grant bypass, envelope substitution,
  optimistic-version bypass, dashboard link/CSRF/CSP issues.
- Secret leakage through CLI output, TUI, MCP, audit/inspect/schema output, or
  the documented output redactor.

## Out of scope

These are documented boundaries, not vulnerabilities:

- an attacker with root, kernel, debugger, or same-user process access reading
  `/proc/<pid>/environ`, process memory, swap, or the unlocked keychain;
- a malicious application exfiltrating secrets it was intentionally given;
- transformations the redactor does not claim to catch (hashing, encryption,
  chunking, values shorter than 4 bytes, values longer than 64 KiB);
- deletion of a whole vault entry line or rollback to an older vault file
  without signed Git commits/trusted remote history (per-entry AEAD does not
  authenticate absence);
- deterministic AES-SIV equality leakage and clear-text key names, which are
  required for line-level Git merging;
- a user who commits a local `.velt.vault` expecting teammates to decrypt it
  without the relay or the owner's keychain;
- a compromised CI runner, build log, or CI platform secret store reading the
  bootstrap identity/SSH key; use a dedicated runner identity;
- denial of service against a self-hosted relay with no rate limiting/WAF;
- physical attacks, cold-boot attacks, or compromised OS/keychain login;
- compliance claims. There is no third-party audit, SOC 2, ISO 27001, or
  penetration-test attestation in this repository.

## Operational baseline

Use full-disk encryption and a locked OS session. Back up PostgreSQL metadata and
recovery shares separately. Rotate the team key after member departure or device
loss. Put the relay behind TLS and a rate-limiting reverse proxy. Do not use the
dashboard as a public-internet multi-tenant service without additional hardening.

Full threat model: [docs/SECURITY.md](docs/SECURITY.md).
