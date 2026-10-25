# Security model

## Reporting

Use GitHub's private vulnerability reporting / Security Advisories for `AdarshJ173/velt`. Do not open a public issue for a vulnerability. Include affected version, reproduction, and impact. This project has no bug-bounty program.

Supported version: `0.1.x` (pre-1.0; security fixes land on `main`).

## Guarantees

1. **Vault confidentiality and entry integrity.** Each vault entry is independently encrypted and authenticated with AES-256-SIV under an HKDF-derived key. The entry name, key version, update timestamp, and expiry are bound as AAD; the team binding is separately encrypted. Wrong keys, modified entries, modified metadata, modified bindings, and format confusion fail closed. There is no password verifier.
2. **Mergeable format, bounded integrity.** There is no whole-file MAC. Per-entry AEAD cannot detect deletion of an entire entry line or rollback to an older file. Completeness requires signed Git commits, a trusted remote, or relay version history. Key names and deterministic equality are intentionally visible.
3. **Atomic persistence.** Vault writes go through a 0600 temporary file, fsync and rename. A crash cannot leave a half-written vault as the live file.
4. **Key isolation.** The relay never receives a vault master key, team key or plaintext. Team payloads are encrypted before upload; team keys are sealed to member X25519 public keys.
5. **Relay authentication.** Registration and login use Ed25519 SSH signatures over a random, single-use challenge with a fixed namespace. Session tokens are random and stored hashed server-side.
6. **Authorization.** Membership, role rank and environment grants are enforced on every blob read/write, audit access, envelope fetch and WebSocket connection. Removed members lose relay access immediately.
7. **Dashboard hardening.** One-time 5-minute login links, HttpOnly `SameSite=Strict` cookies, per-session CSRF tokens, CSP `default-src 'none'`, frame denial, no-store caching, HTML escaping.
8. **Memory hygiene.** Secret values and decrypted payload buffers are wrapped in `zeroize` types and wiped on drop. Errors and Debug implementations never print secret values.

## Non-guarantees

- **No memory locking.** Velt does not call `mlock`; the OS may swap or hibernate process memory. Full-memory encryption or a locked-memory allocator is not implemented.
- **No deletion or rollback detection.** A line-oriented vault authenticates each present entry, not the set of entries or the file's age. An attacker with write access can remove an entry or restore an older vault without a cryptographic error. Use signed commits, a trusted remote, filesystem permissions, and relay audit history.
- **Deterministic ciphertext leaks equality.** AES-SIV with deterministic nonces means identical entries produce identical ciphertext and changes are visible. This is the tradeoff for line-level Git merges. Key names are clear text by design.
- **A committed vault is not a shared team vault.** The local file is encrypted under the local OS-keychain master key. Team members cannot decrypt a copied `.velt.vault`; team sharing uses the relay's E2EE blobs and sealed team keys.
- **CI bootstrap credentials are plaintext in the runner.** `velt ci run` reads `VELT_IDENTITY_KEY`, `VELT_SSH_KEY_CONTENT`/`VELT_SSH_KEY` and an SSH passphrase from the environment. They are removed from the child environment, but the CI platform, its logs and anyone who can read its secrets can read them. Use a dedicated runner identity and rotate it. The team key stays in memory and is not written to the keychain.
- **No process sandbox.** Secrets are present in the child environment. Same-user processes can read `/proc/<pid>/environ` on Linux, inspect process memory, or attach debuggers. A child can write secrets to files or the network.
- **Redaction is best-effort.** It catches the injected value and common encodings in captured stdout/stderr. It cannot catch arbitrary transforms (hashing, chunking, encryption), values shorter than 4 bytes, values longer than 64 KiB, or output that never goes through the pipe.
- **Revocation is not retroactive.** A removed member may retain old ciphertext and team keys. Rotate the team key.
- **Audit is heuristic.** It detects placeholders, weak/expired values, known token formats, plaintext env files and permissions. It does not query breach feeds or verify credentials against providers.
- **Recovery shares are keys.** Anyone with a threshold of shares can decrypt the vault. Velt cannot revoke paper shares.
- **OS keychain is the root of trust.** If the logged-in OS session is compromised, the attacker can ask the keychain to unlock the vault. Hardware-backed keychains and OS login security matter.
- **No third-party security audit, SOC 2, ISO 27001, or penetration-test attestation** is included in this repository. Do not claim compliance based on the code alone.
- **No SSO/SAML/OIDC, SCIM, Jira/VPN ABAC, or billing.** The dashboard is local-passwordless via CLI link only.

## Threat model

| Adversary | Capability | Mitigation |
| --- | --- | --- |
| Stolen vault file | Reads `.velt.vault` | AEAD without the key; key is in the OS keychain |
| Malicious project file | Modifies entry ciphertext or metadata | Per-entry AES-SIV AAD fails closed |
| Malicious project file | Deletes an entry line or rolls the file back | Not detected by the file; signed commits/trusted remote/relay history required |
| Shoulder-surfing / logs | Reads terminal/history | Values masked in TUI, hidden prompts, `--stdin`, no values in list/audit/MCP schema |
| Compromised relay | Reads database, serves requests | Only public keys, envelopes, opaque ciphertext, metadata |
| Network attacker | Intercepts HTTP | Deploy TLS; ciphertext remains confidential even without it, but tokens/metadata need TLS |
| Removed teammate | Retains old keys/ciphertext | Relay revocation + `velt team rotate-key` |
| Malicious agent | Runs commands, prints output | Lease scoping, output redaction, no value APIs, human-in-loop requests, guardrail files |
| Compromised CI runner / build log | Reads runner environment, child process | Dedicated identity, bootstrap env stripped from child, short-lived session, relay revocation; the runner itself is trusted |
| Supply-chain attacker | Replaces binary/build | Not solved in-repo; use signed reproducible builds and pinned toolchains for production |

## Crypto choices

- AES-256-SIV (RFC 5297) for line-oriented vault entries and the encrypted team binding, with a 64-byte HKDF-SHA256-derived key and deterministic per-entry nonces.
- ChaCha20-Poly1305 (RFC 8439) for legacy format 1 vaults, team payload blobs, and key envelopes.
- X25519 (Curve25519 DH) + HKDF-SHA256 for team-key wrapping; low-order public keys are rejected by contributory-behavior checks.
- Ed25519 SSH signatures with namespace `velt-auth-v1` and SHA-512.
- SHA-256 for checksums and token hashes; constant-time comparison where bytes are compared.
- HMAC-SHA256 for local capability leases.
- Shamir's Secret Sharing over GF(2^8) using polynomial `0x11b`; shares are checksummed and vault-bound.
- Ed25519 detached signatures for optional rule packs.

## Operational guidance

1. Use full-disk encryption and a locked OS session.
2. Keep the relay behind TLS; set `VELT_PUBLIC_URL` to the HTTPS origin so the dashboard cookie is `Secure`.
3. Back up PostgreSQL metadata and, separately, recovery shares. Do not store recovery shares with the vault.
4. Rotate the team key after every member departure or device loss.
5. Restrict database and relay network access; the relay is not a public-internet-hardened multi-tenant SaaS without rate limiting/WAF in front.
6. Monitor audit events (`vault_pushed`, `vault_pulled`, `member_*`, `key_rotated`) for anomalies.
7. Treat lease tokens and session tokens as credentials; they are bearer capabilities.
