# Changelog

## Unreleased

- Local vault format 2: line-oriented, one AES-256-SIV ciphertext per entry,
  deterministic nonces, AAD-bound names/timestamps/expiry, encrypted binding,
  atomic 0600 writes. Disjoint entries merge with ordinary Git; no global
  revision/checksum line prevents line merges.
- Format 1 (`VELTVLT1`) remains readable and is migrated on the next save.
- Known-answer vector, duplicate/tamper/deletion-semantics tests, and a
  `git merge-file` merge test.
- Normative [SPEC.md](SPEC.md), contribution rings, governance, and a revised
  threat model. Per-entry AEAD does not authenticate deletion or rollback;
  deterministic equality is documented.
- License split: MIT OR Apache-2.0 for the local CLI/core; FSL-1.1-ALv2 for the
  relay with a two-year Apache-2.0 future grant. SPEC.md is CC0-1.0.
- CI: locked builds, no-unwrap/expect production lints, reproducible Linux
  release build check, keyless Sigstore signing and SLSA-style provenance
  requests in the release workflow.
- `velt ci run`: headless team-environment injection with a CI-only X25519
  identity and SSH key. No local vault, no keychain writes, no persisted team
  key; bootstrap credentials are stripped from the child. GitHub Actions and
  Vercel usage documented in `docs/CI.md`.

## 0.1.0

Initial production-oriented release.

- Encrypted local vault (`.velt.vault`), ChaCha20-Poly1305, OS keychain, zeroize, atomic writes.
- `velt init` stack detection, `.env` import and best-effort shredding, agent guardrail installation.
- `velt set/get/list/remove`, `velt inspect/schema`, `velt audit` with entropy, format, expiry, `.env` and signed rule-pack checks.
- `velt run` process injection, signal forwarding, child exit codes, streaming multi-encoding output redaction.
- ratatui interactive editor with masking, reveal, validation and dirty-state prompts.
- Shamir GF(2^8) recovery shares with checksum and vault binding.
- MCP stdio server, token-optimized `--llm-docs`, scoped HMAC leases, human-in-the-loop secret requests.
- SSH Ed25519 challenge auth, X25519/HKDF sealed team keys, opaque encrypted environment blobs.
- Axum + PostgreSQL zero-knowledge relay, RBAC, audit trail, WebSocket events, optimistic versioning.
- Team create/invite/share/remove/audit, client-driven key rotation, revocation.
- Server-rendered dashboard with one-time CLI login, CSRF/CSP, member management and audit CSV.
- Docker/compose deployment, embedded migrations, health/readiness, TLS-capable SQLx.
- Cross-platform CI with clippy `-D warnings` and full CLI-to-relay end-to-end tests.
