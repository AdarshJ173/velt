# Changelog

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
