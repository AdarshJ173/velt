# Deployment

## Local compose stack

```bash
docker compose up --build
curl http://127.0.0.1:8080/readyz
```

The compose file is for evaluation only: it uses a development database password and plain HTTP.

Point the CLI at it:

```bash
velt auth register --server http://127.0.0.1:8080 --username alice
```

## Configuration

| Variable | Default | Notes |
| --- | --- | --- |
| `DATABASE_URL` | required | PostgreSQL connection string |
| `VELT_BIND` | `127.0.0.1:8080` | API listen address |
| `VELT_SESSION_TTL_HOURS` | `24` | clamp 1..720 |
| `VELT_CHALLENGE_TTL_SECONDS` | `300` | clamp 30..900 |
| `VELT_MAX_BLOB_BYTES` | `4194304` | clamp 1 KiB..16 MiB |
| `VELT_MAX_ENVELOPES` | `512` | rotation batch limit |
| `VELT_PUBLIC_URL` | unset | HTTPS origin used for dashboard links and `Secure` cookies |
| `RUST_LOG` | `info,sqlx=warn,tower_http=info` | tracing filter |

Migrations are embedded in the binary and run automatically at startup before the listener is bound. To inspect them, see `crates/velt-server/migrations/`.

## Production checklist

1. **TLS:** terminate at a reverse proxy or load balancer. Caddy example:

   ```caddyfile
   sync.example.com {
       reverse_proxy velt:8080
   }
   ```

   Set `VELT_PUBLIC_URL=https://sync.example.com` so dashboard cookies are `Secure`. The CLI refuses plaintext `http://` relay URLs unless the host is loopback (`localhost`, `127.0.0.1`, `::1`).

2. **Database:** managed PostgreSQL 15+ with TLS, automated backups and point-in-time recovery. The relay stores only metadata and ciphertext, but losing the database loses envelopes and memberships.
3. **Network:** do not expose PostgreSQL. Restrict the relay at the firewall/WAF; the application does not include multi-tenant rate limiting. Put auth endpoints behind a reverse-proxy rate limit.
4. **Secrets:** provide `DATABASE_URL` via the platform secret manager, not a committed env file.
5. **Process:** run as a non-root user (the image does), with a read-only root filesystem if your platform supports it.
6. **Replicas:** the API is stateless. Run multiple replicas behind a load balancer; PostgreSQL `LISTEN/NOTIFY` fans out events to every instance. No sticky sessions are required for HTTP. WebSockets connect to one instance and receive cluster-wide events through the listener.
7. **Monitoring:** scrape `/readyz`; alert on 5xx rate, auth failures, and audit actions `member_removed` / `key_rotated` without a follow-up rotation.
8. **Backups:** back up PostgreSQL. Back up recovery shares separately and offline. There is no server-side key escrow: if every member loses their device and no recovery shares exist, the team environment is unrecoverable.

## Docker image

```bash
docker build -f deploy/Dockerfile -t velt-relay:0.1.0 .
docker run --rm -p 8080:8080 \
  -e DATABASE_URL=postgres://user:pass@host:5432/velt \
  -e VELT_BIND=0.0.0.0:8080 \
  -e VELT_PUBLIC_URL=https://sync.example.com \
  velt-relay:0.1.0
```

The image contains only the static-ish Rust binary and CA certificates; it runs as UID 10001.

## Scaling

- **API:** horizontally scalable, no local state except an in-memory broadcast bus fed by PostgreSQL notifications.
- **Database:** use a connection pooler if replica count grows; default pool is 32 connections per instance.
- **Events:** `pg_notify` payloads are small team events; WebSocket clients should pull on invalidation. There is no Redis dependency.
- **Blob storage:** blobs are capped by `VELT_MAX_BLOB_BYTES`; PostgreSQL `bytea` is sufficient for team-sized environments. Large binary secret bundles should be stored elsewhere and referenced.
- **Availability:** developers can decrypt and run local vaults while the relay is down; only pushes/pulls and new envelope retrieval are unavailable.

## Operations

### Health

- `GET /healthz` — process liveness.
- `GET /readyz` — executes `SELECT 1`; returns 503 when the database is unavailable.

### Audit

Admins can read `/v1/teams/{id}/audit` or the dashboard CSV. PostgreSQL retains events by team; plan a retention policy if pull volume is high.

### Revocation and rotation

```bash
velt team remove bob --yes
velt team rotate-key --team <team-id>
```

Removal is immediate at the relay. Rotation is client-driven because the relay has no keys. Back up the rotated key state? Team keys live in the OS keychain; envelopes in PostgreSQL. Old epochs are deleted from keychains only on the rotating owner's machine; other members retain historical keys in their keychain. Rotate after any departure.

### Upgrades

1. Back up PostgreSQL.
2. Deploy the new binary; migrations run at startup.
3. Migrations are additive; there is no down migration. Roll back by restoring the database backup and previous binary.
4. CLI and server are versioned independently but share the HTTP protocol; keep them within the same minor version.

### Disaster recovery

- **Relay loss:** restore PostgreSQL. Ciphertext and envelopes are recoverable; plaintext never existed there.
- **Member device loss:** the member re-registers with a new SSH key? The username is unique; recovery requires an owner/admin to remove the old member and invite the returning user. Username re-registration is not supported; plan identity lifecycle accordingly.
- **Vault loss:** restore the encrypted file. If the keychain entry is gone, use Shamir shares; if there are no shares and no key, the vault is unrecoverable by design.

## CI

The included workflow runs formatting, clippy with `-D warnings`, the core/CLI/server tests, and the full CLI↔relay end-to-end test under a virtual D-Bus Secret Service on Linux. The embedded PostgreSQL test binary is downloaded on first run and cached by the Rust cache.

Cross-platform release builds are produced by `.github/workflows/release.yml` for Linux, macOS and Windows. Linux builds need `libdbus-1-dev` for `keyring`; release artifacts are unsigned. For production distribution, add code signing, notarization, reproducible-build verification and checksums.
