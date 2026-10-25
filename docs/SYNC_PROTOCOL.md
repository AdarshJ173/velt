# Sync protocol

## Identities

Each developer has two independent key pairs:

1. **Authentication:** an existing Ed25519 SSH key (`~/.ssh/id_ed25519`). Only the public key is registered. There is no password.
2. **Encryption:** a locally generated X25519 key pair. The private key never leaves the OS keychain. The public key is registered so teammates can seal team keys to it.

They are separate on purpose: SSH keys are often hardware-backed or agent-managed and are not X25519 keys.

## Authentication

1. `POST /v1/auth/register` with `{username, ssh_public_key, encryption_public_key}`.
2. `POST /v1/auth/challenge` with `{username}` returns a 32-byte random challenge, UUID, expiry (5 minutes), and namespace `velt-auth-v1`.
3. The CLI signs the raw challenge with its SSH ED25519 key using the SSH signature format (`sshsig`) and namespace `velt-auth-v1`, SHA-512.
4. `POST /v1/auth/verify` with the PEM signature.
5. The relay verifies the signature against the stored public key, marks the challenge used, and issues a random 32-byte opaque session token (URL-safe base64), stored hashed (SHA-256) with a configurable TTL (default 24 hours).

Challenges are single-use and transactional (`FOR UPDATE`). Session tokens are bearer credentials stored in the OS keychain; the relay never stores the token itself.

## Team key hierarchy

- The team owner generates a random 32-byte **team key** (TK) locally.
- Environment payloads are encrypted with TK using ChaCha20-Poly1305.
- TK is distributed as **sealed envelopes**:

```
recipient, epoch, ephemeral_public_key, nonce, ciphertext
```

Sealing:

```
ephemeral = X25519 key pair (generated per envelope)
shared    = X25519(ephemeral_secret, recipient_public)
aad       = "velt-team-key-v1|<team-id>|<epoch>|<recipient>"   (wire prefix retained)
wrapping  = HKDF-SHA256(salt="velt-team-key-wrap-salt-v1", ikm=shared, info=aad)
ciphertext = ChaCha20-Poly1305(wrapping, nonce, aad, TK)
```

- The relay stores envelopes keyed by `(team_id, user_id, epoch)`.
- Opening requires the recipient's static X25519 private key; the relay cannot perform the DH.
- Envelopes are bound to team id, epoch and recipient username through the AAD. A modified envelope fails authentication.

## Team creation

The CLI generates the team UUID and TK, seals TK to itself, and sends both the team and its self-envelope to the relay. The relay inserts the team, owner membership and envelope in one transaction. Retrying a failed team creation cannot leave a keyless team.

## Environment blobs

Plaintext team payload:

```json
{
  "schema": 1,
  "team_id": "uuid",
  "environment": "production",
  "updated_at": 1790000000,
  "entries": { "KEY": { "value": "...", "updated_at": 0, "expires_at": null } },
  "checksum": "sha256 hex"
}
```

- AAD: `"velt-team-blob-v1|<team-id>|<environment>"`.
- Nonce: random 96-bit.
- The relay stores `nonce`, `ciphertext`, `checksum = SHA-256(ciphertext)`, version, author and timestamp.
- The CLI verifies the ciphertext checksum, decrypts, validates the payload checksum, team id and environment, then validates every key name and value.
- The server checks the plaintext checksum? No. It never sees plaintext. The checksum it stores is over ciphertext for integrity diagnostics; AEAD is the real authentication.

### Versions and conflicts

- First push: `base_version = null`; the relay requires no existing blob.
- Subsequent pushes: `base_version = <current>`; mismatch returns `409` with the current version in the message.
- `force = true` bypasses the version check and still increments the version.
- The CLI stores `base_version` and a SHA-256 fingerprint of local entries in the encrypted vault binding.
- Pull refuses to overwrite local changes unless `--merge` or `--force` is supplied.

## Roles and grants

| Role | Rank | Read | Push | Manage members | Audit | Rotate key |
| --- | --- | --- | --- | --- | --- | --- |
| owner | 4 | all | yes | yes | yes | yes |
| admin | 3 | all | yes | yes | yes | no |
| developer | 2 | granted envs | granted envs | no | no | no |
| ci_bot | 1 | granted envs | no | no | no | no |

- Environment grants are an array of environment names. Owner/admin ignore grants (all access).
- Developers/CI bots with an empty grant array have no environment access.
- The team owner is the only member who can rotate the key; the owner cannot be removed by the API.

## Key epochs and rotation

The relay tracks `teams.key_epoch`. Rotation is client-driven:

1. Owner fetches team details, all environment ciphertexts and current envelopes.
2. Owner decrypts every environment with the current TK.
3. Owner generates TK' and a new epoch `N+1`.
4. Owner re-encrypts every environment and seals TK' for every current member.
5. `POST /v1/teams/{id}/key-epoch` sends `{epoch, envelopes[], blobs[]}`.
6. In one transaction the relay verifies:
   - caller is the owner,
   - epoch is exactly current + 1,
   - there is exactly one envelope per current member,
   - every existing environment is re-encrypted with the current `base_version`.
7. The relay deletes old envelopes, inserts new ones, updates every blob version, bumps the epoch, and audits `key_rotated`.
8. Teammates fetch the new envelope on the next pull and update their local keychain entry.

Removing a member deletes their envelope and membership immediately. It cannot invalidate ciphertext they already downloaded. Rotation after revocation is required; the CLI prints this warning and the dashboard displays it.

## Relay API

All authenticated endpoints use `Authorization: Bearer <session-token>`. Errors use:

```json
{"error":{"code":"conflict","message":"..."}}
```

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/v1/auth/register` | register username and public keys |
| POST | `/v1/auth/challenge` | issue login challenge |
| POST | `/v1/auth/verify` | verify SSH signature, issue session |
| POST | `/v1/auth/logout` | delete current session |
| GET | `/v1/me` | current user and teams |
| GET | `/v1/users/{username}` | public encryption key lookup |
| GET/POST | `/v1/teams` | list/create teams |
| GET/DELETE | `/v1/teams/{id}` | details/delete team |
| POST | `/v1/teams/{id}/members` | invite with sealed envelope |
| PATCH/DELETE | `/v1/teams/{id}/members/{user_id}` | update role/grants, revoke |
| GET | `/v1/teams/{id}/envelopes` | own sealed team keys |
| GET | `/v1/teams/{id}/environments` | environment metadata |
| GET/PUT | `/v1/teams/{id}/environments/{env}` | pull/push encrypted blob |
| POST | `/v1/teams/{id}/key-epoch` | atomic key rotation |
| GET | `/v1/teams/{id}/audit` | admin audit trail |
| GET | `/v1/teams/{id}/events` | WebSocket events |
| POST | `/v1/dashboard/session` | one-time dashboard login link |
| GET | `/healthz`, `/readyz` | liveness/readiness |

## WebSocket events

Authenticate with `Authorization: Bearer` or `?token=` (URL-safe token). The server verifies membership, sends:

```json
{"type":"ready","team_id":"..."}
```

then events:

```json
{"type":"vault_updated","environment":"production","version":14,"created_at":1790000000}
```

Events are delivered through PostgreSQL `LISTEN/NOTIFY`, so any API instance can serve any WebSocket. Clients should treat them as invalidations and pull; events are not the source of truth.

## Server-visible metadata

The relay can see usernames, public keys, team names, memberships, roles, environment names, versions, sizes, timestamps, IP addresses (if logged/proxied), and audit events. It cannot see plaintext, team keys, or vault master keys. There is no server-side search over secret values.

## Cryptographic primitives

| Purpose | Primitive |
| --- | --- |
| Vault / team payload / envelope encryption | ChaCha20-Poly1305 (256-bit key, 96-bit random nonce) |
| Team key wrapping | X25519 + HKDF-SHA256 |
| Auth signatures | Ed25519 SSH signatures (`sshsig`), SHA-512 |
| Integrity metadata | SHA-256 |
| Lease capabilities | HMAC-SHA256 |
| Recovery | Shamir over GF(2^8) |
| Rule packs | Ed25519 detached signatures |
| Dashboard/session tokens | 256-bit OS CSPRNG, SHA-256 stored hashes |
