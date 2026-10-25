# Vault format (version 1)

## File layout

All integers are big-endian where applicable. The file is little more than an authenticated envelope around a JSON payload.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | magic `VELTVLT1` |
| 8 | 1 | format version `1` |
| 9 | 3 | reserved, zero |
| 12 | 16 | random vault id |
| 28 | 12 | ChaCha20-Poly1305 nonce |
| 40 | .. | ciphertext followed by the 16-byte Poly1305 tag |

- Maximum file size: 16 MiB.
- AAD: bytes `0..28` (magic, version, reserved, vault id).
- Nonce: generated from the OS CSPRNG for every save. Nonces are never reused intentionally.
- There is no KDF: the master key is 32 random bytes. There is no password verifier and no offline password guessing surface.

## Payload

The plaintext is compact JSON:

```json
{
  "schema": 1,
  "vault_id": "9f0c...32 hex...",
  "created_at": 1790000000,
  "updated_at": 1790000100,
  "revision": 7,
  "key_version": 1,
  "entries": {
    "DATABASE_URL": {
      "value": "postgres://...",
      "updated_at": 1790000100,
      "expires_at": 1792592000
    }
  },
  "binding": {
    "team_id": "uuid",
    "environment": "production",
    "epoch": 2,
    "base_version": 14,
    "base_checksum": "sha256 hex of entries"
  },
  "checksum": "sha256 hex"
}
```

- `entries` is a `BTreeMap`, so serialization is deterministic.
- `checksum` is SHA-256 over the serialized body without the `checksum` field. It is verified with constant-time comparison after decryption. AEAD already authenticates the data; the checksum catches logic/corruption bugs and gives a diagnosable error.
- `expires_at` is optional Unix seconds.
- `binding` is optional and encrypted. It records the last synced server version and a fingerprint of local entries.
- Names must match `[A-Za-z_][A-Za-z0-9_]*`, max 256 bytes. Values must be valid UTF-8 (Rust strings), contain no NUL, and are limited to 1 MiB each.

## Keys and accounts

OS credential store service: `dev.velt.vault`.

| Account | Contents |
| --- | --- |
| `vault:<vault-id>` | 32-byte vault master key |
| `lease-key:<vault-id>` | 32-byte HMAC lease signing key |
| `identity:<server-hash>:<username>` | 32-byte X25519 private identity |
| `session:<server-hash>:<username>` | relay session token |
| `team-key:<team-id>:<epoch>` | 32-byte team key |

`server-hash` is the first 8 bytes of SHA-256 of the normalized server URL. Secrets are encoded as hex only because the platform APIs accept strings; encoding buffers are zeroized.

## Atomic writes

1. Create a unique temporary file in the vault's directory with mode 0600 (`create_new`).
2. Write ciphertext, `fsync`.
3. Rename over the target.
4. Set mode 0600 again, best-effort `fsync` of the directory.
5. On failure, remove the temporary file.

The advisory lock key is the canonical path; it prevents two Velt processes from losing each other's read-modify-write updates. It is not a security boundary.

## Recovery shares

```
velt1.<vault-id-hex>.<threshold>.<total>.<index>.<base32-share>.<checksum>
```

- The secret is the 32-byte master key interpreted as 32 independent GF(2^8) polynomials.
- Coefficients are random; evaluation is Horner's method over `x = 1..=total`.
- Reconstruction is Lagrange interpolation at `x = 0`.
- Checksum: first 8 bytes of SHA-256 over `"velt-recovery-v1" || vault_id || threshold || total || index || share`.
- `total <= 255`; `threshold >= 2`.
- Extra shares are cross-checked by reconstructing with substituted subsets; inconsistent sets fail closed.
- Shares are displayed once or written as 0600 files. They are equivalent to the master key.

## Compatibility

Any incompatible change increments the format version; readers reject newer versions rather than guessing. Vaults created under the pre-rebrand format are not readable and must be recreated.
