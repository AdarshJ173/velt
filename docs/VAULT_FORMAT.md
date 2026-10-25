# Vault format

The normative format specification is [SPEC.md](../SPEC.md). This page is the
short operational summary.

## On disk

`.velt.vault` is a line-oriented UTF-8 file:

```text
VELT-VAULT 2
id 9f0c...32 lowercase hex...
created_at 1790000000
key_version 1
key_mode team <team-id> <epoch>         # optional; omitted for local-key vaults
binding <base64url ciphertext>          # optional, encrypted RemoteBinding
ENTRY API_KEY 1790000100 - <base64url AES-SIV ciphertext>
ENTRY DATABASE_URL 1790000100 1792592000 <base64url AES-SIV ciphertext>
```

- Entries are sorted by key name. Each entry is encrypted independently with
  AES-256-SIV under a key derived from the vault's 32-byte OS-keychain key.
- Key names, update times, and expiry are clear text but authenticated as AAD.
  Values are never stored in plaintext.
- The team binding is encrypted independently.
- `key_mode team <id> <epoch>` marks an exported file encrypted under the team
  key. The header is public; the key is not in the file. Team id/epoch are bound
  into every entry's AAD, so moving an entry between team files fails closed.
- A local file has no `key_mode` line and uses the OS-keychain master key.
- Unchanged entries produce byte-identical lines; independent additions merge
  with normal Git line merging. There is no global revision or checksum line.
- Entry deletion is not detectable from the file alone; per-entry AEAD only
  authenticates entries that are present. Use signed Git commits or relay
  audit history for completeness.
- An existing `VELTVLT1` binary vault is read with the same master key and
  rewritten as format 2 on the next save.

## Limits

| Item | Limit |
| --- | --- |
| Vault file | 16 MiB |
| Entries | 100,000 |
| Name | 256 bytes, `[A-Za-z_][A-Za-z0-9_]*` |
| Value | 1 MiB UTF-8, no NUL |

## Keys and accounts

OS credential store service: `dev.velt.vault`.

| Account | Contents |
| --- | --- |
| `vault:<vault-id>` | 32-byte vault master key |
| `lease-key:<vault-id>` | 32-byte HMAC lease signing key |
| `identity:<server-hash>:<username>` | 32-byte X25519 private identity |
| `session:<server-hash>:<username>` | relay session token |
| `team-key:<team-id>:<epoch>` | 32-byte team key |

`server-hash` is the first 8 bytes of SHA-256 of the normalized server URL.
Secrets are encoded as hex only because platform APIs accept strings; encoding
buffers are zeroized.

## Atomic writes

1. Create a unique temporary file in the vault's directory with mode 0600.
2. Write the full text, `fsync`.
3. Rename over the target.
4. Set mode 0600 again, best-effort `fsync` of the directory.
5. On failure, remove the temporary file.

The advisory lock key is the canonical path; it prevents two Velt processes
from losing each other's read-modify-write updates. It is not a security
boundary.

## Recovery shares

```text
velt1.<vault-id-hex>.<threshold>.<total>.<index>.<base32-share>.<checksum>
```

Shares encode the 32-byte master key. The checksum is the first 8 bytes of
SHA-256 over `"velt-recovery-v1" || vault_id || threshold || total || index ||
share`. Shares are equivalent to the key; store them separately from the vault.

## Compatibility

Version 2 is the current write format. Version 1 binary vaults remain readable.
Any incompatible change increments the version and readers reject newer files.
