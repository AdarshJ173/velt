# Shared team vault files

A local `.velt.vault` is encrypted under the local OS-keychain master key. That
is deliberate: copying it to another account does not grant access. For a Git
checkout that teammates can open, export a second file encrypted under the
team key:

```bash
velt export --out .velt.shared.vault
git add .velt.shared.vault
```

`velt export` uses the vault's team binding to fetch/load the current team key,
then writes a version 2 line-oriented vault with:

- `key_mode team <team-id> <epoch>` in the clear header;
- each entry encrypted with AES-256-SIV under a key derived from the team key;
- the team binding encrypted under the same team key;
- no team key in the file.

The source vault is unchanged.

## Teammate checkout

The teammate must be a team member and must have an identity registered with
the relay. After authenticating:

```bash
velt auth register --server https://sync.example.com --username bob \
  --ssh-key ~/.ssh/id_ed25519
velt team key-fetch --team <team-id>
```

`team key-fetch` fetches the sealed team-key envelope for the logged-in
account, opens it with the local X25519 identity, and stores the 32-byte key in
the OS keychain. Then:

```bash
velt --vault .velt.shared.vault run -- npm run dev
```

or set `VELT_VAULT=.velt.shared.vault`. If the key is missing, Velt fails with
the exact `key-fetch` command instead of guessing.

## Git behavior

- Entries are one line each and sorted by name; disjoint additions merge with
  ordinary Git line merging.
- The header has no global revision/checksum, so a one-key edit changes one
  line.
- The `key_mode team <id> <epoch>` line is bound into every entry's AAD. Moving
  a ciphertext to another team or epoch, or changing the header team id, fails
  authentication.
- A merge that produces duplicate names is rejected.
- Changing the same key on two branches is a real conflict and must be resolved
  by a human.

## Rotation and revocation

A shared file names a team-key epoch. After `velt team rotate-key`, the old
epoch key may be deleted, so:

1. re-run `velt export --out .velt.shared.vault --force` from a member's local
   vault using the new epoch;
2. have teammates run `velt team key-fetch --team <id>` again;
3. commit the re-exported file.

Revocation is enforced by the relay. A removed member who already has the file
and the old team key can still decrypt it; rotate the team key and re-export.
Do not treat a committed shared file as a revocation mechanism.

## What is still local

- The local `.velt.vault` remains the source of truth for editing, leases,
  requests, recovery shares, and keychain-backed local operation.
- A shared file has no embedded member envelopes and no password fallback. Its
  availability depends on the teammate having fetched the team key.
- The current implementation does not auto-rekey shared files on rotation; this
  is an explicit export step.
- Key names, entry timestamps and equality are visible, exactly as in the local
  line format. Values are encrypted.
