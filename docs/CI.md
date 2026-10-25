# Headless CI

`velt ci run` fetches a team environment from the relay, decrypts it with a
CI-only X25519 identity, injects the values into one child process, and returns
the child's exit code. It does not create a local vault, does not read or write
the OS keychain, and does not persist the team key.

This is the CI primitive for GitHub Actions, Vercel, Buildkite, GitLab, and any
other runner that can execute a command with environment variables. It does not
push secrets into a provider's environment store; that would put plaintext
through a second API and make it available to every later build.

## One-time CI identity

Create a separate identity for the runner. Do not reuse a developer's identity.

```bash
umask 077
openssl rand -hex 32 > ci-identity.hex
VELT_IDENTITY_KEY="$(cat ci-identity.hex)" \
  velt auth register \
    --server https://sync.example.com \
    --username ci-bot \
    --ssh-key ./ci_ed25519
```

Then invite the runner to the team:

```bash
velt team invite ci-bot --role developer --env production --team <team-id>
```

Store these as CI secrets:

- `VELT_IDENTITY_KEY`: the 64-hex-character contents of `ci-identity.hex`
- `VELT_SSH_KEY_CONTENT`: the OpenSSH private key for `ci-bot` (or use
  `VELT_SSH_KEY` with a runner-local path)
- `VELT_SERVER_URL`
- `VELT_USERNAME=ci-bot`

The relay still enforces membership, role, environment grants and key epochs.
`ci-bot` must be a member with access to the requested environment.

## Run

```bash
velt ci run \
  --team <team-id> \
  --env production \
  -- npm run build
```

The child receives the team environment. Bootstrap variables
(`VELT_IDENTITY_KEY`, `VELT_SSH_KEY`, `VELT_SSH_KEY_CONTENT`,
`VELT_SSH_KEY_PASSPHRASE`) are removed from the child environment. Output is
redacted when stdout/stderr are captured; use `--redact always` to force it or
`--redact never` only when you explicitly need raw output.

`--server`, `--username`, `--ssh-key` and `--identity-key` override the
environment. `VELT_SSH_KEY_CONTENT` is useful on platforms that cannot mount a
key file.

## GitHub Actions

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      VELT_SERVER_URL: ${{ secrets.VELT_SERVER_URL }}
      VELT_USERNAME: ci-bot
      VELT_IDENTITY_KEY: ${{ secrets.VELT_IDENTITY_KEY }}
      VELT_SSH_KEY_CONTENT: ${{ secrets.VELT_SSH_KEY_CONTENT }}
    steps:
      - uses: actions/checkout@v4
      - name: Install velt
        run: cargo install --git https://github.com/AdarshJ173/velt --locked velt
      - name: Build with team secrets
        run: velt ci run --team "$TEAM_ID" --env production -- npm run build
```

`TEAM_ID` can be a repository variable. The relay is contacted at build time; a
network outage fails the step. The team key is opened in memory and not stored
in the runner keychain.

## Vercel

Use a build command that wraps the framework build:

```bash
velt ci run --team <team-id> --env production -- npm run build
```

Set `VELT_SERVER_URL`, `VELT_USERNAME`, `VELT_IDENTITY_KEY` and
`VELT_SSH_KEY_CONTENT` as sensitive Vercel environment variables. The Vercel
build image must have the `velt` binary available (vendor it into the build
image or install it in a prebuild step). Do not print the identity key or the
SSH key content in build logs.

## Security boundaries

- The CI platform, its build logs and anyone who can read its secrets can read
  the bootstrap credentials. Use a dedicated runner identity and rotate it when
  a runner is removed.
- The child can read every team secret injected into it and can send it
  anywhere. Redaction only covers captured output.
- The relay is online. `ci run` does not provide offline decryption; use a local
  vault for that.
- Revocation is enforced at authentication and blob fetch. A job that already
  started may finish with values it fetched; rotate the team key after removal.
- `ci run` does not write `.velt.vault`, does not write the team key to the
  keychain, and rejects `--json` because stdout belongs to the child.
