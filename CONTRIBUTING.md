# Contributing

Velt is a security tool. Drive-by pull requests are not accepted. Open an issue,
describe the threat or defect, and wait for a maintainer to assign it before
writing code. This is deliberate: unsolicited LLM-generated patches are costly
to review and can hide supply-chain changes.

## Two contribution rings

### Ring 1: cryptographic core (maintainer-only review)

Paths:

- `crates/velt-core/src/crypto.rs`
- `crates/velt-core/src/vault.rs`
- `crates/velt-core/src/keychain.rs`
- `crates/velt-core/src/recovery.rs`
- `crates/velt-core/src/sync.rs`
- `crates/velt-core/src/lease.rs`
- `crates/velt-server/src/auth.rs`
- `crates/velt-server/src/util.rs`
- `SPEC.md`, `docs/VAULT_FORMAT.md`, `docs/SYNC_PROTOCOL.md`

You may report bugs, add tests, and propose designs. Feature patches are
accepted only with:

- a written threat-model impact;
- known-answer or property tests for every changed cryptographic path;
- an update to `SPEC.md` for any wire-format change;
- two maintainer approvals;
- an external review for a new primitive, key hierarchy, or format version.

### Ring 2: ecosystem (reviewed, still gated)

Paths:

- `crates/velt-core/src/audit.rs` and `rules.rs`
- `crates/velt-cli/src/commands/` (except security-critical auth/sync paths)
- `crates/velt-cli/src/redact.rs`, `envfile.rs`, `detect.rs`
- agent templates, docs, shell completions, packaging, deployment examples

These are open to focused patches, but only after an issue has been discussed
and assigned. There are no "good first issue" bounties and no cash bug bounty.
High-signal contributors are worth more than a large queue of low-effort PRs.

## Hard rules

1. **No unsafe without a syscall reason.** `unsafe` is blocked in review unless
   it wraps a kernel/OS API that cannot be expressed safely. Add a `// SAFETY:`
   comment explaining every invariant, a test, and run Miri where applicable.
2. **No `unwrap()` or `expect()` in non-test code.** Return typed errors with
   `thiserror`. Tests may unwrap.
3. **Never log, format, or serialize a secret value.** Use `SecretValue` and
   `Zeroizing` types. Debug output stays redacted.
4. **No hidden network calls or telemetry.** Local commands must work offline.
5. **No new dependency without justification.** State what it replaces, its
   maintenance state, its license, and whether it is in the cryptographic path.
   Format or crypto dependencies need explicit maintainer review.
6. **Do not weaken redaction, authentication, or validation to make a test
   pass.** Fix the design or explain the tradeoff in the issue.
7. **Signed commits and DCO.** Sign commits with a verified SSH or GPG key and
   add `Signed-off-by: Name <email>` (`git commit -s`). No corporate CLA.
   Contributions are licensed under MIT OR Apache-2.0 for `velt-core`/`velt` and
   FSL-1.1-ALv2 for `velt-server`.
8. **Tests are part of the change.** Add a regression test for every bug. Run
   the commands below. Pull requests that skip checks are closed.

## Local checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./scripts/check-reproducible.sh   # Linux; builds the release CLI twice
```

On Linux, the keychain tests require a Secret Service session:

```bash
dbus-run-session -- bash -c '
  eval "$(printf "" | gnome-keyring-daemon --unlock --components=secrets 2>/dev/null)" || true
  cargo test --workspace
'
```

The CLI-to-relay end-to-end test starts an embedded PostgreSQL instance and runs
only on Unix-like systems.

## Format changes

`SPEC.md` is normative. A format change requires:

1. a new format version, never an in-place reinterpretation;
2. a migration or explicit refusal for old files;
3. a known-answer test vector;
4. updates to `docs/VAULT_FORMAT.md` and `docs/SECURITY.md`;
5. a statement about merge behavior, deletion/rollback detection, and
   deterministic-encryption leakage.

## Security reports

Do not open a public issue for a vulnerability. Use GitHub Security Advisories
for `AdarshJ173/velt`; see [SECURITY.md](SECURITY.md) and
[docs/SECURITY.md](docs/SECURITY.md). There is no public cash bounty.
