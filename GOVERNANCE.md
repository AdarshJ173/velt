# Governance

## Maintainer model

Velt is maintainer-led. There is no voting membership and no corporate CLA. A
maintainer is added by unanimous consent of existing maintainers after a record
of high-signal reviews, tests, and threat-model work. Maintainers can be removed
for inactivity or for merging changes that violate the security contract.

The current maintainer list is the commit history of `main`, plus the repository
owner. This file is intentionally small until there is more than one active
maintainer.

## Two rings

- **Ring 1 (cryptographic core)** is maintainer-only for feature changes. It
  covers the vault format, AEAD/key hierarchy, recovery, keychain, leases, relay
  authentication/authorization, and the normative specifications. Bug reports,
  audits, known-answer tests, and fuzz targets are welcome.
- **Ring 2 (ecosystem)** covers audit rules, agent templates, CLI UX, docs,
  packaging, and integrations. It is open to assigned issues, not unsolicited
  patches.

The exact path lists and review requirements are in
[CONTRIBUTING.md](CONTRIBUTING.md).

## Decision process

1. **Security or format change:** open an issue with a threat model, failure
   modes, migration story, and test plan. Maintainers decide by consensus after
   review. A cryptographic primitive or format-version change needs an external
   reviewer.
2. **Ordinary change:** an assigned issue and one maintainer approval.
3. **Disagreement:** the status quo wins until there is evidence, a test, or a
   written threat-model argument. Security is not decided by popularity.
4. **No roadmap promises.** The repository states what is implemented and what
   is not; it does not sell future features as current capabilities.

## Releases

- Pre-1.0 releases may change the wire format; every incompatible change gets a
  new format version and a migration/refusal test.
- Release builds should be produced from a clean, locked dependency graph
  (`cargo build --locked`) with the pinned toolchain. Signing/provenance is a
  release requirement, not a substitute for code review.
- Security fixes are released on `main` and noted in `CHANGELOG.md`.
- No release is described as audited, SOC 2 compliant, or "military grade" unless
  a linked third-party attestation exists.

## Security reports

Private reports follow [SECURITY.md](SECURITY.md). There is no cash bounty. Do
not publish an exploit before coordinated disclosure.

## Licensing

The local CLI/core and specification are MIT OR Apache-2.0. The relay is
FSL-1.1-ALv2 with an Apache-2.0 future grant. New contributions are accepted
under the license of the crate they modify, plus the DCO. Existing MIT/Apache
code cannot be retroactively restricted. This is a legal decision, not a code
change; get counsel before changing it.
