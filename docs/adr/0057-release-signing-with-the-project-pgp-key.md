# ADR 0057: Sign release tags and `SHA256SUMS` with the project PGP key's primary

- **Status:** Proposed
- **Date:** TBD (accepted on merge)
- **Deciders:** Project lead
- **Related:**
  - Implements [RFC-0017](../rfcs/0017-alpha-distribution.md) §5 and §11 (Accepted 2026-11-03), and resolves its unresolved question "Primary key or subkey".
  - Supersedes the disclosure-only wording of [ADR-0006](0006-commit-signing-ssh-not-gpg.md) §Decision and §Consequences/Neutral. Commit signing stays SSH.
  - Rotation follows [ADR-0005](0005-pgp-key-two-year-expiry.md). Used by [ADR-0054](0054-release-artifact-integrity.md) §4.

## Context

ADR-0006 moved commit signing to SSH keys and kept the PGP key "for the
embargoed-disclosure path", stressing "one keypair per purpose". In
practice `v0.1.0` was then tagged with that key. RFC-0017 makes the key
sign every release tag and every `SHA256SUMS`, so users verify one
published key for both the source and the binaries.

That broadens an accepted decision, so it needs a superseding ADR.

The key is:

```
pub ed25519 2026-05-10 [SC] [expires: 2028-05-09]
    66DB 5100 B070 0E4A E051  971F 9A8D FF06 AFD2 5B24
sub cv25519 2026-05-10 [E]
```

The primary can sign and certify. The only subkey encrypts. There is no
signing subkey.

## Decision

We will sign release tags and each release's `SHA256SUMS` with the
project PGP key's **primary**, only in the maintainer's terminal. A
dedicated signing subkey is deferred to the key's next rotation.

- **Release tags.**
  `git -c gpg.format=openpgp tag -s -u 9A8DFF06AFD25B24 vX.Y.Z`.
- **`SHA256SUMS`.**
  `gpg --armor --detach-sign -u 9A8DFF06AFD25B24` over the file the
  maintainer recomputed (ADR-0054 §4).
- **Commits.** Commits stay SSH-signed. ADR-0006's commit decision is
  unchanged.
- **Disclosure encryption** keeps using the `[E]` subkey.
- **Where the key lives.**
  - The private key, including its passphrase, never goes to CI, a
    GitHub secret or any machine other than the maintainer's.
  - Signing is a manual step that needs a TTY.
- **Rotation (ADR-0005, by 2028-05-09).**
  - The successor key is published in `keys/` with a signature from the
    old key, and `SECURITY.md` names both fingerprints during the
    overlap.
  - The rotation reconsiders a signing-only subkey, which would keep one
    fingerprint for users while separating purposes.
  - Public keys that signed published releases stay in `keys/`, each
    with its validity window, and join ADR-0054 §7's pin set as retired
    keys. Old releases remain verifiable after the key expires, under
    that section's retired-key rule. The rule accepts `EXPKEYSIG` only
    for a release whose immutable record dates it inside the key's
    window.
- **Compromise.**
  - Publish the revocation certificate (ADR-0005). It is a hard
    revocation, so every signature the key ever made counts as made by a
    revoked key, whatever its date. This is intended, because an attacker
    holding the key can backdate a signature.
  - `gpg --verify` alone still exits 0 and prints "Good signature" for
    such a signature. Every check in the release chain is ADR-0054 §7's
    pinned signature check, which fails on `REVKEYSIG` and `KEYREVOKED`.
    After the revocation reaches a user's keyring, every PGP check of
    every release fails.
  - **"Unaffected" is decided without the PGP key.** An attacker can
    forge signature timestamps. A release counts as unaffected only when
    evidence the key does not control shows it was published, assets
    and all, before the earliest possible exposure. That evidence is:
    - GitHub's immutable-release record (`gh release verify`, ADR-0054
      §5);
    - the build attestations with their transparency-log time
      (`gh attestation verify`, ADR-0054 §4).
  - **A security advisory, signed by the successor key** (published
    under `keys/` as under rotation):
    - gives the earliest possible exposure time;
    - lists each unaffected release with the SHA-256 of its
      `SHA256SUMS`;
    - lists every later release as untrusted.
  - **After a compromise, users verify old releases differently.** They
    use the attestations plus the successor-signed advisory instead of
    `SHA256SUMS.asc`. ADR-0054 §6 says so.
  - **The fix ships as a new release** signed with the successor key.
    Immutable releases (ADR-0054 §5) cannot take a replacement
    signature.

## Consequences

### Positive

- One fingerprint, already published in `SECURITY.md`, verifies tags
  and binaries alike, and `v0.1.0` is already signed with it.

  The caveat is that `v0.1.0` was published before immutable releases
  (ADR-0054 §5). Once this key is retired or expires, the `v0.1.0` tag
  cannot meet ADR-0054 §7's retired-key rule, which needs an
  immutable-release record. `v0.1.0` has no binary assets. Its source
  stays identifiable by commit `1fb977e` on `main` and by its Zenodo
  archive.
- No new key material to generate, publish or teach before `0.2.0`.

### Negative

- The key that encrypts disclosures now also anchors releases.
  Compromising it now harms two things. The mitigation is that it is
  used only on the maintainer's machine, behind a passphrase.
- ADR-0006's "one keypair per purpose" no longer holds for PGP. It still
  holds between SSH (commits) and PGP (releases and disclosure).

### Neutral

- The signatures are Ed25519 (EdDSA), classical by design. Post-quantum
  signatures over release artifacts depend on OpenPGP's post-quantum
  work, outside Phase 3.

## Alternatives considered

### Alternative 1: a separate release-only PGP key

This keeps "one keypair per purpose". It also means a second key to
publish, rotate and explain, and `v0.1.0` would remain signed by the
disclosure key.

### Alternative 2: add a signing subkey now

This separates purposes under one fingerprint. It changes the published
key right after `0.1.0` was signed and adds no protection while the primary
stays on the same machine. Deferred to the rotation.

### Alternative 3: sign releases with the maintainer's SSH key

`git` can SSH-sign tags, but `SHA256SUMS` would then need
`ssh-keygen -Y sign`, and that key is personal, not the project's.
Users would have to trust a personal key.

## Links

- [RFC-0017](../rfcs/0017-alpha-distribution.md) §5, §11
- [ADR-0005](0005-pgp-key-two-year-expiry.md), [ADR-0006](0006-commit-signing-ssh-not-gpg.md)
- `SECURITY.md`, `keys/security.asc`
