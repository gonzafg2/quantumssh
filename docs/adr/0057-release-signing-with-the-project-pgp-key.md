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
  - The successor key is published in `keys/`, signed by the old key,
    and added to `keys/release-keys.txt` (ADR-0054 §6). The old key moves
    to `keys/retired/` with its window. `SECURITY.md` names both
    fingerprints during the overlap. The `_release-key.quantumssh.org`
    TXT record and the tap's pinned current fingerprint are updated in
    the same change (ADR-0056 §4).
  - The rotation reconsiders a signing-only subkey, which would keep one
    fingerprint for users while separating purposes.
  - Public keys that signed published releases stay in `keys/`, each
    with its validity window, and join ADR-0054 §7's pin set as retired
    keys. Old releases remain verifiable after the key expires, under
    that section's retired-key rule. The rule accepts `EXPKEYSIG` only
    for a release whose immutable record dates it inside the key's
    window.
- **Compromise.** These steps are done in order:
  1. **Revoke where verifiers look.**
     - Append the hard revocation certificate (ADR-0005) to
       `keys/security.asc` in an SSH-signed commit on `main`.
     - In the same commit, mark the key `revoked` in
       `keys/release-keys.txt`.
     - Update `SECURITY.md` and the tap's pinned fingerprint
       (ADR-0056 §4).
     - Every documented verifier imports from `main`: ADR-0053's
       `precheck`, `verify-download.sh` and the tap's CI. A revocation
       published only to a keyserver would leave them importing a clean
       key, and ADR-0054 §7 would see a clean `VALIDSIG`.
  2. **Fail every PGP check.**
     - The revocation is hard, so every signature the key ever made
       counts as made by a revoked key, whatever its date. This is
       intended, because an attacker holding the key can backdate a
       signature.
     - `gpg --verify` alone still exits 0. ADR-0054 §7's pinned check
       fails on `REVKEYSIG` and `KEYREVOKED`, so once users re-fetch and
       re-import, every PGP check of every release fails.
     - The advisory tells users to re-fetch and re-import.
     - A negative test in `verify-download.sh`'s suite and in the tap's
       CI keeps this true: a revoked `keys/security.asc` must make both
       fail.
  3. **Classify releases without the PGP key, and exhaustively.**
     - Signature timestamps are signer-chosen, so they decide nothing.
     - A release is unaffected only when evidence the key does not
       control shows it was published before the earliest possible
       exposure, assets and all. That evidence is the immutable-release
       publication record (`gh release verify` and `verify-asset`,
       ADR-0054 §5) and the build attestations' transparency-log time.
     - The advisory lists every unaffected release by the SHA-256 of its
       `SHA256SUMS`, and states that **every release not on that list is
       untrusted**. There is no denylist keyed to a signature time.
     - The successor-signed fix is on the list, by digest.
  4. **Authenticate the successor without the old key.**
     - In a compromise the old key's certification proves nothing. The
       successor's fingerprint must reach users through channels the PGP
       key does not control:
       - an SSH-signed commit on `main` (ADR-0006) that adds the key to
         `keys/` and the manifest. It is independent only of a PGP-key
         compromise: ADR-0006's SSH key lives on the same maintainer
         endpoint, and threat model §5.5.2.b includes that endpoint;
       - a DNSSEC-signed TXT record, `_release-key.quantumssh.org`,
         carrying the current release-key fingerprint. It is set
         when this ADR is implemented and updated at every rotation.
         Changing it needs the Cloudflare account, a separate credential
         with its own second factor. Users check it with
         `dig +dnssec TXT _release-key.quantumssh.org`.
     - `quantumssh.org` itself is **not** a channel. It is a 301 to the
       GitHub repository (`docs/infrastructure.md` §"Web endpoints").
     - **Residual risk.** A compromise of the maintainer's endpoint
       together with the Cloudflare account defeats both channels. With
       one maintainer there is no independent witness. That residual
       belongs under threat model §7 (maintainer compromise).
  5. **Ship the fix as a new release** signed with the successor key.
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
