# Changelog

All notable changes to QuantumSSH will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial project scaffolding, governance documents, contribution
  guidelines, license, and CI/CD configuration.
- Project security PGP key published at `keys/security.asc`
  (Ed25519 + Curve25519, fingerprint
  `66DB5100B0700E4AE051971F9A8DFF06AFD25B24`, expires 2028-05-09).
  The `<TBD>` placeholder in `SECURITY.md` is replaced with the
  fingerprint metadata and verified-import instructions.

### Changed

- Email aliases for `quantumssh.org` are live: `security@quantumssh.org`
  and `conduct@quantumssh.org` accept and forward correctly. The
  apex and `www.quantumssh.org` redirect (HTTP 301) to the GitHub
  repository, preserving the request path. The "DNS not yet provisioned"
  caveat in `SECURITY.md` has been removed.
- New `docs/operations.md`: a verification guide that lets external
  observers check the project's DNSSEC chain, TLS posture, CAA whitelist,
  PGP fingerprint, signed-commit history, and `main` branch protection
  end-to-end without any special access. Includes a Mermaid diagram of
  the DNS trust chain.
- New `docs/infrastructure.md`: a public overview of the project's
  supporting infrastructure (DNS, TLS, email, signing, repository
  hardening, CI scaffolding), with rationale for each non-obvious
  configuration choice. Complements `docs/operations.md`, which
  describes how to verify these configurations externally. Includes a
  service-topology Mermaid diagram. `README.md` and `docs/operations.md`
  cross-link to it.
- Architecture Decision Record (ADR) system introduced under
  `docs/adr/` with `README.md` describing process, a MADR-style
  template, and ADRs 0001-0011 backfilling the Phase 0 decisions
  (DNS host, registrar, HSTS preload deferral, DMARC `p=none`, PGP
  two-year expiry, SSH-not-GPG commit signing, CAA whitelist scope,
  branch protection with zero approving reviews, virtual workspace
  in Phase 0, toolchain pinning, CI guards via Python `tomllib`).
  `docs/infrastructure.md` now cites these ADRs rather than inlining
  rationale, and `GOVERNANCE.md` documents the RFC-vs-ADR boundary.

### Fixed

- `docs/adr/0011-ci-guards-python-tomllib.md` and the corresponding
  "CI guard implementation note" in `docs/infrastructure.md`
  incorrectly described all three CI workflows as using a single
  shared `tomllib`/`workspace.members` predicate. In reality
  `audit.yml` is gated on `Cargo.lock` presence (matching what
  `cargo-audit` actually needs), while `ci.yml` and `deny.yml` are
  gated on the `tomllib` member count. Both documents now describe
  the two-predicate split accurately. ADR-0011's title and
  alternatives section are updated accordingly.
- `docs/adr/0003-hsts-preload-deferred.md` claimed in its Positive
  consequences that the header was "preload-eligible" with no
  configuration change required at submission. That was internally
  inconsistent with the same ADR's Alternative 3 section, which
  correctly notes that the current `max-age=15552000` (six months) is
  below the one-year (31536000) preload-list floor. The Positive
  consequence and Alternative 2 wording are corrected to acknowledge
  that submission will require bumping `max-age` to at least one year
  in addition to the existing directive.

### Security

- DMARC policy tightened from `p=none` to `p=reject`. Receivers now
  reject mail that fails alignment under `quantumssh.org` outright
  rather than merely reporting failures. Recorded as
  [ADR-0013](docs/adr/0013-dmarc-tightened-to-p-reject.md), which
  supersedes ADR-0004. The intermediate `p=quarantine` step
  contemplated in ADR-0004 was skipped because the project sends no
  outbound mail under this domain (no legitimate senders to validate
  against the policy). Future outbound-mail integrations under
  `@quantumssh.org` will need to be perfectly SPF/DKIM-aligned before
  they send.
- HSTS `max-age` increased from `15552000` (6 months) to `31536000`
  (1 year). Recorded as
  [ADR-0012](docs/adr/0012-hsts-max-age-bumped-to-one-year.md), which
  partially supersedes ADR-0003 (the `max-age` portion only; the
  preload-list submission deferral established in ADR-0003 remains in
  effect). The new value meets the floor required by hstspreload.org;
  the remaining preload-list eligibility blockers (the HTTP→HTTPS
  same-host first-hop redirect) and the submission decision itself
  are tracked in GitHub issue #10.

[Unreleased]: https://github.com/gonzafg2/quantumssh/compare/HEAD...HEAD
