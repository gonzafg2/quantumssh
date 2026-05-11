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

[Unreleased]: https://github.com/gonzafg2/quantumssh/compare/HEAD...HEAD
