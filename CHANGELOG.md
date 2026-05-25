# Changelog

All notable changes to QuantumSSH will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `docs/rfcs/README.md` and `docs/adr/README.md` codify the project's
  one-decision-per-file convention. Each RFC addresses a single
  shape-determining decision; the implementing subsidiary decisions
  (workspace topology, dependency version pins, configuration
  parameters) are split into separate ADRs that cite the RFC, never
  packaged inside the RFC itself. ADRs in turn record a single
  decision each. The reasoning is reviewability: a reader of an RFC
  must be able to identify the decision in one sentence and the
  alternatives as a list, and a substantive objection to one half of
  a packaged RFC otherwise blocks the other half from landing.
- `docs/rfcs/README.md` also documents the project's tracking
  convention: RFCs reference the Phase-level GitHub issue (e.g. `#9`
  for Phase 1) in their `Roadmap issue:` field rather than create a
  per-RFC tracking issue. The roadmap in `README.md` plus the
  Phase-level issues are the single tracking surface; discussion of a
  specific RFC happens on its pull request. RFC-0001's per-RFC
  tracking issue (`#20`) predates this convention and remains as a
  historical record; it is not retroactively replaced.
- `docs/rfcs/0000-template.md` renames its `Tracking issue:` field to
  `Roadmap issue:` with default guidance to cite the Phase-level
  issue.
- Initial project scaffolding, governance documents, contribution
  guidelines, license, and CI/CD configuration.
- Project security PGP key published at `keys/security.asc`
  (Ed25519 + Curve25519, fingerprint
  `66DB5100B0700E4AE051971F9A8DFF06AFD25B24`, expires 2028-05-09).
  The `<TBD>` placeholder in `SECURITY.md` is replaced with the
  fingerprint metadata and verified-import instructions.

### Changed

- `README.md` §"Roadmap" no longer carries per-Phase calendar
  estimates. The previous wording — *"We expect Phase 1 to take weeks.
  Phase 2, months. Phase 3, a year or more."* — was an implicit
  schedule commitment that invited scope/quality compromises whenever
  a phase's actual work outgrew the estimate. The replacement reads:
  *"Each phase ships when it is ready, not on a calendar. We do not
  estimate Phase durations: the schedule is a function of
  correctness, scrutiny, and community formation, and committing to a
  timeline would invert the priority. We are not in a hurry.
  Cryptographic infrastructure earns trust slowly."* The high-level
  ambitions in `MANIFIESTO.es.md` §"Cómo medimos el éxito" (year-one /
  year-two / year-five outcomes) are deliberately kept; they are
  ambitions, not scope estimates, and removing them would weaken the
  project's stated direction.
- `README.md` Phase 1 roadmap entry now cites the GitHub issue
  tracking it (`#9`), matching the discoverability pattern already
  applied to Phase 0 by the previous CHANGELOG entry.
- `docs/infrastructure.md` "Calendar of time-bound actions" no longer
  lists the 2026-07-10 HSTS preload submit-or-skip decision as a
  pending entry. That decision was resolved ahead of schedule on
  2026-05-11 by ADR-0014 (submission completed). A short note below
  the calendar records the resolution and points at the ADR for
  context, so a future reader auditing the project's calendar drift
  finds the explanation in the same section.
- `README.md` Phase 0 roadmap entry updated to reflect actual status:
  `Manifesto, README, governance model` marked complete; threat model
  document and the `russh` decision marked in-progress with pointers
  to the tracking issues; and a short paragraph added recognising the
  supporting infrastructure (DNS/DNSSEC, HSTS preload, project PGP,
  branch protection, CI scaffolding) and the 16-ADR catalog as Phase 0
  deliverables alongside the originally listed three. Phase 0 header
  changed from `(in progress)` to `(mostly complete)`. Phase 1+ entries
  unchanged.
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
  in Phase 0, toolchain pinning, CI workflow gating via two narrow
  workspace-state predicates — `tomllib`/`workspace.members` for
  `ci.yml` and `deny.yml`, `Cargo.lock` presence for `audit.yml`).
  `docs/infrastructure.md` now cites these ADRs rather than inlining
  rationale, and `GOVERNANCE.md` documents the RFC-vs-ADR boundary.

### Fixed

- `docs/adr/0011-ci-guards-workspace-state.md` and the corresponding
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
- ADR process formalised an errata mechanism for accepted ADRs.
  Previously the README stated that accepted ADRs were immutable
  except for the Status field, but in practice PR #13 made in-place
  factual corrections to ADR-0003 and ADR-0011. That tension is
  resolved by [ADR-0015](docs/adr/0015-permit-annotated-errata-in-adrs.md),
  which permits in-place edits **only** for factual errata, with an
  explicit `Post-acceptance errata` banner near the top of the
  affected ADR documenting the date, the PR or CHANGELOG entry, and
  what was corrected. Decision changes still require a new ADR that
  supersedes the old one. ADR-0003, ADR-0011, and ADR-0013 are
  retroactively annotated with their errata banners under the new
  rule.
- ADR-0011 file renamed from `0011-ci-guards-python-tomllib.md` to
  `0011-ci-guards-workspace-state.md` so the filename slug reflects
  the ADR's corrected scope (two narrow workspace-state predicates,
  not a single `tomllib` predicate). All inbound links in
  `docs/infrastructure.md`, ADR-0009, and earlier CHANGELOG entries
  are updated in the same commit.
- ADR-0011's description of when `Cargo.lock` appears at the repo
  root is refined: the original wording implied a build event in
  some environment, but the actual workflow predicate checks for the
  file in the repository checkout. The corrected wording makes the
  commit step explicit.
- DMARC-related claims in `docs/infrastructure.md`, `CHANGELOG.md`,
  and `docs/adr/0013-dmarc-tightened-to-p-reject.md` had stated
  absolutely that "Receivers reject mail" under `p=reject`. DMARC is
  a policy *request*; enforcement varies (major mailbox providers
  honour `p=reject`, some legacy mailservers ignore DMARC entirely).
  The wording is qualified to "DMARC-compliant receivers" /
  "receivers are instructed to reject" in all three locations.
- The `Records reference` table in `docs/infrastructure.md` was
  out of date with the rest of the document: it listed the DMARC TXT
  record as `p=none` while the "Authentication posture" section
  below it already described the `p=reject` policy. The table row is
  updated to `p=reject`.

### Security

- DMARC policy tightened from `p=none` to `p=reject`. DMARC-compliant
  receivers are instructed to reject mail that fails alignment under
  `quantumssh.org` outright rather than merely reporting failures
  (`p=reject` is a policy request and enforcement varies across the
  receiver ecosystem). Recorded as
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
  partially supersedes ADR-0003.
- HSTS preload-list submission completed. The Cloudflare Redirect Rule
  was scoped to HTTPS-only traffic (via an added `ssl` clause in its
  filter), enabling "Always Use HTTPS" to perform the HTTP→HTTPS
  same-host upgrade before the rule fires; this satisfies the last
  outstanding `hstspreload.org` eligibility requirement (first-hop
  redirect must be to a secure page on the same host). The domain
  `quantumssh.org` was then submitted at `hstspreload.org` and is now
  in the `pending` queue for inclusion in the next Chromium release;
  other browsers follow on their own cadence. Recorded as
  [ADR-0014](docs/adr/0014-hsts-preload-submitted.md), which together
  with ADR-0012 fully supersedes ADR-0003. Removal from the preload
  list is by design slow (6-12 weeks per Chrome, longer elsewhere);
  the project accepts this in exchange for protecting first-time
  HTTP visitors from active downgrade attacks on initial request.

[Unreleased]: https://github.com/gonzafg2/quantumssh/compare/HEAD...HEAD
