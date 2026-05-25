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
- `docs/rfcs/0002-threat-model-phase1-uid-model-and-non-goal.md`
  (Draft) proposes two coupled threat-model refinements: (a) a
  Phase-bounded paragraph appended to §2.5 (Command execution
  authority) clarifying that the *"authority on the host as the
  authenticated user"* goal is the Phase 3 target, and (b) a new
  §8.12 (Out of scope) entry naming *"Per-user UID isolation until
  Phase 3"* as a temporary, closure-conditioned non-goal. The closure
  condition is the Phase 3 privilege-separation RFC, named inline so
  the non-goal is auditable as temporary rather than permanent. The
  RFC also proposes adding `executing_uid` as a first-class field of
  the §2.7 audit record so the Phase-1 UID gap is operationally
  checkable in logs by the operator.

### Changed

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
  a policy _request_; enforcement varies (major mailbox providers
  honour `p=reject`, some legacy mailservers ignore DMARC entirely).
  The wording is qualified to "DMARC-compliant receivers" /
  "receivers are instructed to reject" in all three locations.
- The `Records reference` table in `docs/infrastructure.md` was
  out of date with the rest of the document: it listed the DMARC TXT
  record as `p=none` while the "Authentication posture" section
  below it already described the `p=reject` policy. The table row is
  updated to `p=reject`.
- `README.md` §"The problem" and `MANIFIESTO.es.md` §"El punto de
  partida" each said that GitHub *"rolled out post-quantum SSH access
  in September 2025"* / *"habilitó SSH post-cuántico en septiembre de
  2025"*. The sentence is preceded by the claim that OpenSSH 10.0
  made ML-KEM the default, and in that order the wording invites the
  reader to infer that GitHub adopted ML-KEM. GitHub in fact enabled
  `sntrup761x25519-sha512@openssh.com` (not `mlkem768x25519-sha256`)
  on 17 September 2025, automatically selected for clients that
  support it. Both sentences are amended to name the algorithm
  explicitly. Source: GitHub Engineering blog,
  *Post-quantum security for SSH access on GitHub*, 17 Sep 2025.
- `docs/threat-model.md` §5.2.4 ("Key-derivation flaw") **Test
  handle** referenced *"Test vectors from the IETF hybrid PQ KEX
  draft"*. The current draft (`draft-ietf-sshm-mlkem-hybrid-kex`,
  version -10, 26 Feb 2026) does not in fact publish hybrid-combiner
  test vectors; its appendices are A (Other Combiners) and B (FIPS)
  only. The Test handle is rewritten to a layered substitute that
  exists today: NIST ACVP-Server vectors for the ML-KEM-768 half,
  RFC 7748 §6.1 vectors for the X25519 half, and internally-captured
  golden vectors for the hybrid combiner output and SSH exchange
  hash, generated against an OpenSSH 10.x peer with a fixed-RNG test
  profile analogous to OpenSSH's `TEST_SSH_FIXED_KEX_SEED`. The
  closure condition (an IETF appendix of canonical vectors) is named
  inline so the test handle reverts to the original wording if the
  draft adopts one. Treated as a factual correction under the
  threat-model maintenance clause; an RFC was not required because
  the change is to a Test handle subsection, not to an asset, an
  actor tier, a trust boundary, an in-scope attack vector, or a
  non-goal.

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
