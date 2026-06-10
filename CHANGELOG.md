# Changelog

All notable changes to QuantumSSH will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `docs/rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md` (added as
  Draft; promoted to Accepted in the same Unreleased cycle — see
  **Changed** below)
  proposes that Phase 1's SSH-2 transport, KEX, authentication, and
  channel layers be implemented greenfield on top of audited
  cryptographic primitive crates (`ml-kem`, `x25519-dalek`,
  `ed25519-dalek`, `chacha20poly1305`, `aes-gcm`, `sha2`, `hmac`),
  rather than depending on the `russh` crate. The choice is
  scored against the five MANIFIESTO commitments and against
  threat-model §3.2.6 (RFC-0001 maintainer-compromise actor). The
  `russh`-with-maximum-mitigations path is named as Option B (a
  documented fallback if a future constraint forces the trade), and a
  narrow hybrid (Option C — use `ssh-key` for `authorized_keys`
  parsing only, greenfield everything else) is named as a documented
  extension. The RFC supersedes the *"tentatively `russh`"* wording
  in `README.md` §Roadmap if accepted; the README amendment is a
  follow-up PR, not bundled here.
- `docs/adr/0016-phase-1-service-account-uid-model.md` (Proposed)
  records the operational counterpart to RFC-0002: `quantumsshd` will
  run in Phase 1 as a dedicated non-root service account
  (`quantumssh:quantumssh`), never holding `root`, never calling
  `setuid`/`setgid`/`initgroups`/`chroot`, and never integrating with
  PAM. Commands inherit the service account's UID/GID and a sanitised
  environment. The `executing_uid` audit field (RFC-0002 §2.7) is
  populated by `nix::unistd::Uid::current()`; in Phase 1 the value is
  a per-process constant, and the schema is forward-compatible with
  the Phase 3 per-user value. The ADR depends on the merge of
  RFC-0002 and advances from Proposed to Accepted when Phase 1
  implementation begins.
- `docs/rfcs/README.md` and `docs/adr/README.md` codify the project's
  one-decision-per-file convention. Each RFC addresses a single
  shape-determining decision; the implementing subsidiary decisions
  (workspace topology, dependency version pins, configuration
  parameters) are split into separate ADRs that cite the RFC, never
  packaged inside the RFC itself. ADRs in turn record a single
  decision each. The reasoning is reviewability: a reader of an RFC
  must be able to identify the decision in one sentence and the
  alternatives as a list, and a substantive objection to one half of
  a packaged RFC would otherwise block the other half from landing.
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
- `docs/rfcs/0002-threat-model-phase1-uid-model-and-non-goal.md`
  (Draft) proposes two coupled threat-model refinements: (a) a
  Phase-bounded paragraph appended to §2.5 (Command execution
  authority) clarifying that the *"authority on the host as the
  authenticated user"* goal is the Phase 3 target, and (b) a new
  §8.12 (Out of scope) entry naming *"Per-user UID isolation until
  Phase 3"* as a temporary, closure-conditioned non-goal. The closure
  condition is a follow-up Phase 3 RFC (TBD), so the non-goal is
  auditable as temporary rather than permanent. The RFC also proposes
  adding `executing_uid` as a first-class field of the §2.7 audit
  record so the Phase-1 UID gap is operationally checkable in logs by
  the operator.

### Changed

- `docs/rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md` advances
  from Draft to **Accepted** (2026-06-10, lazy consensus — the 14-day
  comment period closed with no substantive maintainer objection). The
  decision is now binding: Phase 1's SSH-2 transport, KEX,
  authentication, and channel layers are implemented greenfield on
  audited primitive crates; `russh` is **not** a dependency and becomes
  a reference implementation only. The RFC's four unresolved questions
  are resolved at acceptance: (1) the upstream `russh` fuzz-harness
  contribution is deferred until Phase 1 gains a second contributor;
  (2) `unsafe_code = "forbid"` is enforced workspace-wide from the
  first crate's first line; (3) the hybrid Option C is *not* promoted
  to co-equal, staying a named narrow extension; (4) CI pins a specific
  OpenSSH version for the interop gate and treats version bumps as
  their own reviewed PR. The four follow-up ADRs the RFC named
  (workspace topology, `unsafe_code = forbid`, `RustCrypto/ml-kem`
  selection, CI interop gate) are now unblocked.
- Issue [`#9`](https://github.com/gonzafg2/quantumssh/issues/9) (Phase 1
  / Hito 1) reconciled with RFC-0003: the `russh` dependency framing is
  removed, the crate layout moves to `crates/quantumssh` (binary) +
  `crates/quantumssh-core` (library), and the acceptance criteria are
  preserved unchanged per RFC-0003 §"Acceptance criteria stay as issue
  #9 defines them".
- `docs/rfcs/0001-threat-model-actor-project-maintainer-compromise.md`
  advances from Draft to **Accepted** (2026-06-10, lazy consensus —
  the 14-day comment period closed with no substantive maintainer
  objection). The five unresolved questions are resolved at
  acceptance: (1) the §5.5.2 refinement uses the a/b sub-heading
  layout as proposed; (2) §3.2 stays qualitative with no likelihood
  ratings; (3) the hardware-backed signing key is deferred to its own
  future ADR; (4) reproducible builds are committed to as a Phase 3
  direction only, with the exact form deferred to a dedicated RFC; (5)
  the §6.4 "Signed releases and" phrase will be dropped in the
  Implementation PR, with the signed-release mechanism itself deferred.
  Acceptance records the decision; the `docs/threat-model.md` edits
  will land in the (still TBD) Implementation PR.
- `docs/rfcs/0002-threat-model-phase1-uid-model-and-non-goal.md`
  advances from Draft to **Accepted** (2026-06-10, lazy consensus —
  the 14-day comment period closed with no substantive maintainer
  objection). The four unresolved questions are resolved at
  acceptance: (1) §8.12 stays Phase-anchored with no calendar date,
  the closure condition (Phase 3 privsep RFC + landing) being the
  anchor; (2) Phase 1 documents the single-user assumption rather than
  enforcing it with launch-time refusal heuristics; (3) the audit
  field is named `executing_uid`, matching the merged ADR-0016; (4)
  the `executing_uid` addition rides with this RFC and is not split
  into its own RFC. Acceptance records the decision; the
  `docs/threat-model.md` edits will land in the Implementation PR. This
  unblocks ADR-0016 (operational counterpart) to advance from
  Proposed to Accepted when Phase 1 implementation begins.
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
