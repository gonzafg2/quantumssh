# CLAUDE.md — guidance for Claude Code and automated reviewers

This file is read by Claude Code (and the `claude-code-action` CI reviewer)
when working in this repository. It encodes how QuantumSSH wants changes
reviewed and made. It is **project guidance**, public and Apache-2.0 like
the rest of the repo, and is also useful onboarding for human contributors.

Authoritative documents this file points at rather than duplicates:
[`README.md`](README.md) (vision), [`MANIFIESTO.es.md`](MANIFIESTO.es.md)
(why, in Spanish), [`docs/threat-model.md`](docs/threat-model.md)
(defensive posture), [`docs/adr/`](docs/adr/) and [`docs/rfcs/`](docs/rfcs/)
(decisions and process).

## What this is

QuantumSSH is a memory-safe, post-quantum-first SSH server written in Rust.
It is built greenfield on audited cryptographic primitive crates — it does
**not** depend on `russh` ([RFC-0003](docs/rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md)).

**Status: pre-alpha.** Phase 0 (foundation: manifesto, governance, threat
model, ADR/RFC catalog, supporting infrastructure) is complete. Phase 1
(the walking-skeleton server, [issue #9](https://github.com/gonzafg2/quantumssh/issues/9))
has **landed**: milestones M1–M6 are merged. The `quantumssh-core` library
and the `quantumssh` binary implement the full greenfield path end to end —
version exchange → `mlkem768x25519-sha256` hybrid KEX → AEAD transport →
publickey Ed25519 authentication → one `session` channel running one
`exec` → clean close, with mid-session re-keying (1 GiB / 1 h, [ADR-0026](docs/adr/0026-phase-1-rekeying-policy.md))
— and interoperate with a stock OpenSSH 10.x client
(the `interop` CI gate, [ADR-0020](docs/adr/0020-phase-1-ci-openssh-interop-gate.md)).
It is **not** hardened for production: no PTY, no SFTP, no config file, no
per-user privilege separation (Phase 2+).

The Phase-1 ADRs (0016–0024, 0026) are **Accepted** — flipped from `Proposed`
in the [#86](https://github.com/gonzafg2/quantumssh/issues/86) governance sweep
once their implementing milestones merged.

## The five commitments, as review criteria

Every change is measured against the five MANIFIESTO commitments. Stated as
hard review rules:

1. **Memory-safe by construction.** *Reject* any first-party `unsafe`. The
   workspace is `unsafe_code = "forbid"` ([ADR-0018](docs/adr/0018-phase-1-unsafe-code-forbid-workspace.md));
   there is no `#[allow]` escape. Dependencies may contain `unsafe`; that is
   the audited primitive layer.
2. **Post-quantum by default, not by opt-in.** *Reject* any non-hybrid or
   classical-only key exchange in the default profile. `mlkem768x25519-sha256`
   is the only KEX offered ([ADR-0021](docs/adr/0021-phase-1-negotiation-profile.md)).
   Failure of either hybrid half must abort, never silently fall back.
3. **Zero legacy.** *Reject* SSH-1, RSA, DSA, ECDSA-NIST, CBC modes,
   `diffie-hellman-group1/14-sha1`, `ssh-rsa`, password authentication, and
   compression. None of these may be compiled in, not merely configured off.
   That list is the permanent floor, not the whole definition: anything NIST
   or IETF **disallows** is also legacy
   ([RFC-0009](docs/rfcs/0009-zero-legacy-moving-frontier.md)). A
   deprecated-but-not-yet-disallowed primitive is **not** legacy — deprecation
   only starts a managed migration ([RFC-0007](docs/rfcs/0007-cryptographic-primitive-migration-procedure.md));
   do not reject a PR that keeps such a primitive in use during its migration
   window (e.g. `ssh-ed25519` under [RFC-0006](docs/rfcs/0006-post-quantum-host-key-signatures.md)).
4. **Small surface, sharp edges.** *Reject* features beyond the current
   phase's scope unless they are opt-in behind an explicit flag. *Reject* any
   new dependency that is not justified in the PR and does not pass
   `cargo deny`.
5. **Permanently open.** *Reject* anything that narrows the Apache-2.0
   posture (source-available terms, relicensing, an enterprise fork).

## Hard security rules

The threat model ([`docs/threat-model.md`](docs/threat-model.md)) is the
authoritative reference; the operative rules a reviewer applies:

- **The pre-authentication path is the highest-trust surface** (§4.1). No
  `unsafe`, no allocation sized by an attacker-controlled length without an
  explicit bound, and it must be fuzzable. Parser changes get extra scrutiny.
- **Fail closed.** A peer that does not offer the hybrid PQ KEX, or does not
  negotiate strict-kex, is rejected (`SSH_DISCONNECT_KEY_EXCHANGE_FAILED`).
  No downgrade path may exist.
- **Strict-kex is required** (Terrapin / CVE-2023-48795 defence), AEAD-only
  ciphers, no exercised MAC path in the default profile — the MAC name-list
  is nominal and never used under AEAD ([ADR-0021](docs/adr/0021-phase-1-negotiation-profile.md)).
- **Public-key authentication only.** The server **reads** `authorized_keys`;
  it never writes it.
- **Key material is zeroized after use, never logged, never in error or panic
  output** (§4.3).
- **The transport is a type-state machine** ([RFC-0003](docs/rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md)):
  an `Expect<Stage>` exposes only the messages valid in that stage. Do not
  loosen this to "accept and branch" — that is the Terrapin bug class.
- **Audit log fields are mandated** ([ADR-0024](docs/adr/0024-phase-1-log-event-schema.md)):
  `authenticated_identity` and `executing_uid` are separate first-class
  fields on every `exec.*` event; `command` is a structured field, never
  interpolated into a message string.

## RFC vs ADR vs plain PR

- **RFC** ([`docs/rfcs/`](docs/rfcs/)) — a shape-determining decision: a
  protocol extension, a change to default cryptographic algorithms, a new
  public API, a dependency that materially expands the trust base, or anything
  that contradicts or refines a `README.md` / `MANIFIESTO.es.md` commitment.
- **ADR** ([`docs/adr/`](docs/adr/)) — records a decision taken, often
  implementing an accepted RFC, or a smaller locked-in operational choice.
  One decision per file. Accepted ADRs are immutable except Status and errata
  ([ADR-0015](docs/adr/0015-permit-annotated-errata-in-adrs.md)).
- **Plain PR or issue** — bug fixes, refactors with no behaviour change,
  docs, tests. When unsure which lane a change belongs in, open an issue and
  ask.
- **Plan** ([`docs/plans/`](docs/plans/)) — a mutable, **non-authoritative**
  design note: a milestone plan, or a scoping note for future work
  ([ADR-0027](docs/adr/0027-docs-plans-governance-category.md)). The code,
  ADRs, and RFCs are authoritative, never the plan. Every plan carries a
  dated `Governance status` banner pointing at the ADRs/RFCs (or tracking
  issue) that hold its decisions, and **a plan is never the sole record of
  a locked-in decision** (that always goes to an ADR/RFC).

## Contribution conventions

- **Conventional Commits** for messages (`feat`, `fix`, `docs`, `chore`,
  `ci`, `refactor`, …) with a scope where it helps.
- **DCO sign-off** on every commit: `git commit -s`.
- **Signed commits are required.** `main` enforces verified signatures via
  branch protection; sign with `git commit -S`. A commit that lands unsigned
  (e.g. from a GitHub App) must be re-signed before it can merge.
- **Never push to `main`.** Open a pull request from a branch.
- **Spanish and English are both first-class** in issues, PRs, and docs.
- Automated reviewers (`opencode`, `Claude Code Review`) only trigger for human-authored PRs (`OWNER`/`MEMBER`/`COLLABORATOR`). Dependabot PRs receive CI + manual review only.

## Repo map

| Path | What |
|---|---|
| [`README.md`](README.md), [`MANIFIESTO.es.md`](MANIFIESTO.es.md) | Vision (EN) and manifesto (ES) |
| [`docs/threat-model.md`](docs/threat-model.md) | Defensive posture — authoritative |
| [`docs/adr/`](docs/adr/) | Architecture Decision Records + their README |
| [`docs/rfcs/`](docs/rfcs/) | RFCs + the lightweight RFC process |
| [`docs/plans/`](docs/plans/) | Mutable, non-authoritative milestone design notes ([ADR-0027](docs/adr/0027-docs-plans-governance-category.md)) |
| [`docs/infrastructure.md`](docs/infrastructure.md), [`docs/operations.md`](docs/operations.md) | Ops topology and verification recipes |
| `deny.toml`, `clippy.toml`, `rust-toolchain.toml`, `Cargo.toml` | Tooling and workspace config |
| `crates/quantumssh-core/` | The library — modules `wire`, `kex`, `cipher`, `host_key`, `transport` (type-state machine), `auth`, `channel`, `exec`, `server` |
| `crates/quantumssh/` | The thin binary entrypoint over the library (two crates, flat — [ADR-0017](docs/adr/0017-phase-1-workspace-topology-two-crates-flat.md)) |
| `tests/interop/` | `run_openssh_client.sh` — the OpenSSH interop gate driver (ADR-0020) |
| `.github/workflows/` | CI: `ci`, `audit`, `deny`, `interop` (OpenSSH gate), and the Claude reviewers |
| [`.github/REVIEW-FORMAT.md`](.github/REVIEW-FORMAT.md) | Report contract both automated reviewers follow |

## Key commands

The toolchain is pinned in `rust-toolchain.toml` (stable channel, MSRV 1.92,
edition 2024). The validation loop, run on every PR:

```sh
cargo fmt --all                                              # format
cargo clippy --workspace --all-targets -- -D warnings        # lint, warnings = errors
cargo deny check                                             # licences, advisories, sources
cargo test --workspace                                       # unit + integration
cargo build --workspace --release                            # the connectable binary
```

The `interop` CI job additionally drives a real OpenSSH 10.x client through
connect → auth → exec → close against the release binary
([ADR-0020](docs/adr/0020-phase-1-ci-openssh-interop-gate.md)); reproduce it
locally with `tests/interop/run_openssh_client.sh`. (The CI workspace-state
guards that self-disabled during Phase 0 — [ADR-0011](docs/adr/0011-ci-guards-workspace-state.md)
— are now active, since the workspace has members.)

## What not to do

- Do not add `unsafe` anywhere in first-party code.
- Do not introduce legacy crypto, or a second KEX, into the default profile.
- Do not add a dependency without justifying it in the PR and passing
  `cargo deny`.
- Do not write mock, stub, or placeholder code — everything committed must be
  functional. No "not implemented yet" left in a merged path.
- Do not reference files or paths that do not exist yet as if they do; mark
  planned work (Phase 2+) as TBD, as the forward-looking ADRs do.
- Do not edit an accepted ADR in place except its Status field or annotated
  errata ([ADR-0015](docs/adr/0015-permit-annotated-errata-in-adrs.md)); to
  change a decision, write a superseding ADR.
- Do not loosen the type-state transport machine to accept-and-branch.
