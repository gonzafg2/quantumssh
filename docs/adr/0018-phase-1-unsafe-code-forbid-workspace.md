# ADR 0018: Promote `unsafe_code` from `deny` to `forbid` workspace-wide

- **Status:** Proposed
- **Date:** TBD (advances to Accepted when the first Phase 1 crate lands)
- **Deciders:** Project lead
- **Related:** Implements [RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) §"Operational dependencies of this decision" and resolves its unresolved question 2; depends on [ADR-0017](0017-phase-1-workspace-topology-two-crates-flat.md) (workspace shape); touches `Cargo.toml` `[workspace.lints.rust]`.

## Context

The workspace today sets `unsafe_code = "deny"` in `[workspace.lints.rust]` (`Cargo.toml`). `deny` makes `unsafe` a hard error *but* permits a per-item escape hatch: an `#[allow(unsafe_code)]` on a function or block silently re-enables it. `forbid` is the stronger sibling — it refuses the `#[allow]` override entirely, so no future commit can quietly reintroduce `unsafe` anywhere in first-party code.

[RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) chose a greenfield stack whose dependencies are pure-Rust primitive crates that confine their own `unsafe` internally (the audited fiat-crypto backend, `RustCrypto/ml-kem`). Because no chosen dependency requires QuantumSSH first-party code to write or `#[allow]` `unsafe`, the escape hatch that `deny` leaves open buys nothing — and MANIFIESTO #1 ("memory-safe by construction") is most literally honoured by the variant that removes it. RFC-0003's unresolved question 2 asked whether to make this promotion immediately or defer it; it was resolved at acceptance in favour of *immediately*.

## Decision

We will set `unsafe_code = "forbid"` in `[workspace.lints.rust]`, replacing the current `"deny"`, so that first-party QuantumSSH code is free of `unsafe` **with no per-item override available**.

- The `Cargo.toml` change lands in the **same PR as the first Phase 1 crate**, so the first crate compiles under `forbid` from its first line. (The lint has no observable effect on today's empty workspace; flipping it only becomes load-bearing once first-party code exists, which is why this ADR advances to Accepted at that point.)
- `forbid` applies workspace-wide via `[lints] workspace = true` inheritance in every member crate ([ADR-0017](0017-phase-1-workspace-topology-two-crates-flat.md)).
- The constraint binds **first-party code only**. Dependencies keep their own `unsafe`; that is the audited primitive layer RFC-0003 deliberately relies on, and the lint does not (and cannot) reach into them.

## Consequences

### Positive

- MANIFIESTO #1 is enforced in its strongest form: no first-party `unsafe`, and no mechanism to add it without changing `Cargo.toml` itself (a conspicuous, reviewable edit).
- The "memory-safe by construction" claim becomes mechanically checkable in CI from the first crate, not a convention reviewers must police by eye.
- Closes the category where a future contributor adds `#[allow(unsafe_code)]` "just here, just for now" and it never leaves.

### Negative

- If a genuine need for first-party `unsafe` ever arises (e.g. a syscall wrapper not covered by `nix`/`rustix`), `forbid` cannot be locally overridden — lifting it requires editing `Cargo.toml` and, given the MANIFIESTO weight, a superseding ADR. Mitigation: this is the intended friction, not an accident; the bar to introduce first-party `unsafe` *should* be a documented decision.
- Marginally higher discipline cost during exploration, since a quick `unsafe` spike cannot be left in even temporarily. Mitigation: accepted explicitly in RFC-0003's resolution of question 2.

### Neutral

- No effect on the dependency tree or build output today; the workspace is empty. The change is forward-looking by design.

## Alternatives considered

### Alternative 1: Keep `unsafe_code = "deny"`

The status quo. Rejected: `deny` leaves the `#[allow(unsafe_code)]` escape hatch open, which is exactly the silent-reintroduction path MANIFIESTO #1 wants closed. With no dependency forcing first-party `unsafe`, keeping the weaker lint has cost (the open hatch) and no benefit.

### Alternative 2: Defer the promotion to a later PR (land the first crate under `deny`, tighten later)

RFC-0003's question 2 named this option. Rejected: tightening a lint *after* code exists risks discovering an `#[allow]` already in place and having to unwind it. Starting at `forbid` makes the first line the cleanest it will ever be, and there is no exploration value in `unsafe` that the project wants to preserve.

### Alternative 3: `forbid` only on `quantumssh-core`, `deny` on the binary

Rejected as needless asymmetry. The binary is a ≤50-LoC entrypoint ([ADR-0017](0017-phase-1-workspace-topology-two-crates-flat.md)); there is no reason it would need `unsafe` that the library would not, and a split lint policy is harder to reason about than a uniform workspace-wide one.

## Links

- Decision source: [RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) §"Operational dependencies of this decision" and its resolved unresolved-question 2.
- Configuration this decision changes: `Cargo.toml` `[workspace.lints.rust]` (`unsafe_code`), landing with the first Phase 1 crate.
- Related ADRs: [ADR-0017](0017-phase-1-workspace-topology-two-crates-flat.md) (lint inheritance across the two crates).
- Roadmap: Phase 1 / Hito 1 — [`#9`](https://github.com/gonzafg2/quantumssh/issues/9).
- Implementation: TBD (no code has landed yet; the lint flip is part of the first-crate PR).
