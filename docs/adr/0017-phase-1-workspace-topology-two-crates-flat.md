# ADR 0017: Lay out the Phase 1 workspace as two flat crates

- **Status:** Proposed
- **Date:** TBD (advances to Accepted when the first Phase 1 crate lands)
- **Deciders:** Project lead
- **Related:** Implements [RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) §"Operational dependencies of this decision"; sources the project's internal Phase-1 decision notes §"Decisión 2"; interacts with [ADR-0011](0011-ci-guards-workspace-state.md) (CI guards self-disable on first crate) and [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md) (`unsafe_code = "forbid"`).

## Context

[RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) commits Phase 1 to a greenfield SSH stack. The first implementation PR must add the first crate(s) to the currently empty workspace, and the physical shape it picks is durable: every later module, test target, and dependency edge is laid down relative to it, and re-shaping a workspace mid-Phase-1 is churn the project would rather not pay.

Three shapes were on the table: a single `quantumssh` crate holding everything; a conservative two-to-three crate split; or a granular four-to-five crate split (`-core`, `-transport`, `-auth`, `-channel`, …) mirroring how `russh` and the new `OranPie/RuSSH` lay themselves out. This ADR records which shape the first commit settles on, and why early fragmentation is the wrong default. It does not re-open the greenfield decision — that lives in RFC-0003.

## Decision

We will lay out the Phase 1 workspace as **two crates in a flat `crates/` layout**:

```
QuantumSSH/
├── Cargo.toml                 # virtual manifest (already present)
├── Cargo.lock                 # appears with the first binary
└── crates/
    ├── quantumssh/            # binary — thin entrypoint (argparse + tracing init + start core)
    └── quantumssh-core/       # library — wire, kex, transport, auth, channel, host_key, server
```

- The virtual manifest declares `members = ["crates/quantumssh", "crates/quantumssh-core"]` with `resolver = "3"`.
- Each member inherits `edition`, `license`, `rust-version` via `<field>.workspace = true`, and lints via `[lints] workspace = true`.
- `quantumssh-core` is marked `publish = false` until its API stabilises (Phase 3+).

The split is **two, not one and not four-plus**. The binary stays a wiring/CLI shell (≤50 LoC); all server logic lives in the library so it can be exercised by integration tests without launching the binary.

## Consequences

### Positive

- Integration tests target `quantumssh-core` directly, without spawning the binary.
- Single-responsibility boundary: the binary is entrypoint/CLI; the library is the server. The boundary is enforced by the crate edge, not by convention.
- `Cargo.lock` appears at the first binary commit, satisfying the `audit.yml` predicate from [ADR-0011](0011-ci-guards-workspace-state.md) with no extra work, and self-disabling the workspace-empty CI guards on the same commit.
- Lint inheritance is uniform: every crate carries `[lints] workspace = true`, so [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md)'s `unsafe_code = "forbid"` applies everywhere by construction.

### Negative

- One extra `Cargo.toml` versus a mono-crate. This is the entire marginal cost over Option A, and it is accepted in exchange for testability and the entrypoint/logic split.
- If Phase 5+ adds a client, a further refactor (`core-shared` + `server-core` + `client-core`) becomes likely. Mitigation: that refactor costs the same now as later, and *later* the project will know what the client actually needs — so deferring is strictly more informed (YAGNI).

### Neutral

- The audit boundary is unchanged by the crate count. What an external audit scopes is reachable LoC, not number of crates; physical fragmentation neither helps nor hurts it.

## Alternatives considered

### Alternative 1: Single crate (mono-crate)

Defensible if KISS is weighted above everything. Rejected as the default because integration tests would have to drive the binary, and the entrypoint/logic separation would be a module convention rather than a compiler-enforced edge. The difference from the chosen option is exactly one `Cargo.toml`.

### Alternative 2: Four-to-five granular crates (`-core`, `-transport`, `-auth`, `-channel`, …)

Rejected as premature. The matklad large-workspaces guidance (≪500 LoC + a single dependent → not its own crate) and live ecosystem evidence point the other way: `russh` is reverting its own `russh-keys` split back into `russh` ([discussion #315](https://github.com/Eugeny/russh/discussions/315)); `rustls` only fragmented (`rustls-pki-types`) *after* 1.0 once duplication across real consumers justified it; and `rustls-pemfile` went unmaintained (RUSTSEC-2025-0134) after being reabsorbed. Splitting before there are real modularity requirements is paid back at refactor time for no Phase 1 benefit.

### Alternative 3: Three crates (`-core` + `-server` + binary)

A middle option. Rejected because Phase 1 has exactly one product (the server) and one entrypoint; a separate `-server` layer between `-core` and the binary has no second consumer to justify it. Collapses cleanly into the two-crate shape.

## Links

- Decision source: [RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) §"Operational dependencies of this decision"; analysis in the project's internal Phase-1 decision notes §"Decisión 2".
- Evidence: [`matklad`, *Large Rust Workspaces*](https://matklad.github.io/2021/08/22/large-rust-workspaces.html); [`russh` discussion #315](https://github.com/Eugeny/russh/discussions/315).
- Interacts with: [ADR-0011](0011-ci-guards-workspace-state.md) (CI workspace-state guards), [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md) (`unsafe_code = "forbid"`).
- Roadmap: Phase 1 / Hito 1 — [`#9`](https://github.com/gonzafg2/quantumssh/issues/9).
- Implementation: TBD (first Phase 1 crate — no code has landed yet).
