# ADR 0022: Use multi-threaded Tokio with a minimal feature set for the Phase 1 runtime

- **Status:** Proposed
- **Date:** TBD (advances to Accepted when the first Phase 1 crate lands)
- **Deciders:** Project lead
- **Related:** Implements the runtime substrate RFC-0003's greenfield server needs; constrained by [ADR-0010](0010-toolchain-pinning-resolver-3-edition-2024-msrv-1-92.md) (MSRV 1.92) and [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md) (`unsafe_code = "forbid"`); the `server.rs` accept loop in [ADR-0017](0017-phase-1-workspace-topology-two-crates-flat.md)'s `quantumssh-core` is built on it. Touches `crates/quantumssh/Cargo.toml` and `crates/quantumssh-core/Cargo.toml`.

## Context

[RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) specifies the nine cryptographic primitive crates in detail but says nothing about the async runtime, because the runtime is not a cryptographic decision. The current root `Cargo.toml` carries `tokio` only as a commented placeholder (`# tokio = { version = "1", features = ["full"] }`). Before `server.rs` can be written, the runtime, its feature set, and its threading model must be fixed: the accept loop's shape, whether per-connection state must be `Send`, and which `tokio` modules are linked all follow from this choice.

Two questions are entangled and must be separated:

1. **Which runtime, and single- or multi-threaded?** This determines the `Send`/`Sync` bounds the compiler imposes on every type that crosses an `.await`.
2. **What concurrency does Phase 1 actually need?** The walking skeleton serves one connection through to close before accepting the next; it does not need parallelism.

The trap is to answer (2) first ("Phase 1 is sequential, so use a single-threaded runtime") and let it silently decide (1). A `current_thread` runtime relaxes the `Send` bound on futures. If any type in the type-state transport machine (`Expect<KexInit>`, `Expect<NewKeys>`, …) then captures a non-`Send` value — an `Rc`, a `RefCell`, a non-`Sync` handle — it compiles fine under `current_thread` and only fails when Phase 2 introduces real per-connection concurrency, at which point the fix is an invasive refactor of code written months earlier. The cost of that refactor is paid precisely when the project is trying to add features, not foundations.

## Decision

We will use the **multi-threaded Tokio runtime from the first commit**, with a **sequential accept loop** in Phase 1 (one connection handled to completion before the next is accepted; `tokio::spawn` is deliberately not used yet).

The dependency, pinned to the active LTS line, with `default-features = false` and an explicit minimal feature set:

```toml
tokio = { version = "1.51", default-features = false, features = [
    "net",             # TcpListener / TcpStream — the accept loop and the wire
    "io-util",         # AsyncReadExt / AsyncWriteExt — binary-packet framing
    "rt-multi-thread", # the runtime (pulls in "rt")
    "macros",          # #[tokio::main] in the binary, #[tokio::test] in tests
    "time",            # tokio::time::timeout — handshake budget (threat model §5.1.3)
    "sync",            # broadcast — graceful-shutdown signal
] }
```

Binding details:

- **`rt-multi-thread`, not `current_thread`.** The threading model is chosen for its compile-time effect — it forces futures and the state they hold to be `Send` from line one — not because Phase 1 needs parallelism. The proposed design has nothing non-`Send`: an `Expect<Stage>` holds only the current connection's buffers, and the host key is shared read-only as `Arc<HostKey>` (`Send + Sync`). The bound is therefore free to satisfy now and expensive to retrofit later.
- **Sequential accept loop in Phase 1.** `loop { let (sock, peer) = listener.accept().await?; handle(sock, peer).await; }` — no `spawn`. Moving to concurrent connections in Phase 2 is adding `tokio::spawn(handle(...))` (the body is already `Send`), not a refactor.
- **Features that are deliberately excluded, with rationale:**
  - **`fs`** — host key and `authorized_keys` are read once at startup with `std::fs`. One-time blocking I/O outside the hot path does not justify the async filesystem layer.
  - **`process`** — Phase 1 command execution uses `std::process::Command` on a `tokio::task::spawn_blocking` thread, not `tokio::process`. This keeps the child-process lifecycle simple for the walking skeleton; `tokio::process` (and the `process` feature) is reconsidered when PTY support lands in Phase 2.
  - **`signal`** — graceful shutdown on SIGTERM/SIGINT is a Phase 2 operational concern; Phase 1's `sync::broadcast` shutdown path is driven by tests, not OS signals.
- **Version pin: `1.51` (the active LTS).** Tokio 1.51.x is an LTS line with security backports through March 2027 — well into Phase 2. The latest stable at the time of writing is 1.52.3; the LTS line is preferred over chasing latest for a foundational dependency. A bump to a newer LTS is recorded as errata on this ADR ([ADR-0015](0015-permit-annotated-errata-in-adrs.md) mechanism), not a silent `Cargo.lock` drift. `1.51` is compatible with the MSRV 1.92 pinned in ADR-0010.
- **Crate placement.** `quantumssh-core` depends on `tokio` with the I/O and runtime-trait features it needs to define async fns (`net`, `io-util`, `time`, `sync`); the `quantumssh` binary additionally enables `macros` and `rt-multi-thread` and is the only crate that constructs the runtime (`#[tokio::main]`). The library never starts a runtime — it exposes async fns the binary drives. The exact per-crate feature split is an implementation detail of the first PR, constrained by this list.

## Consequences

### Positive

- Non-`Send` state in the transport machine is a **compile error from the first crate**, not a latent Phase 2 hazard. The most expensive class of "works now, breaks when we add concurrency" bug is closed by construction.
- Phase 2's jump to concurrent connections is a one-line `spawn`, because the per-connection future is already `Send`.
- `default-features = false` plus a six-feature allowlist keeps the linked surface small and auditable, consistent with MANIFIESTO #4. No `full` grab-bag pulling in `fs`, `process`, `signal`, `net`'s every corner, etc.
- Pinning to the LTS line gives a stable, security-supported base for the whole of Phase 1 and into Phase 2 without dependency churn.

### Negative

- A multi-threaded runtime for a sequential workload is nominally "more runtime than Phase 1 uses." The work-stealing scheduler is present even though only one connection runs at a time. The cost is negligible (a thread pool sized to cores, mostly idle) and is the deliberate price of the `Send` discipline.
- `spawn_blocking` for command execution means Phase 1 carries a blocking-thread pool for child processes. This is simpler than `tokio::process` but is a different model than Phase 2 will likely want for PTY streaming, so some of the Phase 1 exec path is provisional. Flagged so it is not mistaken for the final design.
- Choosing a specific LTS pin now means a maintainer must consciously bump it later; the errata trail is the mitigation.

### Neutral

- Tokio itself is not re-litigated as *the* runtime. It is the de facto standard async runtime for networked Rust (RFC-0003's prior-art crates — `rustls` consumers, the broader ecosystem — assume it), and no alternative (`async-std`, `smol`, `glommio`) offers a reason to diverge for an SSH server. This ADR records the feature/threading decision, not a runtime bake-off, because there is no genuine contender.
- The feature set will grow across phases (PTY, signals, possibly `tokio::process`). Each addition is a small, reviewable `Cargo.toml` change, not a re-decision of this ADR.

## Alternatives considered

### Alternative 1: `current_thread` (single-threaded) runtime

The most literal match for a sequential Phase 1 workload: no thread pool, no `Send` bound on futures, slightly less machinery. Rejected because relaxing the `Send` bound is a liability, not a saving — it lets non-`Send` state into the transport machine undetected, converting a free compile-time check into a Phase 2 refactor. The runtime saving is immaterial for a server; the lost invariant is not.

### Alternative 2: `tokio` with `features = ["full"]`

The placeholder in the current `Cargo.toml` and the path of least resistance. Rejected: `full` links `fs`, `process`, `signal`, `net`, `io-*`, `time`, `sync`, `rt-multi-thread`, and more, most unused in Phase 1. It contradicts "small attack surface" and obscures which runtime capabilities the code actually depends on. An explicit allowlist makes every linked feature a decision.

### Alternative 3: A non-Tokio runtime (`async-std`, `smol`, `glommio`)

Considered for completeness. `glommio`'s thread-per-core model is interesting for a high-throughput server but is Linux-io_uring-only and over-specialised for a walking skeleton; `async-std` is effectively in maintenance; `smol` is minimal but cedes the ecosystem advantage. None offers an SSH-relevant benefit over Tokio that would justify diverging from the runtime the rest of the Rust networking ecosystem (and RFC-0003's reference implementations) assumes. No bake-off was warranted.

### Alternative 4: Defer the runtime decision to the first implementation PR

Let the implementer pick when writing `server.rs`. Rejected for the same reason RFC-0003 refused "decide later" on the stack: the first `Cargo.toml` settles the threading model irrevocably for the phase, and the `Send` consequence ripples through every transport type. Deciding it deliberately now, with the reasoning recorded, is cheaper than reconstructing it from a `Cargo.toml` diff later.

## Links

- Code that implements this decision: `crates/quantumssh/Cargo.toml`, `crates/quantumssh-core/Cargo.toml`, `crates/quantumssh-core/src/server.rs` (accept loop), `crates/quantumssh/src/main.rs` (`#[tokio::main]`).
- Related ADRs: [ADR-0010](0010-toolchain-pinning-resolver-3-edition-2024-msrv-1-92.md) (MSRV 1.92 compatibility), [ADR-0017](0017-phase-1-workspace-topology-two-crates-flat.md) (which crate constructs the runtime), [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md) (`unsafe_code = "forbid"` — Tokio's own `unsafe` is in the dependency, not first-party).
- Background: [`docs/threat-model.md`](../threat-model.md) §5.1.3 (handshake budget — the `time` feature), §2.8 (service availability — the sequential-loop posture and its explicit non-DoS stance).
- Tokio LTS policy: the project publishes LTS lines with multi-year security backport windows; the 1.51.x line is supported through March 2027. Verify the current LTS table at <https://tokio.rs> before bumping the pin.
