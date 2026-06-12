# ADR 0022: Use multi-threaded Tokio with a minimal feature set for the Phase 1 runtime

- **Status:** Proposed
- **Date:** TBD (advances to Accepted when the first Phase 1 crate lands)
- **Deciders:** Project lead
- **Related:** Subsidiary to [RFC-0004](../rfcs/0004-phase-1-async-runtime-tokio.md), which decides the *adoption* of Tokio (trust-base impact, alternatives); this ADR fixes the operative detail — version, features, threading. Constrained by [ADR-0010](0010-toolchain-pinning-resolver-3-edition-2024-msrv-1-92.md) (MSRV 1.92) and [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md) (`unsafe_code = "forbid"`); the `server.rs` accept loop in [ADR-0017](0017-phase-1-workspace-topology-two-crates-flat.md)'s `quantumssh-core` is built on it. Will touch (TBD — `crates/` does not exist yet) `crates/quantumssh/Cargo.toml` and `crates/quantumssh-core/Cargo.toml`.

## Context

[RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) specifies the nine cryptographic primitive crates in detail but says nothing about the async runtime; the adoption of Tokio — a dependency that materially expands the trust base on the networking path — is decided by [RFC-0004](../rfcs/0004-phase-1-async-runtime-tokio.md), per the RFC lane rule. This ADR records the subsidiary operative choices. The current root `Cargo.toml` carries `tokio` only as a commented placeholder (`# tokio = { version = "1", features = ["full"] }`). Before `server.rs` can be written, the runtime, its feature set, and its threading model must be fixed: the accept loop's shape, whether per-connection state must be `Send`, and which `tokio` modules are linked all follow from this choice.

Two questions are entangled and must be separated:

1. **Which threading model, and how is the `Send` discipline enforced?** The `Send` bound on a future is imposed by `tokio::spawn` — its signature requires `F: Future + Send + 'static` on *both* the multi-thread and `current_thread` schedulers. What relaxes it is the `current_thread`-only escape hatch (`LocalSet`/`spawn_local`), and what silently skips it is not spawning at all (a plain inline `.await` loop checks nothing).
2. **What concurrency does Phase 1 actually need?** The walking skeleton serves one connection through to close before accepting the next; it does not need parallelism.

The trap is to answer (2) first ("Phase 1 is sequential, so use a single-threaded runtime and a plain inline loop") and let it silently decide (1). Under that shape, nothing in the compiler checks `Send`: if any type in the type-state transport machine (`Expect<KexInit>`, `Expect<NewKeys>`, …) captures a non-`Send` value — an `Rc`, a `RefCell`, a non-`Sync` handle — it compiles fine, and `current_thread`'s `spawn_local` invites exactly that pattern. The omission only surfaces when Phase 2 introduces real per-connection concurrency via `tokio::spawn`, at which point the fix is an invasive refactor of code written months earlier — paid precisely when the project is trying to add features, not foundations.

## Decision

We will use the **multi-threaded Tokio runtime from the first commit**, with a **sequential accept loop** in Phase 1: each connection is spawned and immediately joined (`tokio::spawn(handle(sock, peer)).await`), so one connection is handled to completion before the next is accepted, while the `spawn` keeps the `Send` bound on the per-connection future enforced by the compiler from line one.

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

- **`rt-multi-thread`, not `current_thread`.** The `Send` bound itself comes from `tokio::spawn` (identical on both schedulers); the threading model is chosen because it closes the escape hatch — there is no `spawn_local`/`LocalSet` path through which non-`Send` state can creep into the transport machine — and because it is the scheduler Phase 2's concurrent connections run on, so the code is born on its final substrate. The proposed design has nothing non-`Send`: an `Expect<Stage>` holds only the current connection's buffers, and the host key is shared read-only as `Arc<HostKey>` (`Send + Sync`). The bound is therefore free to satisfy now and expensive to retrofit later.
- **Sequential accept loop in Phase 1, spawn-and-join shape.** `loop { let (sock, peer) = listener.accept().await?; let _ = tokio::spawn(handle(sock, peer)).await; }`. The immediate `.await` on the `JoinHandle` keeps effective concurrency at one, while the `spawn` (a) makes the compiler enforce `Send` on the per-connection future from the first crate and (b) isolates a per-connection panic from the accept loop (a `JoinError` is logged as `connection.closed` with reason, instead of taking the server down). Moving to concurrent connections in Phase 2 is *removing* the immediate join (track the handle instead), not a refactor.
- **Features that are deliberately excluded, with rationale:**
  - **`fs`** — host key and `authorized_keys` are read once at startup with `std::fs`. One-time blocking I/O outside the hot path does not justify the async filesystem layer.
  - **`process`** — Phase 1 command execution uses `std::process::Command` on a `tokio::task::spawn_blocking` thread, not `tokio::process`. This keeps the child-process lifecycle simple for the walking skeleton; `tokio::process` (and the `process` feature) is reconsidered when PTY support lands in Phase 2.
  - **`signal`** — graceful shutdown on SIGTERM/SIGINT is a Phase 2 operational concern; Phase 1's `sync::broadcast` shutdown path is driven by tests, not OS signals.
- **Version pin: `1.51` (the active LTS).** Tokio 1.51.x is an LTS line with security backports through March 2027 — well into Phase 2. The latest stable at the time of writing is 1.52.3; the LTS line is preferred over chasing latest for a foundational dependency. A bump to a newer LTS is recorded as errata on this ADR ([ADR-0015](0015-permit-annotated-errata-in-adrs.md) mechanism), not a silent `Cargo.lock` drift. `1.51` is compatible with the MSRV 1.92 pinned in ADR-0010.
- **Crate placement.** `quantumssh-core` depends on `tokio` with the I/O and task features it needs to define async fns (`net`, `io-util`, `time`, `sync`, and `rt` — `tokio::task::spawn_blocking` and `tokio::spawn` are gated behind the `rt` feature); the `quantumssh` binary additionally enables `macros` and `rt-multi-thread` and is the only crate that constructs the runtime (`#[tokio::main]`). The library never starts a runtime — it exposes async fns the binary drives. The exact per-crate feature split is an implementation detail of the first PR, constrained by this list.

## Consequences

### Positive

- Non-`Send` state in the transport machine is a **compile error from the first crate** — enforced by the `tokio::spawn` in the accept loop, not assumed from the scheduler choice. The most expensive class of "works now, breaks when we add concurrency" bug is closed by construction.
- Phase 2's jump to concurrent connections is *removing* the immediate join on an already-`Send` future, not a refactor.
- A panicking connection handler surfaces as a logged `JoinError`, not a dead server — panic isolation per connection comes free with the spawn-and-join shape.
- `default-features = false` plus a six-feature allowlist keeps the linked surface small and auditable, consistent with MANIFIESTO #4. No `full` grab-bag pulling in `fs`, `process`, `signal`, `net`'s every corner, etc.
- Pinning to the LTS line gives a stable, security-supported base for the whole of Phase 1 and into Phase 2 without dependency churn.

### Negative

- A multi-threaded runtime for a sequential workload is nominally "more runtime than Phase 1 uses." The work-stealing scheduler is present even though only one connection runs at a time. The cost is negligible (a thread pool sized to cores, mostly idle) and is the deliberate price of the `Send` discipline.
- `spawn_blocking` for command execution means Phase 1 carries a blocking-thread pool for child processes. This is simpler than `tokio::process` but is a different model than Phase 2 will likely want for PTY streaming, so some of the Phase 1 exec path is provisional. Flagged so it is not mistaken for the final design.
- Choosing a specific LTS pin now means a maintainer must consciously bump it later; the errata trail is the mitigation.
- Under the sequential loop, the handshake timeout (`time` feature, threat model §5.1.3) bounds how long any one connection can hold the server, but it does not stop an adversary from serialising slow handshakes back-to-back and monopolising the listener. That is accepted for Phase 1: availability under adversarial load is explicitly out of scope (threat model §8.3, §2.8), and Phase 2's concurrent accept closes the window. The timeout is still required — without it a single half-open connection would hold the server indefinitely.

### Neutral

- Tokio itself is not re-litigated here: the adoption — including the trust-base analysis and the runtime alternatives (`async-std`, `smol`, `glommio`, synchronous `std::net`) — is decided by [RFC-0004](../rfcs/0004-phase-1-async-runtime-tokio.md). This ADR records the subsidiary feature/threading decision only.
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

- Implementation: TBD — when the first crate lands, this decision will be implemented by `crates/quantumssh/Cargo.toml`, `crates/quantumssh-core/Cargo.toml`, the accept loop in `quantumssh-core`'s `server` module, and `#[tokio::main]` in the binary. None of these paths exist yet.
- Related ADRs: [ADR-0010](0010-toolchain-pinning-resolver-3-edition-2024-msrv-1-92.md) (MSRV 1.92 compatibility), [ADR-0017](0017-phase-1-workspace-topology-two-crates-flat.md) (which crate constructs the runtime), [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md) (`unsafe_code = "forbid"` — Tokio's own `unsafe` is in the dependency, not first-party).
- Background: [`docs/threat-model.md`](../threat-model.md) §5.1.3 (handshake budget — the `time` feature), §2.8 (service availability — the sequential-loop posture and its explicit non-DoS stance).
- Tokio LTS policy: the project designates LTS minor releases with published per-line end-of-support dates and backported fixes for at least a year per line; the README's current table lists `1.51.x` as "LTS release until March 2027". Verify the current LTS table in the Tokio README before bumping the pin.
