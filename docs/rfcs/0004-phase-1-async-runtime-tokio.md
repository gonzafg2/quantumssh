# RFC 0004: Adopt Tokio as the Phase 1 async runtime

- **Status:** Accepted (2026-07-17)
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-06-11
- **Roadmap issue:** [`#9`](https://github.com/gonzafg2/quantumssh/issues/9) (Phase 1 / Hito 1)
- **Implementation PR:** TBD

## Summary

QuantumSSH adopts **Tokio** as the async runtime for the Phase 1 server. This RFC decides the *adoption* — the entry of a large networking dependency into the trust base. The operative detail (version pin, feature allowlist, threading model, accept-loop shape) is a subsidiary decision recorded in ADR-0022 (in review), which cites this RFC.

## Motivation

[RFC-0003](0003-phase-1-ssh-stack-greenfield-vs-russh.md) fixed the cryptographic primitive crates in detail but is silent on the async runtime. The RFC process ([README](README.md)) routes to the RFC lane *"a new dependency that materially expands the trust base (anything in the crypto, **networking**, or process-spawning paths)"*. The runtime is the networking path: every byte of the pre-authentication surface — the highest-trust surface in the threat model (§4.1) — flows through it. Adopting it through an ADR alone would have been the project's first silent exception to its own process; this RFC closes that gap before the first crate lands.

## Guide-level explanation

Tokio provides the TCP listener/stream types, the async I/O traits the binary-packet framing is written against, timers for handshake budgets (threat model §5.1.3), and the task primitives the server composes. It will be the substrate the `server` module (TBD — no code has landed yet) is built on; it is **not** part of the protocol or cryptographic logic, which remain runtime-agnostic in their core types.

What this RFC does **not** decide: the version pin, which Tokio features are linked, single- vs multi-threaded scheduler, and the Phase 1 accept-loop shape. Those are operative choices with their own trade-offs, recorded in ADR-0022 so they can be revisited (superseded) without re-opening the adoption itself.

## Reference-level explanation

**Trust-base impact.** Tokio brings itself plus a small transitive set (notably `mio` for the OS event queue). These crates contain internal `unsafe` — permitted by [ADR-0018](../adr/0018-phase-1-unsafe-code-forbid-workspace.md), which forbids first-party `unsafe` while accepting it in audited dependencies — and sit under the pre-auth path. This RFC carries the companion qualification of `docs/threat-model.md` (§3.2.4, §5.1.2, §6.2): those passages said "no `unsafe` in the pre-authentication path" without the first-party qualifier, a literal guarantee any dependency with internal `unsafe` on that path — the RFC-0003 primitives included — would already read as violating. They now state the first-party rule, name ADR-0018 as the enforced (and auditable) mechanism, and route dependency-internal `unsafe` through the RFC lane explicitly. Mitigations, all already in place or decided:

- `cargo deny` (licences, advisories, sources) and `cargo audit` run in CI on every PR (ADR-0011 guards self-enable with the first crate).
- The feature allowlist (ADR-0022, in review) will link only the modules the server uses — no `full` grab-bag — keeping the audited surface enumerable.
- The version is pinned to a published LTS line with a documented end-of-support date; bumps are deliberate, reviewed events — a superseding ADR to ADR-0022, since a new pin is a decision change, which [ADR-0015](../adr/0015-permit-annotated-errata-in-adrs.md) routes to supersession rather than errata — not silent lockfile drift.
- Tokio's security posture is mature: RUSTSEC advisories exist and have been handled with timely point releases and backports to LTS lines, which is the behaviour the pin relies on.

**Boundary.** The library crate exposes async functions; only the binary constructs a runtime. No protocol type embeds runtime handles, preserving the option (Phase 4, client library) of embedding the core under a caller-provided runtime.

## Drawbacks

- Tokio is large relative to the rest of the dependency tree, and most of its internal `unsafe` sits in exactly the path we care most about. The feature allowlist bounds but does not eliminate this.
- A runtime is soft lock-in: the async ecosystem's traits are not runtime-portable in practice, so a future migration would be a real refactor. Accepted: no credible migration target exists (see alternatives).

## Rationale and alternatives

- **`async-std`** — effectively in maintenance mode; adopting a fading runtime for new security infrastructure is indefensible.
- **`smol`** — minimal and sound, but cedes the ecosystem: fewer eyes, fewer integrations, no LTS policy comparable to Tokio's published per-line end-of-support dates.
- **`glommio`** — thread-per-core io_uring design, Linux-only; over-specialised for a portable walking skeleton.
- **Synchronous `std::net` + threads** — the honest non-async alternative for a sequential Phase 1. Rejected because Phase 2's concurrent connections, per-handshake timeouts, and graceful-shutdown signalling are all natural in async and awkward as hand-rolled thread/select machinery; migrating a synchronous transport to async mid-project is precisely the class of invasive refactor RFC-0003 chose to avoid for the stack.
- **Defer to the implementation PR** — rejected for the same reason RFC-0003 refused "decide later": the first `Cargo.toml` settles the substrate; deciding it deliberately with the reasoning recorded is cheaper than reconstructing it from a diff.

Tokio is the de-facto standard runtime for networked Rust; `russh` (the reference implementation we read but do not depend on) runs on it, and the broader server ecosystem assumes it. There is no genuine contender for this workload.

## Prior art

- `russh` (Tokio-based) — the closest comparable SSH stack in Rust.
- `rustls` — runtime-agnostic core with async adapters; QuantumSSH mirrors the spirit by keeping protocol types runtime-free and confining Tokio to the I/O boundary.

## Unresolved questions

None. Version, features, and threading are deliberately delegated to ADR-0022.

## Future possibilities

- Phase 2+ may enable additional Tokio features (`process` for PTY streaming, `signal` for graceful shutdown) — each a small, reviewable `Cargo.toml` change under ADR-0022's allowlist discipline.
- If a formally-verified or substantially smaller runtime ever becomes viable for the pre-auth path, a superseding RFC owns that migration.
