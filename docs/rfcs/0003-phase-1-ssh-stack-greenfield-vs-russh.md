# RFC 0003: Phase 1 SSH stack — greenfield-modular vs `russh`

- **Status:** Draft
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-05-27
- **Roadmap issue:** [`#9`](https://github.com/gonzafg2/quantumssh/issues/9) (Phase 1 / Hito 1)
- **Implementation PR:** TBD

## Summary

Phase 1's walking skeleton needs a foundation: either we depend on the existing [`russh`](https://github.com/Eugeny/russh) crate for the SSH-2 wire and KEX layers, or we implement those layers ourselves on top of audited cryptographic primitive crates (`ml-kem`, `x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`, `aes-gcm`).

The [`README.md`](../../README.md) roadmap entry for Phase 0 records a *tentative* preference for `russh` and explicitly defers the formal decision to this RFC. The adversarial analysis captured in [`claudedocs/phase1-open-decisions.md`](../../claudedocs/phase1-open-decisions.md) (2026-05-13) examined three options against the MANIFIESTO commitments; this RFC proposes that we adopt the **greenfield-modular** option (A), with the **`russh`-with-mitigations** option (B) named as a documented fallback only if a future constraint forces the trade.

The decision belongs to RFC and not ADR scope because Phase 1's foundation determines what code runs in QuantumSSH's pre-authentication path — the highest-trust surface in the system — for the lifetime of the project. Reversing it later costs an order of magnitude more than choosing once.

## Motivation

The MANIFIESTO commits the project to five things: memory safety by construction, post-quantum by default, zero legacy, small attack surface with sharp edges, and permanently open. Phase 1 is where these commitments stop being aspirational and start being load-bearing.

The two candidate foundations score very differently against those commitments. The summary table below comes from [`claudedocs/phase1-open-decisions.md`](../../claudedocs/phase1-open-decisions.md) §"Decisión 1 — `russh` vs. implementación greenfield"; the full evidence with citations lives there.

| Dimension | `russh` | Greenfield | Winner |
|---|---|---|---|
| MANIFIESTO #1 (memory-safe by construction) | `unsafe` in `russh-cryptovec` reaches pre-auth buffers; workspace-wide `unsafe_code = "deny"` would need an exception | Pure-Rust primitive crates with localised `unsafe` (audited fiat-crypto backend, `RustCrypto/ml-kem`); workspace-wide `forbid` is achievable | **Greenfield** |
| MANIFIESTO #3 (zero legacy) | `Preferred::default()` exposes CBC, 3DES, DH-group1-sha1, ssh-rsa, ECDSA-NIST — *compiled and linked* even if configured off | No legacy primitive is ever compiled in | **Greenfield** |
| MANIFIESTO #4 (small attack surface) | ~25 kLoC + transitive deps, >50% rejected by MANIFIESTO #3 | <5 kLoC of protocol code on top of vetted primitive crates | **Greenfield** |
| Value: "we do not invent crypto" | Avoids re-implementing primitives and framing | Re-uses primitives; implements *protocol*, not primitives — same posture rustls took | **Tie** |
| Value: "correctness over cleverness" | `russh` has shipped Terrapin-class bugs that required retroactive fixes | Type-state machine (`Expect<Stage>`, rustls-style) makes the Terrapin category impossible by construction | **Greenfield, mildly** |
| Promise: "Phase 1 takes weeks" | 4–8 weeks plausible | 6+ months for one full-time experienced developer | **`russh`** |
| Threat-model §3.2.6 (RFC-0001 maintainer compromise) | `russh` bus factor is ~4 substantive committers; introduces a `russh`-maintainer-compromise actor outside QuantumSSH's threat model | The threat actor remains the QuantumSSH project itself | **Greenfield** |
| `cargo audit` clean from day 1 | Blocked: `russh` 0.57+ → `rsa 0.10.0-rc.12` → RUSTSEC-2023-0071 (Marvin), *no fixed upgrade available* | Achievable | **Greenfield** |

The "Phase 1 takes weeks" row was the only one where `russh` clearly won. **That commitment no longer exists.** [PR #25](https://github.com/gonzafg2/quantumssh/pull/25), merged on 2026-05-27, removed per-phase calendar estimates from the README in favour of *"each phase ships when it is ready, not on a calendar."* The wording change is direct: the project explicitly traded schedule promises for the room to do the work right. The argument for `russh` that survived was the one that no longer applies.

That clears the path to recommend the option the MANIFIESTO actually points at.

## Guide-level explanation

This RFC proposes that Phase 1 be built as a **greenfield-modular** SSH server on top of audited cryptographic primitive crates. The proposed stack:

```toml
# crates/quantumssh-core/Cargo.toml — primitive layer
ml-kem            = { version = "0.3.0", default-features = false, features = ["zeroize"] }
x25519-dalek      = { version = "2.0.1", default-features = false, features = ["static_secrets", "zeroize"] }
ed25519-dalek     = { version = "2",     default-features = false, features = ["std", "rand_core", "zeroize"] }
chacha20poly1305  = { version = "0.10",  default-features = false, features = ["alloc"] }
aes-gcm           = { version = "0.10",  default-features = false, features = ["aes"] }
sha2              = { version = "0.10",  default-features = false }
hmac              = { version = "0.12",  default-features = false }
subtle            = { version = "2",     default-features = false }
zeroize           = { version = "1",     default-features = false, features = ["zeroize_derive"] }
```

All five crates are pure-Rust (no FFI, no C), all are Apache-2.0 or MIT, all expose `feature = "zeroize"` for the key-material hygiene that `docs/threat-model.md` §2.4 and §5.2.4 require. The selection of `RustCrypto/ml-kem` over alternatives (`libcrux-ml-kem`, `aws-lc-rs`, `liboqs-rust`, `pqcrypto-mlkem`, `fips203`) is documented in [`claudedocs/phase1-open-decisions.md`](../../claudedocs/phase1-open-decisions.md) §"Decisión 3" and will move to its own ADR when this RFC merges.

The Phase 1 protocol code lives in `quantumssh-core` as modules:

```
crates/quantumssh-core/src/
├── lib.rs
├── wire.rs        # RFC 4253 §6 — Binary Packet Protocol, sshtype encoding
├── kex.rs         # mlkem768x25519-sha256 — only algorithm offered
├── transport.rs   # Type-state machine: Expect<KexInit>, Expect<NewKeys>, …
├── auth.rs        # RFC 4252 publickey, Ed25519 only
├── channel.rs     # RFC 4254 subset — one session, exec only (see ADR-TBD)
├── host_key.rs    # Ed25519 host key load + verify
└── server.rs      # accept loop + composition
```

The Phase 1 server is "what we wish russh were, if russh had the MANIFIESTO as its specification": a thin, audited surface that does exactly what Phase 1 promises and nothing else.

### What changes for project users

Operationally, nothing for end users — Phase 1 has no users yet. For project contributors, the consequences are:

- The pre-auth code path is QuantumSSH's own code, reviewable in this repository in one read-through. There is no "upstream" to coordinate with on cryptographic policy.
- The CI lint `unsafe_code` can move from `"deny"` to `"forbid"` at the workspace level (no `#[allow]` escapes), aligning with MANIFIESTO #1 in the strongest form. That promotion is a follow-up ADR, not in scope for this RFC.
- `cargo audit` stays green from the first crate commit. The `russh → rsa-rc12 → RUSTSEC-2023-0071` path does not exist in the dependency tree.
- The Phase 1 implementation effort is larger. Concretely: roughly 6–9 months of focused work by an experienced systems-Rust developer to reach the walking-skeleton acceptance criteria from issue [`#9`](https://github.com/gonzafg2/quantumssh/issues/9), versus 4–8 weeks for the `russh`-based path. This is the cost the project chose to take on when [PR #25](https://github.com/gonzafg2/quantumssh/pull/25) removed calendar estimates from the roadmap.

### What does *not* change

- `russh` remains the obvious **reference implementation** to read while implementing Phase 1. It is the most actively maintained Rust SSH server library, and its protocol code (independent of its dependency posture) is a valid teaching artefact. The [Acknowledgements section of the README](../../README.md#acknowledgements) already credits the `russh` project for this role; the credit stays whether we depend on the crate or not.
- The choice of *cryptographic primitives* — ML-KEM-768 + X25519 hybrid KEX, Ed25519 host keys, ChaCha20-Poly1305 / AES-256-GCM transport, HMAC-SHA2-512-ETM — is identical to what `russh` 0.59+ would have given us. `russh` migrated to `RustCrypto/ml-kem` in [PR #660](https://github.com/Eugeny/russh/pull/660) on 2026-03-26. Both paths converge on the same primitive crate; we are choosing whether to consume `russh`'s protocol layer on top.
- The MANIFIESTO commitment "*no inventamos cripto*" is preserved. The greenfield path implements *protocol* (RFC 4251-4254, the hybrid KEX draft, RFC 8709), not *primitives*. This is the same posture [rustls](https://github.com/rustls/rustls) took: reuse audited cryptographic crates, write the protocol carefully.

## Reference-level explanation

### What greenfield is not

Greenfield here does **not** mean "implement ChaCha20-Poly1305 in Rust." It means "implement the SSH-2 transport, KEX, authentication, and channel layers in Rust, on top of audited primitive crates." The boundary is precise:

- **In scope for QuantumSSH code:** SSH binary packet protocol, KEXINIT negotiation, hybrid KEX message flow, transport-layer encryption/MAC framing, key derivation per RFC 4253 §7, host-key signing and verification, public-key authentication per RFC 4252, the RFC 4254 channel layer subset documented in ADR-TBD ("scope of single-command execution"), and structured logging via `tracing`.
- **Out of scope for QuantumSSH code:** any cryptographic primitive. ML-KEM, X25519, Ed25519, ChaCha20-Poly1305, AES-GCM, SHA-2, HMAC, and constant-time comparison all come from existing crates with public audits or, in `RustCrypto/ml-kem`'s case, NIST ACVP conformance tests.

### Why type-state for the transport state machine

The Terrapin attack (CVE-2023-48795) was a transport-layer state machine bug: the implementation accepted `SSH_MSG_IGNORE` and other unauthenticated messages during the KEX phase in a way the protocol did not anticipate. Both OpenSSH and `russh` patched it retroactively. The structural defence is to make the state machine refuse those messages by construction: a `Expect<NewKeys>` state has no method that accepts a `SshMsgIgnore`, so the bug category cannot be introduced by a future commit.

This is the pattern [`rustls`](https://github.com/rustls/rustls) uses for the TLS handshake. The pattern is not free — it costs some code-shape rigidity — but it is the principal reason `rustls` has not shipped a Heartbleed-class bug since 2015. Phase 1 adopts it.

### Why this is achievable in Rust by a small team

Concrete prior art: [`rustls`](https://github.com/rustls/rustls) was created post-Heartbleed (April 2014) and shipped a TLS 1.2 MVP in roughly 17 months of part-time work. TLS 1.2 is a larger protocol surface than SSH-2 Phase 1. The numerical sanity check: Phase 1 from issue [`#9`](https://github.com/gonzafg2/quantumssh/issues/9) is wire (~1.0 person-month) + KEX with strict-kex from day zero (~1.5) + Ed25519 host key (~0.25) + pubkey-auth (~0.75) + channel exec subset (~1.0) + fuzz/hardening (~2.0) ≈ **6.75 person-months for one experienced developer**. The number is honest; the timeline scales with how many person-hours the project actually receives. The README's new wording — *"the schedule is a function of correctness, scrutiny, and community formation"* — is what makes this scope-honest.

### Acceptance criteria stay as issue #9 defines them

This RFC does not redefine "Phase 1 done". The acceptance criteria in issue [`#9`](https://github.com/gonzafg2/quantumssh/issues/9) remain authoritative:

- A `cargo build --release` produces a binary that listens on a port.
- A standard SSH client speaking hybrid PQ connects, authenticates with a public key, executes a single command, and disconnects cleanly.
- The crate has unit tests for non-trivial logic and an integration test exercising connect/auth/exec/close against a known fixture.
- CI runs the full check matrix.

What this RFC adds is a hard interop gate (recommendation, formalised in a follow-up ADR): **a real OpenSSH 10.x client must complete connect/auth/exec/close against `quantumssh`** in CI, end-to-end, on every PR. This is the property `russh`-based tests cannot give: a `quantumssh ↔ quantumssh` test only proves the implementation talks to itself.

### Test vectors and KAT plan

This RFC commits to the test-vector sourcing strategy already documented for the threat model in [PR #23](https://github.com/gonzafg2/quantumssh/pull/23):

- **ML-KEM-768:** NIST ACVP-Server JSON (`gen-val/json-files/ML-KEM-keyGen-FIPS203` and `ML-KEM-encapDecap-FIPS203`).
- **X25519:** RFC 7748 §6.1 hardcoded.
- **Hybrid KEX (`K_PQ || K_CL` concatenation, exchange hash `H`):** internally-captured golden vectors against OpenSSH 10.x with a fixed-RNG test profile, closed when the IETF draft (`draft-ietf-sshm-mlkem-hybrid-kex`) adopts a canonical-vectors appendix.

The vectors layout is part of the Phase 1 implementation PR, not this RFC.

### Operational dependencies of this decision

If this RFC is accepted, four follow-up ADRs become unblocked. Their numbering will be reassigned at merge time (ADRs are numbered chronologically by merge order per [`docs/adr/README.md`](../adr/README.md)):

- **Workspace topology.** Two crates, flat layout (`crates/quantumssh` binary + `crates/quantumssh-core` library), per [`claudedocs/phase1-open-decisions.md`](../../claudedocs/phase1-open-decisions.md) §"Decisión 2".
- **`unsafe_code = "forbid"` workspace-wide.** Promote from the current `"deny"` (which permits per-item `#[allow]`) to `"forbid"` (which does not). Now possible because no dependency requires the escape hatch.
- **`RustCrypto/ml-kem` 0.3.0** as the ML-KEM-768 implementation, with `libcrux-ml-kem` named as fallback under specific triggers (formal verification requirement, OpenSSH byte-parity requirement) per [`claudedocs/phase1-open-decisions.md`](../../claudedocs/phase1-open-decisions.md) §"Decisión 3".
- **CI interop gate** (Debian trixie container, OpenSSH 10.0p1) per [`claudedocs/phase1-open-decisions.md`](../../claudedocs/phase1-open-decisions.md) §"Decisión 5".

These ADRs are deliberately *not* bundled into this RFC, per the one-decision-per-file convention codified in [PR #25](https://github.com/gonzafg2/quantumssh/pull/25). They each merit a focused decision record cited back to this RFC.

## Drawbacks

1. **Larger implementation effort.** Phase 1 takes roughly 6–9 person-months of focused work versus 4–8 weeks on `russh`. Mitigation: the project explicitly removed the "Phase 1 takes weeks" commitment in PR #25, in anticipation of exactly this trade.

2. **No upstream maintainer base.** Bugs found in QuantumSSH's transport code are QuantumSSH's responsibility to fix; we cannot defer to a `russh` release for a Terrapin-class issue. Mitigation: the trade is symmetric — bugs *introduced* by upstream maintainers (RFC-0001 §3.2.6 threat actor) also do not affect QuantumSSH directly. The threat surface moves from "QuantumSSH + russh" to "QuantumSSH" alone.

3. **Risk of subtly diverging from real-world SSH clients.** Implementing the protocol against the RFC text is not the same as implementing it against what OpenSSH actually does in production. Mitigation: the hard interop gate (every PR exercises a real OpenSSH 10.x client) is the structural defence. Without that gate this risk would be unacceptable; with it the divergences surface immediately.

4. **Greater chance of state-machine bugs introduced by future contributors.** Type-state helps but does not eliminate the risk. A reviewer who does not understand the `Expect<Stage>` pattern could approve a PR that loosens it. Mitigation: a short contributor-facing doc (one or two pages) at `docs/contributing/transport-state-machine.md` lands alongside the first implementation PR; the doc is referenced from every PR template touching `transport.rs`.

5. **Bus factor of the implementation.** The project lead is currently the only contributor; a single greenfield implementation by one author is a bus-factor risk. Mitigation: the explicit goal of [`docs/governance.md`](../../GOVERNANCE.md) (Phase 0→2 transition) is exactly this — recruit and onboard maintainers. This RFC's acceptance makes the recruitment story coherent ("come help build a careful Rust SSH stack from scratch") in a way the `russh`-wrapper story would not be.

## Rationale and alternatives

### Option A — Greenfield-modular (chosen)

Detailed in the body of this RFC. Wins on MANIFIESTO #1, #3, #4, on threat-model containment, and on `cargo audit` cleanliness. Loses on initial implementation cost.

### Option B — `russh` with maximum mitigations

The pragmatic fallback. Use `russh = "=0.60.2"` (pinned exact, not caret) with the following constraints baked into the integration:

1. Workspace lint exception (`#[allow(unsafe_code)]`) for the `russh-cryptovec` path, documented with a citation to threat-model §3.3 and to this RFC.
2. A hand-built `Preferred` that lists only `mlkem768x25519-sha256` + Ed25519 + ChaCha20-Poly1305/AES-256-GCM + HMAC-SHA2-512-ETM + no compression, with a test that fails if negotiation selects anything else.
3. `auth_keyboard_interactive` left at the library default (reject), never overridden.
4. `cargo audit` configured with an explicit allowlist entry for `RUSTSEC-2023-0071` with a 90-day expiry and a mandatory review at each `russh` bump.
5. An upstream PR contributing a `cargo-fuzz` harness for `russh`'s BPP parser, KEXINIT, and `USERAUTH_INFO_RESPONSE`.
6. A written commitment to migrate to Option A *before* the `0.1.0` release, recorded in the Phase 2 plan as explicit technical debt.

This option is named here so that if a later constraint forces the project's hand (a hard external deadline, loss of full-time author bandwidth, an unexpected greenfield blocker), the project can adopt B *without re-running the analysis* — the conditions and the migration commitment are pre-written.

Triggers that would re-open the choice in favour of B:
- A schedule that the project cannot move (regulatory deadline, external commitment).
- Discovery, during Phase 1 implementation, of a category of SSH state machine subtlety the team cannot afford to learn under deadline pressure.

### Option C — Hybrid (use only `russh-keys`-equivalent atomic crates)

Use `ssh-key` (the standalone OpenSSH key parsing crate, no relation to `russh-keys`) for `authorized_keys` parsing and host-key encoding, but write the BPP / KEX / transport / auth / channel layers greenfield. This narrows the surface where we accept upstream code to the parser for a well-specified, stable file format that is not in the pre-auth network path.

Rejected as the *primary* recommendation because the marginal saving is small (a few hundred lines of careful parsing) and the cost — one more dependency in the audit boundary — is not zero. Recorded here because a future implementer might land on it as the actual pragmatic compromise, and the option deserves a name. If the Phase 1 author wants to take this path, the RFC accepts it as a documented narrow extension of Option A; the workspace lint and `cargo audit` posture stay intact because `ssh-key` is `#![forbid(unsafe_code)]` and has no `rsa-rc12` dependency.

### Why not "decide later"

This was considered. Phase 1 cannot begin in earnest without this decision: the first crate's `Cargo.toml` settles it irrevocably for the duration of the phase, because re-deciding mid-Phase-1 means rewriting Phase 1. "Decide later" is "decide by default, by reaching for `russh` because the README's old wording made it the path of least resistance." The MANIFIESTO is not the path of least resistance, and this RFC exists to make the choice deliberate.

## Prior art

- **[`rustls`](https://github.com/rustls/rustls)** is the closest analogue: a greenfield TLS implementation in Rust, built on top of audited primitive crates (`ring`, then `aws-lc-rs`/`*ring*` alternatives), reaching a usable MVP in ~17 months after Heartbleed. Its handshake state-machine architecture is the source of the type-state pattern proposed for QuantumSSH's transport layer.
- **[`russh`](https://github.com/Eugeny/russh)** itself is prior art for what an SSH-2 server in Rust looks like and what the integration surface needs to cover. The greenfield path consumes its lessons (Terrapin handling, the migration to `RustCrypto/ml-kem`, the architectural shape of session-channel handling) without consuming its code.
- **[OranPie/RuSSH](https://github.com/OranPie/RuSSH)** (March 2026) is a recent greenfield SSH-2 implementation in Rust that publicly commits to "0 unsafe blocks" across a layered workspace (`russh-core`, `russh-transport`, `russh-auth`, `russh-channel`). It is too new and too single-author to depend on, but its existence is evidence that the greenfield path is being trodden by others in 2026.
- **OpenSSH** is the reference for *behaviour* in the field — the implementation any QuantumSSH client must interoperate with. The hard interop gate proposed in §"Acceptance criteria" makes the dependency on OpenSSH explicit and continuous.
- **[Project Eleven, *State of Post-Quantum Cryptography in Rust*](https://blog.projecteleven.com/), November 2025**, surveys the available ML-KEM crates and confirms that no Rust ML-KEM implementation has a public professional audit as of late 2025. This is a constraint on both options (Phase 3 will need to fund such an audit either way) and is recorded here so it is not forgotten.

## Unresolved questions

1. **Whether the `cargo-fuzz` harness contribution upstream to `russh` (Option B condition 5) should still happen even though we choose Option A.** The work would benefit the broader ecosystem and would let downstream `russh` users (warpgate, Tabby, GitButler, etc.) inherit a stronger fuzz baseline. Argument for: good citizenship in the Rust SSH community. Argument against: contributor time is the scarcest resource, and Phase 1 work has higher direct project value. Defer until Phase 1 implementation gains a second contributor.

2. **Whether to enforce `unsafe_code = "forbid"` *immediately* on workspace creation (in the same PR as the first crate), or land it in a follow-up ADR.** Forbid is the stronger commitment but requires the first crate to compile under it from line 1. The current `"deny"` permits `#[allow]` escapes that we may need during exploration. Author's lean: land `"forbid"` from day 1, accept the discipline cost. Open for review.

3. **Whether the hybrid Option C should be promoted to a co-equal "Option A+" rather than a documented narrow extension.** The argument is that `ssh-key` for `authorized_keys` parsing is a much better-tested artefact than anything we would write in Phase 1, and rewriting it would be cycles spent on solved problems. The counter-argument is the audit-boundary cost. This is the most defensible question to bike-shed during the comment period.

4. **What "interop hard gate" means precisely under CI failures.** If OpenSSH 10.0 patches a bug that changes wire format slightly (this has happened during the PQ KEX rollout), does the QuantumSSH PR block until upstream OpenSSH stabilises, or do we pin to an OpenSSH version in CI? Proposed default: pin to an OpenSSH version in CI, surface "OpenSSH version bump" as its own PR with a deliberate review. Open for review.

## Future possibilities

- **Phase 2: protocol coverage.** Interactive PTY (`pty-req` / `shell`), SFTP, and TOML configuration. All build on the Phase 1 transport unchanged. The greenfield foundation is what makes "small attack surface, sharp edges" still true at Phase 2 — every new feature requires an explicit decision to compile it in.
- **Phase 3: hardening and audit.** Continuous fuzzing (`cargo-fuzz`, OSS-Fuzz integration), conformance tests against OpenSSH client + server, professional security audit. The greenfield foundation has a smaller surface to fuzz and audit than a `russh`-based equivalent would.
- **Phase 4: client.** A QuantumSSH client built on the same `quantumssh-core` crates becomes natural; the `connect` path is the mirror image of the `accept` path the server already implements. With Option B, building a client would mean depending on `russh`'s client surface as well, doubling the consumed upstream surface.
- **Contributing back.** Even though Option A does not consume `russh`'s code, the Phase 1 implementation will run into the same protocol edge cases `russh` has run into. Sharing post-mortems, test cases, and clarifications of the IETF hybrid KEX draft with the `russh` maintainers is good citizenship and is named here so it is not forgotten.
- **A more radical alternative deferred to Phase 5+.** The Phase 1 state machine, expressed as type-state, is amenable to formal verification (Hax/F\*, Creusot, Verus). This is not a Phase 1 commitment; it is named here so a future RFC can pick it up without re-inventing the framing.
