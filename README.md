# QuantumSSH

> SSH for the next 30 years, not the past 30.
> **Open source. No NDAs. No exceptions.**

**QuantumSSH** is a memory-safe, post-quantum-first SSH server written in Rust. It is designed from scratch for a world where today's encrypted traffic is being recorded and will be decrypted by quantum computers within a generation.

We are not forking OpenSSH. We are not adding PQ algorithms as an option. We are building the SSH server we believe should exist by default in 2030 — and we are building it as **genuinely open infrastructure**, freely auditable, freely forkable, freely usable.

---

## Status

🚧 **Pre-alpha — design complete, implementation starting.**

Phase 0 (foundation) is done: manifesto, governance, a substantive threat model, 20 Architecture Decision Records, and 3 accepted RFCs that settle the Phase 1 stack (greenfield, `unsafe_code = "forbid"`, `RustCrypto/ml-kem`, OpenSSH 10.x interop gate). No Rust code has landed yet — that is Phase 1, tracked in [#9](https://github.com/gonzafg2/quantumssh/issues/9).

Supporting infrastructure (DNS, TLS, email, signing, repository hardening) is described in [`docs/infrastructure.md`](./docs/infrastructure.md); independent verification recipes live in [`docs/operations.md`](./docs/operations.md).

---

## The problem

SSH is the protocol that runs the internet's plumbing. Every server, every deployment, every CI pipeline, every embedded device with a control plane — they all speak SSH. The dominant implementation, OpenSSH, is a triumph of careful C engineering and has served us extraordinarily well.

But it carries two compounding burdens:

**1. Memory unsafety.** OpenSSH is ~120,000 lines of C. Despite world-class discipline from its maintainers, the broader ecosystem it depends on (and the shells, PAM modules, and OS primitives it integrates with) has produced a steady cadence of CVEs over the years. The 2024 `xz-utils` backdoor, which targeted OpenSSH's authentication path through a compression dependency, made clear how fragile the trust chain has become.

**2. The quantum cliff.** Today's SSH key exchange relies primarily on classical Diffie-Hellman over elliptic curves and RSA. Both are vulnerable to Shor's algorithm on a sufficiently capable quantum computer. The threat model that matters today is not "quantum computers exist tomorrow" — it is **harvest-now-decrypt-later**. Nation-state adversaries are recording encrypted SSH sessions today, betting they can decrypt them in 10–15 years. Any session that protects information with a long shelf life — source code, infrastructure secrets, regulated banking data, personal correspondence — is already at risk.

OpenSSH is responding. Version 10.0 made the ML-KEM hybrid key exchange the default. GitHub rolled out hybrid post-quantum SSH access (`sntrup761x25519-sha512@openssh.com`) on 17 September 2025; the algorithm is selected automatically for modern clients with no opt-in required. The direction is right. But the implementations are bolted onto a 25-year-old codebase in a memory-unsafe language, retaining decades of legacy algorithms, configuration surface, and edge cases — every line of which is a potential attack surface and a maintenance burden.

We think there is room for a different answer.

---

## The vision

QuantumSSH is built around four technical commitments and one structural one.

**Memory-safe by construction.** Written in Rust. No `unsafe` blocks in the protocol or crypto layers without justification, review, and tests. The borrow checker is a feature, not a tax.

**Post-quantum by default, not by opt-in.** Hybrid key exchange (ML-KEM + X25519) is the default and only supported family. Users do not need to know what PQ means or how to configure it. The right thing happens out of the box.

**Zero legacy.** No SSH-1. No RSA-1024. No DSA. No CBC modes. No `diffie-hellman-group1-sha1`. No password auth in the default profile. We refuse to inherit 25 years of "it's still there because someone's old router needs it."

**Small attack surface.** The MVP supports public-key authentication, command execution, interactive PTY shell, and SFTP. That is it. Port forwarding, X11 forwarding, agent forwarding, and other features are explicit opt-ins, gated behind feature flags and configuration.

**Open source as a permanent commitment.** This is not a marketing posture. See the next section.

---

## Open source, really

Cryptographic infrastructure earns trust through three things: time, scrutiny, and the ability for anyone to verify the claims. The third is non-negotiable, and we are explicit about it because the broader landscape is increasingly using *open* as a marketing word for things that are not.

**QuantumSSH is, and will always be, Apache 2.0.**

We commit publicly and permanently to:

- **No source-available licensing.** Source-available is not open source. We will not adopt licenses that restrict commercial use, fork rights, redistribution, or modification.
- **No NDAs to read the code.** Every line is in the public repository from the first commit. Always.
- **No "Enterprise Edition" with fundamentally different code.** If we ever offer paid services, they will be services around the open project (support, hosting, integration), not a bifurcated codebase where the real version is private.
- **No relicensing rug-pull.** Every contributor's work stays under the license they contributed under. We will not pull a future BUSL or AGPL conversion on accepted contributions. Governance will be structured to make such a move structurally hard, not just unlikely.
- **No patents enforced against the project.** Apache 2.0's patent grant flows in both directions. Any patents Fleming Science and Technologies SpA holds related to this work are licensed to all users of the project, royalty-free, irrevocably.

This commitment is in the README on purpose. If a future version of this project quietly removes this section, that itself is the signal something has changed. We invite the community to hold us to this.

---

## Non-goals

We are deliberately not trying to be:

- **A drop-in replacement for OpenSSH.** Configuration files, command-line flags, and behaviors will diverge where doing so produces a safer or simpler system.
- **Backwards-compatible with old clients.** If your client cannot speak modern, hybrid-PQ SSH, it does not connect. Period.
- **The fastest SSH server.** OpenSSH is fast enough. Our optimization target is correctness, then security, then ergonomics. Performance comes after.
- **An academic research vehicle.** We use the algorithms NIST has standardized and that the broader community is converging on. We do not invent crypto.

---

## Roadmap

### Phase 0 — Foundation (complete)
- ✅ Manifesto, README, governance model
- ✅ Threat model document — see [`docs/threat-model.md`](./docs/threat-model.md); structural changes go through the RFC process from here.
- ✅ SSH stack foundation decision — **greenfield on audited primitive crates**, not `russh`; decided and accepted in [RFC-0003](./docs/rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) (2026-06-10, [#9](https://github.com/gonzafg2/quantumssh/issues/9)).

Phase 0 also delivered the project's supporting infrastructure (DNS with DNSSEC, TLS with HSTS preload submission, inbound email forwarding, a published project PGP key, branch protection on `main` enforcing signed commits, and CI scaffolding with workspace-state guards that self-disable when Phase 1 lands) and a 20-ADR catalog documenting each operational choice with its rationale. See [`docs/infrastructure.md`](./docs/infrastructure.md) for the current state, [`docs/operations.md`](./docs/operations.md) for independent verification recipes, and [`docs/adr/`](./docs/adr/) for the decision records.

### Phase 1 — Walking skeleton
Tracked in [#9](https://github.com/gonzafg2/quantumssh/issues/9). Stack and tooling decisions (all ADRs are Proposed — they advance to Accepted when the first crate lands):

- **Stack:** greenfield SSH-2 transport, KEX, auth, and channel layers on audited primitive crates (`ml-kem`, `x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`, `aes-gcm`) — no `russh` dependency ([RFC-0003](./docs/rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md), Accepted).
- **Workspace:** `crates/quantumssh` (binary) + `crates/quantumssh-core` (library), `unsafe_code = "forbid"` workspace-wide ([ADR-0017](./docs/adr/0017-phase-1-workspace-topology-two-crates-flat.md), [ADR-0018](./docs/adr/0018-phase-1-unsafe-code-forbid-workspace.md), Proposed).
- **ML-KEM-768 crate:** `RustCrypto/ml-kem` 0.3.0 ([ADR-0019](./docs/adr/0019-phase-1-ml-kem-crate-rustcrypto.md), Proposed).
- **CI interop gate:** every PR exercises a real OpenSSH 10.x client end-to-end ([ADR-0020](./docs/adr/0020-phase-1-ci-openssh-interop-gate.md), Proposed).

Acceptance criteria:
- Server listens on a port, accepts a connection
- Hybrid PQ key exchange (`mlkem768x25519-sha256` — only algorithm offered)
- Ed25519 host key
- Public-key authentication only
- Single-command execution
- Structured logging via `tracing`
- A real OpenSSH 10.x client completes connect/auth/exec/close in CI (hard gate)

### Phase 2 — Usable
- Interactive PTY allocation
- Configuration file (TOML, not `sshd_config`)
- SFTP subsystem
- systemd integration
- First public release: `0.1.0`

### Phase 3 — Hardening
- Continuous fuzzing (`cargo-fuzz`, OSS-Fuzz)
- Conformance tests against OpenSSH client
- Security audit (community-funded or grant-funded)
- First production-candidate release: `0.5.0`

### Phase 4 — Ecosystem
- Distribution packages (Debian, Arch, Alpine, Homebrew)
- Documentation site
- Reference deployment patterns
- Quantum-readiness guidance for regulated industries

Each phase ships when it is ready, not on a calendar. We do not estimate Phase durations: the schedule is a function of correctness, scrutiny, and community formation, and committing to a timeline would invert the priority. We are not in a hurry. Cryptographic infrastructure earns trust slowly.

---

## Why Rust, why now

Rust is the first systems language with C's performance characteristics, memory safety as a core guarantee, and a modern toolchain. It is being adopted for exactly this class of problem: the Linux kernel is integrating Rust drivers; Cloudflare replaced nginx with Pingora (Rust); Microsoft is rewriting parts of Windows in Rust; ISRG (the foundation behind Let's Encrypt) funds memory-safe rewrites of `sudo`, `ntpd`, and the DNS stack through their [Prossimo](https://www.memorysafety.org/) project.

SSH has not yet had its moment as truly open, memory-safe, post-quantum infrastructure. We think it is overdue.

We also think the post-quantum transition is the right inflection point. Every infrastructure team in the world will need to migrate to PQ-capable SSH within the next decade. They can do it by upgrading OpenSSH incrementally, or they can do it by adopting a tool that was designed for that world from day one. Both are valid. We are building the second option, and keeping it open while we do.

---

## Project values

- **Correctness over cleverness.** Boring code that obviously works beats elegant code that probably works.
- **Documentation is part of the product.** A protocol implementation no one understands is a protocol implementation no one can audit.
- **Spanish and English are first-class.** Documentation, blog posts, and conference talks will exist in both languages. Latin America has been a consumer of systems software for too long. We intend to be a producer.
- **Small surface, sharp edges.** We will say no to features more often than yes. Every feature is a permanent commitment to maintain, audit, and reason about.
- **Open governance.** Design decisions go through public RFCs. There is no benevolent dictator in the long run; there is a community that documents its reasoning so newcomers can understand how things came to be.

---

## Related work

We owe the community honesty about what already exists in this space. Several projects share part of QuantumSSH's territory, and our positioning is best understood next to theirs.

**OpenSSH** is the mature, dominant implementation. Written in C, actively maintained, and integrating PQ key exchange (`mlkem768x25519-sha256` is the default in 10.0+). It carries 25 years of legacy by design — a feature for compatibility, a burden for security. QuantumSSH is not a replacement for OpenSSH; it is an alternative with different tradeoffs.

**`russh`** is a Rust library implementing the SSH protocol, both client and server primitives. QuantumSSH does not depend on `russh` as a crate — Phase 1 implements the SSH-2 protocol layers greenfield, on audited cryptographic primitive crates ([RFC-0003](./docs/rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md)). `russh` is the closest reference implementation we read while building, and that role is acknowledged in RFC-0003 §"What does not change": the project's protocol work in Rust is a teaching artifact, not a competitor.

**Open Quantum Safe (`liboqs`, `liboqs-rust`)** at the University of Waterloo provides the post-quantum primitives that make this kind of project possible at all. Their `openssh` fork is research-oriented and based on older OpenSSH. We use their cryptographic libraries; we do not fork their SSH.

**Microsoft `Quantum-Safe-OpenSSH`** is a research fork of OpenSSH with PQ algorithms, distributed as Azure VM images. It is explicitly research-only and not for production.

**`qssh`** is a related effort targeting post-quantum SSH in Rust, with formal verification claims. As of this writing, it is distributed under a *source-available collaboration license* requiring email request and potential NDA for source access. We respect the work and the choice of model. QuantumSSH takes a different path: Apache 2.0, public from the first commit, contributions open to anyone without prior agreement. The two projects are not interchangeable, and the community is better served by having both directions explored.

If we have missed your project, please open an issue and we will add it.

---

## Origin

QuantumSSH is initiated and currently led by [Gonzalo Fleming Garrido](https://flemingtechnologies.cl/) at **Fleming Science and Technologies SpA** in Chile. The project is open source from the first commit and welcomes contributors from anywhere.

The companion document [`MANIFIESTO.es.md`](./MANIFIESTO.es.md) explains in Spanish why this project exists and what we hope it becomes. Reading it is encouraged but not required.

---

## Getting involved

- **Watch this repository** to follow the journey.
- **Open an issue** to discuss design decisions, propose features, or challenge assumptions. No NDA required, ever.
- **Reach out** if you have experience with: SSH protocol internals, post-quantum cryptography, fuzzing, formal verification, or systems Rust at scale.

We are explicitly looking for collaborators with cryptography backgrounds. If that is you, please introduce yourself.

---

## License

QuantumSSH is licensed under the **Apache License 2.0** (see [`LICENSE`](./LICENSE)).

Apache 2.0 was chosen deliberately:

- It is the de facto standard for modern systems infrastructure (Kubernetes, Tokio, most of the Rust ecosystem).
- It includes a patent grant, which matters in a project that touches cryptographic algorithms.
- It is permissive enough for adoption in regulated industries (banking, government, healthcare) without legal friction.
- It is compatible with most other open-source licenses for downstream integration.

This license choice is explicitly permanent. See the *Open source, really* section above.

Copyright (c) 2026 Fleming Science and Technologies SpA and contributors.

---

## Acknowledgements

This project stands on the shoulders of:

- The **OpenSSH** team, whose 25 years of careful work taught the world what a good SSH implementation looks like.
- The **Open Quantum Safe** project at the University of Waterloo, whose `liboqs` and `liboqs-rust` libraries make post-quantum cryptography accessible to implementers.
- The **`russh`** project, whose protocol work in Rust is the closest reference implementation QuantumSSH reads while building its own greenfield transport layer. Its prior art on Terrapin handling, the hybrid KEX migration, and the architectural shape of session-channel handling informed the design even though QuantumSSH does not depend on the crate.
- **ISRG / Prossimo** and the **Sovereign Tech Fund**, whose models of funding memory-safe critical infrastructure inspire our roadmap.
- The **NIST Post-Quantum Cryptography** standardization team, whose multi-year process gave us algorithms we can build on.

---

*Built in Chile. Written for the world. Designed for the next thirty years. Open, and staying open.*
