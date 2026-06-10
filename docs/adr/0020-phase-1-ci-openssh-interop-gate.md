# ADR 0020: Gate Phase 1 CI on OpenSSH 10.x interop with a pinned version

- **Status:** Proposed
- **Date:** TBD (advances to Accepted when the first Phase 1 crate lands)
- **Deciders:** Project lead
- **Related:** Implements [RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) §"Acceptance criteria stay as issue #9 defines them" and resolves its unresolved question 4; sources the project's internal Phase-1 decision notes §"Decisión 5"; adds a workflow alongside `.github/workflows/ci.yml`.

## Context

[RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) chose a greenfield SSH stack. Its sharpest residual risk (Drawback 3) is **silent protocol divergence**: code written against the RFC text and the `draft-ietf-sshm-mlkem-hybrid-kex` Internet-Draft can pass a `quantumssh ↔ quantumssh` test suite while still failing against what a real OpenSSH client does on the wire (the `C_INIT`/`S_REPLY` encoding, the `K_PQ || K_CL` order, the `K` byte encoding). The README non-goal is explicit — *"if your client cannot speak modern, hybrid-PQ SSH, it does not connect"* — so if the reference PQ-capable client (OpenSSH 10.x) cannot connect, the product does not work.

The structural defence RFC-0003 names is a **hard interop gate**: every PR must drive a real OpenSSH 10.x client through connect/auth/exec/close against `quantumssh`. The operative obstacle is runner availability — `ubuntu-latest` (24.04 LTS) ships OpenSSH **9.6p1, not 10.0**, so `apt install openssh-client` on the default runner does not satisfy the gate. RFC-0003's unresolved question 4 asked what the gate does when a pinned OpenSSH version itself changes wire behaviour; it was resolved at acceptance in favour of pinning.

## Decision

We will add a **mandatory CI interop job** that exercises a real OpenSSH 10.x client against `quantumssh` end-to-end on every PR, with the OpenSSH version **explicitly pinned** (not left to a floating tag):

- The job runs in a **Debian trixie container** providing OpenSSH 10.0p1-7, on a GitHub-hosted runner, because the default Ubuntu runner ships 9.6p1.
- The pin is enforced concretely, because the `debian:trixie-slim` *tag* is mutable and Debian's APT repositories advance over time: the container is referenced **by image digest** (`debian@sha256:…`), and `openssh-client` is installed with an **explicit version** (`apt-get install openssh-client=<version>`) from a frozen source (a pinned `snapshot.debian.org` suite, or a vendored `.deb`). The tag name alone is documentation, not the pin.
- The job asserts the client version — `ssh -V` output (which carries distro/build suffixes, e.g. `OpenSSH_10.0p1 Debian-…`) must **contain** `OpenSSH_10.0p1` — then builds the release binary, runs the full test suite, and runs `tests/interop/run_openssh_client.sh` (connect → pubkey auth → `echo hello` → clean close).
- The interop job is a **required check** for merge into `main`.
- **The OpenSSH bits are pinned, not floated.** With the digest + package-version pin above, an upstream OpenSSH change that alters wire behaviour never silently breaks an unrelated PR. Bumping the pin (new digest and/or package version) is its own deliberately-reviewed PR ("OpenSSH version bump"), so a wire-format shift during the ongoing PQ-KEX rollout surfaces as a reviewed event, not as a mystery red check on someone else's change. Without the digest + version pin this property does not hold — which is why the pin mechanism is part of this decision, not an implementation detail.

The HARD acceptance subset this job enforces (from RFC-0003 / the project's internal Phase-1 decision notes §"Decisión 5"): `integration::openssh_smoke` (`ssh … echo hello` → `hello`, exit 0), `integration::openssh_verbose_kex` (`ssh -v` shows `kex: algorithm: mlkem768x25519-sha256`), and `integration::negative_no_hybrid` (a non-hybrid client receives `SSH_DISCONNECT_KEY_EXCHANGE_FAILED`).

Phase 1 deliberately does **not** add `cargo-fuzz` (nightly, CI cost; Phase 3 owns serious fuzzing); lightweight `proptest` roundtrips are the soft, non-blocking complement.

## Consequences

### Positive

- Silent protocol divergence is caught on the PR that introduces it, against the world's reference PQ-capable client — the one property a self-interop suite structurally cannot give.
- The pin makes CI deterministic: the same OpenSSH binary on every run, so a red interop check means *our* change broke interop, not that the runner image moved under us.
- OpenSSH upgrades become visible, reviewed decisions with their own diff and rationale.

### Negative

- Running inside a container adds setup time (apt install of `openssh-client`, build toolchain) versus a bare runner. Mitigation: trixie-slim is small; the cost is a few minutes, acceptable for a required correctness gate.
- A pinned OpenSSH can lag a freshly released wire-format fix until the bump PR lands. Mitigation: that lag is the point — it is a reviewed window, not silent drift; a matrix against 10.0/10.1/10.2 is named as a soft, post-Phase-1 enhancement.
- The interop gate cannot run until the first crate produces a connectable binary, so it is wired up in the first-crate PR, not before.

### Neutral

- Container choice is an implementation detail, not a protocol commitment. Building OpenSSH from source (cacheable, ~3-4 min) is the named alternative if a multi-version matrix is later wanted; switching does not change what the gate asserts.

## Alternatives considered

### Alternative 1: Rust-only interop (`quantumssh ↔ quantumssh`, or a Rust client)

Rejected as the gate. A self-interop test proves the implementation is consistent with itself, not with OpenSSH — exactly the divergence class RFC-0003 Drawback 3 calls out. Kept as a *complementary* fast test (`integration::client_smoke`), not as the hard gate.

### Alternative 2: `apt install openssh-client` on `ubuntu-latest`

Rejected on a verified fact: Ubuntu 24.04 LTS ships OpenSSH 9.6p1, which does not speak the hybrid PQ KEX the gate must exercise. The naive approach silently tests the wrong version.

### Alternative 3: Float OpenSSH (always newest available)

Rejected per RFC-0003 question 4. Floating means an upstream OpenSSH wire-format change can turn an unrelated PR's interop check red with no first-party cause, during a protocol era (PQ KEX rollout) where exactly such changes have happened. Pinning + an explicit bump PR keeps the signal attributable.

### Alternative 4: Build OpenSSH 10.x from source in CI

A viable variant, useful when a multi-version matrix (10.0/10.1/10.2) is wanted. Not chosen for Phase 1 because the trixie container reaches a single pinned 10.0p1 with less moving machinery; recorded as the upgrade path if the matrix becomes desirable.

## Links

- Decision source: [RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) §"Acceptance criteria stay as issue #9 defines them" and resolved unresolved-question 4; analysis in the project's internal Phase-1 decision notes §"Decisión 5".
- Version facts (verified 2026-05, re-check on implementation): the GitHub-hosted `ubuntu-24.04` runner ships OpenSSH 9.6p1 — source: [`actions/runner-images`](https://github.com/actions/runner-images) (which documents GitHub runner images, not Debian containers); Debian trixie's `openssh-client` is 10.0p1-7 — source: the Debian package tracker ([tracker.debian.org/pkg/openssh](https://tracker.debian.org/pkg/openssh)). Both are time-dependent; the pinned digest + package version (see "Decision") is what fixes them in CI regardless of upstream drift.
- Configuration this decision adds: a new interop job alongside `.github/workflows/ci.yml`, plus `tests/interop/run_openssh_client.sh`, landing with the first connectable binary.
- Related ADRs: [ADR-0011](0011-ci-guards-workspace-state.md) (CI workspace-state guards), [ADR-0019](0019-phase-1-ml-kem-crate-rustcrypto.md) (ML-KEM crate whose wire output this gate validates).
- Roadmap: Phase 1 / Hito 1 — [`#9`](https://github.com/gonzafg2/quantumssh/issues/9).
- Implementation: TBD (no code or workflow has landed yet; the gate is wired up in the first-crate PR).
