# ADR 0019: Use `RustCrypto/ml-kem` 0.3.0 for ML-KEM-768

- **Status:** Proposed
- **Date:** TBD (advances to Accepted when the first Phase 1 crate lands)
- **Deciders:** Project lead
- **Related:** Implements [RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) §"Operational dependencies of this decision"; sources [`claudedocs/phase1-open-decisions.md`](../../claudedocs/phase1-open-decisions.md) §"Decisión 3"; constrained by [ADR-0010](0010-toolchain-pinning-resolver-3-edition-2024-msrv-1-92.md) (MSRV 1.92) and [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md) (`unsafe_code = "forbid"`).

## Context

[RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) commits Phase 1 to a greenfield stack built on audited primitive crates and names the ML-KEM-768 crate selection as a follow-up ADR. The post-quantum half of the `mlkem768x25519-sha256` hybrid KEX is the single most consequential dependency choice in the cryptographic core: it sits in the pre-authentication path, it must conform to NIST FIPS 203 final, and Phase 1's `unsafe_code = "forbid"` posture ([ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md)) requires it to keep any `unsafe` confined inside the dependency rather than forcing first-party escapes.

Six candidates were surveyed: `RustCrypto/ml-kem`, `libcrux-ml-kem`, `aws-lc-rs`, `liboqs-rust`, `pqcrypto-mlkem`, and `fips203`. The classical half (X25519) is settled separately in the same RFC stack and is noted here only for completeness. This ADR records the ML-KEM crate choice and the conditions under which the fallback would be taken.

## Decision

We will use **`RustCrypto/ml-kem` 0.3.0** as the ML-KEM-768 implementation:

```toml
ml-kem       = { version = "0.3.0", default-features = false, features = ["zeroize"] }
x25519-dalek = { version = "2.0.1", default-features = false, features = ["static_secrets", "zeroize"] }
sha2         = "0.10"
```

Reasons, in order:

1. **Pure Rust, zero FFI, no `unsafe` on the exposed surface** — compatible with `unsafe_code = "forbid"` ([ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md)).
2. **It is the path `russh` itself adopted in 0.59** ([PR #660](https://github.com/Eugeny/russh/pull/660), 2026-03-26), so the stack does not diverge from the wider Rust SSH ecosystem even if RFC-0003's Option B fallback is ever taken.
3. **Apache-2.0 OR MIT**, compatible with the project's Apache-2.0 licence.
4. **NIST ACVP KATs run in CI**; conformant to FIPS 203 final (2024-08-13).
5. The `zeroize` feature provides the key-material erasure hygiene `docs/threat-model.md` §2.4 and §5.2.4 expect.
6. MSRV 1.85, within the workspace MSRV 1.92 ([ADR-0010](0010-toolchain-pinning-resolver-3-edition-2024-msrv-1-92.md)).

We will also call `validate_public_key` (FIPS 203 §7.2) before `encapsulate`, and add an explicit test for the `K = HASH(K_PQ || K_CL)` byte-array encoding (the classical share `K_CL` is a byte array, not an `mpint`) — the encoding bug OpenSSH hit on big-endian systems.

**Fallback — `libcrux-ml-kem` 0.0.8** — is taken only under either trigger:

- a later RFC raises the bar to **explicit formal verification** of the PQ path (`libcrux` is the only Rust ML-KEM crate with published hax/F\* proofs), or
- **byte-for-byte parity with OpenSSH 10.x** is required (OpenSSH's `kexmlkem768x25519.c` uses libcrux via `libcrux_mlkem768_sha3.h`).

The fallback's costs are recorded so the trade is pre-analysed: a `0.0.x` (unstable-API) version, five extra transitive crates, and two recent maturity signals (the 0.0.3 yank for an aarch64 bug, [cryspen/libcrux#1220](https://github.com/cryspen/libcrux/issues/1220), and RUSTSEC-2026-0074 in `libcrux-sha3` — which does not affect the ML-KEM path but denotes ecosystem immaturity).

## Consequences

### Positive

- The PQ dependency is pure-Rust and `forbid`-compatible from day one; no FFI toolchain (C/CMake/Go) enters the build.
- Stack convergence with `russh` 0.59+ means RFC-0003's Option B fallback, if ever invoked, does not also force an ML-KEM crate migration.
- ACVP conformance is mechanically checked in CI, not asserted.

### Negative

- **No Rust ML-KEM crate has an independent professional audit** as of mid-2026 (Project Eleven, *State of Post-Quantum Cryptography in Rust*, Nov 2025). If Phase 3 requires an external audit of the PQ path, it must be funded — there is no shortcut, and this is consistent with the MANIFIESTO's "what we are willing to accept". This cost is shared by every alternative.
- `ml-kem` 0.3.0 is pre-1.0; a breaking API change before the project pins a `Cargo.lock` for release is possible. Mitigation: exact-version discipline and the ACVP KAT suite catch behavioural drift on upgrade.

### Neutral

- The fallback crate is named but not vendored. Switching to `libcrux-ml-kem` later is a contained `Cargo.toml` + KEX-glue change, gated by the two triggers above.

## Alternatives considered

### Alternative 1: `libcrux-ml-kem` 0.0.8 (the named fallback)

The only Rust ML-KEM crate with published formal-verification artefacts, and the implementation OpenSSH itself links. Not chosen as primary because of its `0.0.x` API instability, five extra transitive deps, and two recent maturity incidents. Retained as the documented fallback under the formal-verification or OpenSSH-byte-parity triggers.

### Alternative 2: `aws-lc-rs`

Rejected for Phase 1. Requires C + CMake + Go + bindgen, breaking the pure-Rust posture and the `forbid` story. Reserve for Phase 3+ only if a FIPS 140-3 requirement appears.

### Alternative 3: `liboqs-rust`

Rejected. C bindings; last release May 2025; out of sync with liboqs 0.14. Stale.

### Alternative 4: `pqcrypto-mlkem`

Rejected. C bindings (PQClean); mixed licences in vendored code; little traction (~10 reverse deps).

### Alternative 5: `fips203` (Schorn)

Rejected as a production dependency. It is the only candidate with an explicit `#![forbid(unsafe_code)]`, but it is stalled (last commit Sep 2025), single-contributor, with no relevant reverse deps. Useful as an audit reference, not as a load-bearing dependency.

## Links

- Decision source: [RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) §"Operational dependencies of this decision"; analysis in [`claudedocs/phase1-open-decisions.md`](../../claudedocs/phase1-open-decisions.md) §"Decisión 3".
- Conformance vectors: NIST ACVP-Server (`ML-KEM-keyGen-FIPS203`, `ML-KEM-encapDecap-FIPS203`); X25519 against RFC 7748 §6.1. Test-vector sourcing aligns with [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md) and RFC-0003 §"Test vectors and KAT plan".
- Upstream convergence: [`russh` PR #660](https://github.com/Eugeny/russh/pull/660) (migration to `RustCrypto/ml-kem`).
- Constrained by: [ADR-0010](0010-toolchain-pinning-resolver-3-edition-2024-msrv-1-92.md) (MSRV), [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md) (`unsafe_code = "forbid"`).
- Roadmap: Phase 1 / Hito 1 — [`#9`](https://github.com/gonzafg2/quantumssh/issues/9).
- Implementation: TBD (the dependency is declared in the first `quantumssh-core` `Cargo.toml`; no code has landed yet).
