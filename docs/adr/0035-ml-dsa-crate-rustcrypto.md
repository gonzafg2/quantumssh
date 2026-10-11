# ADR 0035: Use `RustCrypto/ml-dsa` for the ML-DSA-44 half of the composite host key

- **Status:** Proposed
- **Date:** — (set on acceptance; drafted 2026-10-11)
- **Deciders:** Project lead
- **Related:** Subsidiary ADR 1 ("the ML-DSA primitive crate") of [RFC-0012](../rfcs/0012-composite-host-key-cutover.md) §Subsidiary decisions, which implements [RFC-0006](../rfcs/0006-post-quantum-host-key-signatures.md); the dependency layer of [RFC-0007](../rfcs/0007-cryptographic-primitive-migration-procedure.md) §2 ("a crate-selection ADR paralleling ADR-0019"); parallels [ADR-0019](0019-phase-1-ml-kem-crate-rustcrypto.md) (`ml-kem`); constrained by [ADR-0010](0010-toolchain-pinning-resolver-3-edition-2024-msrv-1-92.md) (MSRV 1.92) and [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md) (`unsafe_code = "forbid"`).

## Context

RFC-0012 cuts host authentication over to the composite
`ssh-mldsa44-ed25519`. The Ed25519 half is already in the tree
(`ed25519-dalek`); the ML-DSA-44 half (FIPS 204) needs a crate, and
RFC-0006 and RFC-0007 both require that choice to be its own ADR, as
ADR-0019 was for ML-KEM.

What the crate must do, fixed by RFC-0012 §Reference-level explanation:

- Derive the signing key from a 32-byte seed with
  `ML-DSA.KeyGen_internal` (FIPS 204 §6.1), because the composite stores
  seeds, not expanded keys.
- Sign with an explicit FIPS 204 context string (`ctx = Label`), and
  verify with it.
- Keep private state zeroizable (RFC-0012 §Key material).

What makes this choice stricter than ADR-0019's: **host-key signing is
reachable before authentication.** Every key exchange ends with the
server signing the exchange hash, so an unauthenticated peer can obtain
— and time — as many signatures as it opens connections. Constant-time
signing is a hard requirement, not a quality attribute.

Candidates surveyed on 2026-10-11:

| Crate | Version | Shape | Notes |
|---|---|---|---|
| `RustCrypto/ml-dsa` | 0.1.1 (2026-06-05) | Pure Rust; `unsafe_code = "forbid"` in its own manifest; `no_std` | ML-DSA-44/65/87; ACVP and Wycheproof vectors; `from_seed`, `sign_randomized` / `sign_deterministic` with `ctx`, `verify_with_context`; no independent audit |
| `libcrux-ml-dsa` | 0.0.11 (2026-10-07) | Rust with `unsafe` in SIMD paths; `0.0.x` API | Four RustSec advisories in 2026 (RUSTSEC-2026-0076, -0077, -0125, -0126), two rated high |
| `fips204` | 0.4.6 (2024-12-22) | Pure Rust | No release in almost two years |
| `aws-lc-rs` | 1.18.1 | FFI to C (AWS-LC) | `PqdsaKeyPair::sign(&self, msg, signature)` takes **no context string**, so it cannot produce the composite's `ctx = Label` signature |
| `pqcrypto-mldsa` | 0.1.2 | FFI to PQClean | Unmaintained (RUSTSEC-2026-0166, which recommends migrating to `ml-dsa`) |

`RustCrypto/ml-dsa` history matters for the version rule below:

- RUSTSEC-2025-0144, a timing side channel in `Decompose` during
  signing, was patched in `0.1.0-rc.3`. 0.1.1 is clean in RustSec.
- [RustCrypto/signatures#1386](https://github.com/RustCrypto/signatures/pull/1386),
  "ml-dsa: fix constant time issues" (`infinity_norm`,
  `coeff_from_half_byte`), merged on 2026-06-24 as `31b75402e4`. As of
  2026-10-11 it is in **no published release**; crates.io's latest is
  still 0.1.1.

## Decision

We will use **`RustCrypto/ml-dsa`** for the ML-DSA-44 half of the
composite host key.

1. **Version rule.** The pin is the first `ml-dsa` release that contains
   RustCrypto/signatures#1386, pinned exactly with an `=` requirement in
   the workspace `Cargo.toml`. **0.1.1 is not acceptable**: its signing
   path predates the constant-time fixes, and the signer is reachable
   before authentication (Context). This ADR stays `Proposed` until
   that release exists. It flips to `Accepted` in the PR that introduces
   the dependency, and that PR records the exact version here.
2. **Features.** `default-features = false, features = ["zeroize",
   "rand_core"]`: `zeroize` for private-state erasure (RFC-0012 §Key
   material), and `rand_core` for hedged signing. The defaults `alloc`,
   `getrandom` and `pkcs8` are not needed, because keys come from the
   `openssh-key-v1` container, not PKCS#8. A `cargo check` of
   `quantumssh-core` with this feature set against 0.1.1 compiles.
3. **Signing mode: hedged.** We call `sign_randomized` with
   `ctx = "COMPSIG-MLDSA44-Ed25519-SHA512"` and fresh OS randomness for
   every signature (the workspace already takes its randomness from
   `getrandom`). The hedged variant is FIPS 204's default, and it is
   what OpenSSH 10.6 does: its
   `ssh-mldsa-eddsa.c` fills a fresh `mldsa_rnd` with `arc4random_buf`
   for every signature. Byte-for-byte parity with OpenSSH is therefore
   neither possible nor required; verifiers accept any valid signature.
4. **Key derivation and verification.** Keys come from the stored seed
   through `from_seed` (FIPS 204 `KeyGen_internal`). Verification, used
   by the project's own tests, goes through `verify_with_context` with
   the same `ctx`.

## Consequences

### Positive

- The PQ signature path is pure Rust and `forbid`-compatible, with no FFI
  toolchain, mirroring ADR-0019.
- One vendor family for both post-quantum primitives (`ml-kem`,
  `ml-dsa`). The `ml-dsa` dependencies already in `Cargo.lock`
  (`module-lattice`, `hybrid-array`, `ctutils`, `crypto-common`) resolve
  to the existing versions; nothing there is duplicated.
- The version rule ties the pin to a concrete, verifiable fix rather
  than to a date.

### Negative

- **No independent audit.** Shared with every candidate, as ADR-0019
  recorded for ML-KEM. RFC-0012's composite contains the impact: a
  defect confined to the ML-DSA half degrades host authentication to
  Ed25519 alone, not below it.
- **`0.1.0` now waits on an upstream release.** If RustCrypto does not
  publish a release with #1386, the cut-over and with it `0.1.0` wait
  (RFC-0012 §Ordering). A git dependency is not an escape hatch:
  `deny.toml` sets `allow-git = []`.
- **Four new crates in `Cargo.lock`** with 0.1.1: `ml-dsa`, `shake`
  0.1.0, `signature` 3.0.0 and `sponge-cursor` 0.1.0. All four are
  RustCrypto crates licensed Apache-2.0 OR MIT, which `deny.toml`
  allows. The exact set is re-checked against the pinned release.
- **Two `signature` majors.** `ml-dsa` uses `signature` 3.x while
  `ed25519-dalek` 2.x uses 2.x. `deny.toml` only warns on duplicates
  (`multiple-versions = "warn"`). The duplication ends with the
  coordinated dalek 3.x bump planned on
  [#109](https://github.com/gonzafg2/quantumssh/issues/109); that bump
  is its own ADR (subsidiary to RFC-0003) and is not decided here.

### Neutral

- `cargo deny check` runs in the PR that adds the dependency. This ADR
  checked its inputs by hand: licences against `deny.toml`, and
  advisories against RustSec.

## Alternatives considered

### Alternative 1: `libcrux-ml-dsa`

It has partial formal-verification artefacts. It was not chosen
because of its `0.0.x` API, `unsafe` in its SIMD paths, and four RustSec
advisories in 2026, two of them in signature verification rated high.
Unlike ADR-0019's ML-KEM fallback, there is no byte-parity trigger to
reserve it for, because hedged signatures are not reproducible.

### Alternative 2: `aws-lc-rs`

Rejected. It is FFI to C, breaking the pure-Rust posture, and its
`PqdsaKeyPair::sign` takes no context string, so it cannot implement the
composite at all.

### Alternative 3: `fips204`

Pure Rust and `unsafe`-free, but with no release since 2024-12-22. It
can serve as an audit reference; it cannot be a load-bearing dependency,
for the same reason ADR-0019 gave for `fips203`.

### Alternative 4: `pqcrypto-mldsa`

Rejected. It is FFI, and RustSec declares it unmaintained.

### Alternative 5: pin `ml-dsa` 0.1.1 now

Rejected. It ships without the constant-time fixes, on a signing path an
unauthenticated peer can drive and time.

## Links

- Decision source: [RFC-0012](../rfcs/0012-composite-host-key-cutover.md) §Subsidiary decisions (1) and §Ordering; [RFC-0006](../rfcs/0006-post-quantum-host-key-signatures.md) §Unresolved questions ("Primitive crate").
- Upstream: [RustCrypto/signatures `ml-dsa`](https://github.com/RustCrypto/signatures/tree/master/ml-dsa); [#1386](https://github.com/RustCrypto/signatures/pull/1386) (constant-time fixes, merged 2026-06-24, unreleased as of 2026-10-11); [RUSTSEC-2025-0144](https://rustsec.org/advisories/RUSTSEC-2025-0144.html).
- Alternatives: [RustSec `libcrux-ml-dsa`](https://rustsec.org/packages/libcrux-ml-dsa.html); [RUSTSEC-2026-0166](https://rustsec.org/advisories/RUSTSEC-2026-0166.html) (`pqcrypto-mldsa` unmaintained); [`aws-lc-rs` `PqdsaKeyPair`](https://docs.rs/aws-lc-rs/1.18.1/aws_lc_rs/signature/struct.PqdsaKeyPair.html).
- Hedged signing in OpenSSH: `ssh-mldsa-eddsa.c` at tag `V_10_6_P1` of [openssh-portable](https://github.com/openssh/openssh-portable).
- Roadmap: Phase 2 — [`#109`](https://github.com/gonzafg2/quantumssh/issues/109).
- Implementation: TBD — the PR that adds the dependency, pins the exact version, and flips this ADR to `Accepted`.
