# ADR 0036: Move `ed25519-dalek` and `x25519-dalek` to 3.x together, on `curve25519-dalek` 5

- **Status:** Proposed
- **Date:** — (set on acceptance; drafted 2026-10-11)
- **Deciders:** Project lead
- **Related:** Subsidiary to [RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) (the primitive stack, §"Guide-level explanation"); the decision the [#109 comment of 2026-07-18](https://github.com/gonzafg2/quantumssh/issues/109) deferred ("bump x25519-dalek 3.x and ed25519-dalek 3.x together … recorded in an ADR subsidiary to RFC-0003"); interacts with the `ml-dsa` ADR proposed in [#174](https://github.com/gonzafg2/quantumssh/pull/174) (numbered ADR-0035 at drafting time; `ml-dsa` depends on `signature` 3.x); constrained by [ADR-0010](0010-toolchain-pinning-resolver-3-edition-2024-msrv-1-92.md) (MSRV 1.92) and [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md) (`unsafe_code = "forbid"`). Format parallels [ADR-0019](0019-phase-1-ml-kem-crate-rustcrypto.md).

## Context

The classical half of the stack is `x25519-dalek` 2.0.1 (the X25519 half
of `mlkem768x25519-sha256`) and `ed25519-dalek` 2.2.0 (host-key signing
and user-signature verification). Both sit on `curve25519-dalek` 4.1.3.
On 2026-07-06 the dalek project released a new line: `ed25519-dalek`
3.0.0 and `x25519-dalek` 3.0.0, both on `curve25519-dalek` 5.0.0.

The #109 comment of 2026-07-18 closed Dependabot's lone `x25519-dalek`
bump (#115). Moving one crate alone would have put two copies of the
curve core in the pre-auth tree. The comment asked for a coordinated
move in an ADR that evaluates four things: the new API, the
preservation of `zeroize` and `static_secrets`, the MSRV, and the
maturity and audit status of `curve25519-dalek` 5. It also chose to
"let them season first". `.github/dependabot.yml` keeps major bumps of
both crates out of Dependabot (#119), so the move only happens as a
decision.

Facts gathered on 2026-10-11:

| | Today | Proposed |
|---|---|---|
| `curve25519-dalek` | 4.1.3 (2024-06-18, MSRV 1.60). 4.2.0 was yanked: wrong `hash_to_curve` | 5.0.0 (2026-07-06, MSRV 1.85, edition 2024) |
| `ed25519-dalek` | 2.2.0 (2025-07-09, MSRV 1.81) | 3.0.0 (2026-07-06, MSRV 1.85) |
| `x25519-dalek` | 2.0.1 (2024-02-07, MSRV 1.60) | 3.0.0 (2026-07-06, MSRV 1.85) |
| Licence | BSD-3-Clause (all three crates) | BSD-3-Clause (all three crates), allowed by `deny.toml` |

Licence note: [RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md)
§"Guide-level explanation" says the nine primitive crates "are
Apache-2.0 or MIT". The dalek crates have always been **BSD-3-Clause**.
`deny.toml`'s allow-list includes BSD-3-Clause, so nothing was ever out
of policy, but the accepted RFC is inaccurate on this point. This ADR
records the correct fact. Accepted RFCs are layered on, not edited.

**The four points the #109 comment asked for:**

1. **API** (CHANGELOG of each 3.0.0 / 5.0.0 release):
   - `ed25519-dalek` 3.0.0 **removes the `std` feature**. Its runtime
     dependencies move to `ed25519` 3 and `sha2` 0.11 (and
     `curve25519-dalek` 5). `signature` 3 and `rand_core` 0.10 are
     optional there; `signature` 3 still enters the tree through
     `ed25519` 3. `getrandom` 0.4 is only a dev-dependency.
   - Everything the project calls is unchanged: `SigningKey::from_bytes`,
     `VerifyingKey::from_bytes`, `Signature::from_bytes` / `from_slice`,
     and `Signer` / `Verifier`.
   - `verify` keeps its 2.x semantics, and `verify_strict` stays a
     separate method.
   - `curve25519-dalek` 5.0.0 removes `group-bits` for soundness reasons
     (#909), which the project does not use. It makes compressed-point
     equality constant-time and keeps backend selection (serial / simd /
     `fiat` by cfg) unchanged.
   - Building the workspace against the new line needs **zero
     first-party code changes**. That was checked in a scratch copy:
     `check`, `clippy -D warnings`, the full test suite (34 + 103 + 35)
     and `build --release` all pass.
2. **`zeroize` and `static_secrets`:**
   - Both features remain in `x25519-dalek` 3.0.0.
   - 3.0.0 drops `impl Zeroize` on the secret types (PR #782), so
     `StaticSecret` and `SharedSecret` are now erased **on drop only**,
     through `ZeroizeOnDrop`. The project never calls `.zeroize()` on
     them; its explicit calls (`kex.rs`) target ML-KEM state and plain
     buffers.
   - `ed25519-dalek`'s `SigningKey` keeps `Drop` + `ZeroizeOnDrop`.
   - The one latent dependency on `std` was `zeroize/alloc`, which
     `Zeroizing<Vec<u8>>` needs. It used to arrive through
     `ed25519-dalek/std` and is now declared explicitly (the
     prerequisite PR, #175).
3. **MSRV:** 1.85 for all three. The workspace MSRV is 1.92 (ADR-0010).
4. **Maturity and audit:**
   - **Advisories.** RustSec lists RUSTSEC-2024-0344 for
     `curve25519-dalek` (timing leak in scalar subtraction, fixed in
     4.1.3) and RUSTSEC-2022-0093 for `ed25519-dalek` (fixed in 2.0).
     `x25519-dalek` has none. **No advisory affects the versions in use
     today, nor the proposed ones.**
   - **Formal verification.** `curve25519-dalek`'s README states that
     "the 280 Rust functions in version 4.1.3" were formally verified
     with Verus (VeriLib certificate). **That coverage is for 4.1.3,
     not 5.0.**
   - **Audit.** The only public audit found is Quarkslab's 2019 review,
     commissioned by Tari, which focused on `curve25519-dalek`. No
     public audit of 5.0 or of the 3.0 crates is known. They have been
     public for about three months.
   - **Maintenance of the old line.** There has been no usable 4.x
     release since 2024-06-18: 4.2.0, published 2025-07-09, was yanked.
     There is no 4.x maintenance branch, and no EOL is declared either.

## Decision

We will move **`ed25519-dalek` to 3.0.0 and `x25519-dalek` to 3.0.0
together**, so both resolve to `curve25519-dalek` 5.0.0:

```toml
x25519-dalek  = { version = "3.0.0", default-features = false, features = ["static_secrets", "zeroize"] }
ed25519-dalek = { version = "3.0.0", default-features = false, features = ["zeroize"] }
```

- `ed25519-dalek` drops `std`, which no longer exists, and `rand_core`.
  First-party code does not use `rand_core`: host keys are loaded from
  `openssh-key-v1`, never generated by the server.
- `x25519-dalek` keeps `static_secrets` and `zeroize`.
- The move lands in **one implementation PR**, after the prerequisite
  `zeroize/alloc` declaration (#175). That PR flips this ADR to
  `Accepted`.
- `.github/dependabot.yml` keeps ignoring major bumps of both crates.
  Their next major is again a coordinated decision, not a bot PR.

**What this decision is for — stated without overselling.** It fixes no
known vulnerability. Its value is indirect:
- **A smaller and single-versioned trust base.** `Cargo.lock` goes from
  102 to 88 packages, and `cargo tree -d` for `quantumssh-core` goes
  from six duplicated crates (`sha2`, `digest`, `rand_core`,
  `block-buffer`, `crypto-common`, `cpufeatures`) to none. Among the
  packages that leave `Cargo.lock` are `pkcs8`, `der`, `spki` and
  `generic-array`. Only `generic-array` is compiled today; the other
  three are unselected optional dependencies of `ed25519`, but they
  still sit in the lockfile (MANIFIESTO #4).
- **Alignment with the `ml-dsa` ADR proposed in #174.** `ml-dsa` depends
  on `signature` 3.x. Moving the dalek line now means the ML-DSA
  implementation adds no second `signature` major.
- **Staying on the current line.** `curve25519-dalek` 4.x has had no
  usable release since 2024-06-18 (4.2.0, 2025-07-09, was yanked).
  `ed25519-dalek` 2.x last released on 2025-07-09. The 5.x/3.x line is where upstream's releases now are.

## Consequences

### Positive

- One version of each hash, digest, RNG-trait and signature crate in the
  core's dependency tree, and 14 fewer packages to trust.
- `signature` 3 matches what `ml-dsa` requires (the ADR proposed in #174).
- The `zeroize/alloc` reliance is explicit rather than inherited (#175).
- The diff is two manifest lines plus `Cargo.lock`, with no first-party
  code change and no change to `verify` semantics. The `zeroize/alloc`
  line belongs to #175.

### Negative

- **Loses the Verus coverage.** The formal verification of 280
  functions applies to `curve25519-dalek` 4.1.3. On 5.0 that assurance
  is no longer claimed. This is the main cost, and it is accepted
  knowingly. The controls in place today are the RFC 7748 §6.1 X25519
  vectors (`kex.rs`) and the OpenSSH interop gate, which exercises
  Ed25519 host signing and user-signature verification end to end.
  They cover known-answer and end-to-end correctness; they do not
  replace a formal guarantee, and nothing currently does. Fuzzing
  (Phase 3, not yet in place) will add another layer, not the same one.
- **Young releases with no public audit.** About three months old, with
  no known audit. The same holds for every crate in the PQ layer
  (ADR-0019, and the `ml-dsa` ADR proposed in #174).
- **x25519 secrets erase on drop only.** The project relies on drop
  already, but an explicit `.zeroize()` on those types is no longer
  available should it ever be wanted.

### Neutral

- The MSRV floor of the dependencies rises from 1.60/1.81 to 1.85, which
  is still below the workspace's 1.92.
- `ed25519-dalek`'s `verify` remains non-strict, as in 2.x. Whether user
  authentication should use `verify_strict` is a separate hardening
  question, not decided here.

## Alternatives considered

### Alternative 1: Stay on 4.1.3 / 2.x until a trigger

Keep the Verus-covered core and revisit when (a) Verus coverage extends
to 5.x, (b) an advisory hits 4.x/2.x, or (c) the ML-DSA implementation
needs `signature` 3. Not chosen: the project lead decided on 2026-10-11
to move now, valuing the single-versioned, smaller tree and the
alignment with the `ml-dsa` ADR (#174) over the 4.1.3 verification
coverage. That
trade-off is recorded above.

### Alternative 2: Move only `x25519-dalek` (Dependabot #115)

Rejected, as the #109 comment already did. It leaves two copies of the
curve core and two `fiat-crypto` versions in the pre-auth tree, and
`deny.toml` only warns on duplicates.

### Alternative 3: Move only `ed25519-dalek`

Rejected for the same reason, mirrored.

## Links

- Decision source: [#109 comment of 2026-07-18](https://github.com/gonzafg2/quantumssh/issues/109); RFC-0003 §"Guide-level explanation" (the primitive stack).
- Upstream: [`dalek-cryptography/curve25519-dalek`](https://github.com/dalek-cryptography/curve25519-dalek) (CHANGELOGs of `curve25519-dalek` 5.0.0, `ed25519-dalek` 3.0.0, `x25519-dalek` 3.0.0); [Verus coverage statement in the `curve25519-dalek` README](https://github.com/dalek-cryptography/curve25519-dalek/blob/main/curve25519-dalek/README.md).
- Advisories: [RUSTSEC-2024-0344](https://rustsec.org/advisories/RUSTSEC-2024-0344.html), [RUSTSEC-2022-0093](https://rustsec.org/advisories/RUSTSEC-2022-0093.html).
- Audit: [Quarkslab, "Security audit of dalek libraries" (2019)](https://blog.quarkslab.com/security-audit-of-dalek-libraries.html).
- Prerequisite: [#175](https://github.com/gonzafg2/quantumssh/pull/175) (`zeroize/alloc` declared explicitly).
- Implementation: TBD — the PR that changes the two manifest lines and flips this ADR to `Accepted`.
