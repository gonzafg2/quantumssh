# ADR 0061: Wipe the stack below the transport ciphers, and keep their keys behind a box

- **Status:** Accepted
- **Date:** 2026-11-17 (accepted with the implementing PR, [#285](https://github.com/gonzafg2/quantumssh/pull/285). Its CI gave the x86_64 result this ADR lacked as a draft: the tests of §5 pass there with 16 KiB, in the dev and the release profile and with both AES backends; drafted 2026-11-17)
- **Deciders:** Project lead
- **Related:**
  - [#277](https://github.com/gonzafg2/quantumssh/issues/277), which records the key material the transport ciphers leave on the stack and holds this mitigation as its second open question.
  - The hardening milestone of Phase 3, [#248](https://github.com/gonzafg2/quantumssh/issues/248).
  - [Threat model](../threat-model.md) §4.3, which says what key erasure reaches and names the `aes` case as outside it. The implementing PR updates that text.
  - Keeps these decisions unchanged:
    - [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md): no first-party `unsafe`. `zeroize::zeroize_stack` is a safe function.
    - [ADR-0021](0021-phase-1-negotiation-profile.md): the two ciphers offered, and their order.
    - [ADR-0039](0039-rust-toolchain-pinned-to-exact-release.md): one pinned toolchain. The measurements here are for 1.100.0.

## Context

Threat model §4.3 commits to erasing key material after use, on a best
effort. [#280](https://github.com/gonzafg2/quantumssh/pull/280) made the
section say where that erasure stops: it reaches the values that hold a
key, and it does not reach the copies a primitive crate or the compiler
leaves on the stack. [#281](https://github.com/gonzafg2/quantumssh/pull/281)
then turned on the `zeroize` features that erase the ChaCha20 cipher
objects. Two questions stayed open in #277: how much key material is
still left on the stack by this binary, and whether a first-party wipe
removes it.

Upstream will not close the gap. The `aes` maintainers closed the report
of the software backend's residue as not planned
(`RustCrypto/block-ciphers#606`), and their position in
`RustCrypto/meta#38` is that a library erases the buffers its types own
and leaves stack temporaries to the caller, with
`zeroize::zeroize_stack`.

### What the transport ciphers leave on the stack

Measured on `main` at `371781d`, which includes #281. The harness calls
`quantumssh_core::cipher::PacketCipher` as the transport does, then
reads the process's stack through `/proc/self/mem` and counts the
16-byte chunks of each secret found there. Before every operation it
clears the region being measured, so a count is what that one operation
left.

- **Platform:** Linux on aarch64, in a container on an Apple Silicon
  host, `rustc 1.100.0`, release profile, 1024-byte payload.
- **AES backends:** the ARMv8 hardware backend, and the software backend
  selected with `--cfg aes_backend="soft"`.
- **Control:** a secret planted on the stack is found, 4 chunks of 4.

| Secret (chunks) | after `new` | after `seal` | after `body_len` | after `open` | after drop |
|---|---|---|---|---|---|
| ChaCha20: both keys (4) | 4 | 2 | 1 | 2 | 0 |
| ChaCha20: Poly1305 key (2) | 0 | 0 | 0 | 0 | 0 |
| AES, hardware: key (2) | 2 | 0 | 0 | 0 | 0 |
| AES, hardware: round keys (30) | 30 | 0 | 0 | 0 | 0 |
| AES, software: key (2) | 0 | 0 | 0 | 0 | 0 |
| AES, software: expanded schedule (60) | 0 | 60 | 0 | 60 | 0 |
| AES, software: compact schedule (15) | 15 | 0 | 0 | 0 | 0 |

Payloads of 64 bytes and of 32 KiB gave the same picture, with one or
two ChaCha20 key chunks after `seal`, and after `body_len` and `open`
taken together.

AES-GCM's `body_len` leaves nothing because it reads no key: it only
validates the length it is given. ChaCha20's decrypts the length with
the header key.

So every path leaves key material behind:

- **The default cipher** leaves both keys after construction, and part
  of them after every packet.
- **AES with hardware support** leaves the key and the whole schedule
  after construction, and nothing per packet.
- **AES in software** leaves the whole expanded schedule, 960 bytes,
  after every packet.

### What a wipe removes

The same runs, with `zeroize::zeroize_stack::<N>()` called from the
caller's frame after each operation:

- **`N` = 1024 is not enough.** Both ChaCha20 keys were still found
  after construction, and 21 of the 30 AES round keys.
- **`N` = 4096 clears both AES backends at every stage.**
- **`N` = 4096 clears ChaCha20 after `seal`, `open` and drop, and not
  after construction.** `PacketCipher::ChaCha` holds both keys inline,
  so the value `PacketCipher::new` returns carries them into the
  caller's frame. A wipe covers the frames below the one that calls it,
  not that frame.
- **With the ChaCha20 state behind a `Box`, `N` = 4096 clears it at
  every stage.** This was measured on a copy of the source with that one
  change. `PacketCipher::Gcm` is already boxed, which is why AES showed
  no such copy.

### What a wipe costs

Same container, with the host in its high-performance power mode. One
iteration is `seal`, `body_len` and `open`, with a wipe after each. Each
figure is the best of three runs, in nanoseconds.

| Cipher, payload | no wipe | 4 KiB | 16 KiB | 64 KiB |
|---|---|---|---|---|
| ChaCha20-Poly1305, 64 B | 1537 | 1678 | 1806 | 2469 |
| ChaCha20-Poly1305, 32 KiB | 63768 | 66408 | 65031 | 67296 |
| AES-256-GCM, hardware, 64 B | 312 | 492 | 669 | 1306 |
| AES-256-GCM, hardware, 32 KiB | 18208 | 16984 | 17081 | 18268 |

On small packets a 16 KiB wipe costs about 90 to 120 ns each. On 32 KiB
packets the differences are inside the run-to-run noise: the figures do
not even rise with `N`.

The implementation costs more than this estimate. Measured the same
way against `main`, in one session and two rounds, a packet sealed and
opened took:

| Cipher, payload | `main` | with the wipes of §2 |
|---|---|---|
| ChaCha20-Poly1305, 64 B | 1582 to 1590 ns | 1937 to 2043 ns |
| ChaCha20-Poly1305, 32 KiB | 65.8 µs | 66.2 to 67.0 µs |
| AES-256-GCM, hardware, 64 B | 316 to 318 ns | 542 to 570 ns |
| AES-256-GCM, hardware, 32 KiB | 16.7 µs | 17.1 µs |

That is about 110 to 150 ns per wipe on small packets, with three wipes
for ChaCha20 and two for AES-GCM, and one to two percent on 32 KiB
packets.

### What was not measured

- **x86_64, in the draft.** The upstream report covers `aes` there and
  found the key on the stack with AES-NI. Nothing in the draft's
  measurement ran on x86_64, which is the main server target. The
  implementing PR's CI did: §3 records the result.
- **The other primitives.** The key exchange, the host-key signature
  and the key derivation were not examined.
- **Other threads.** The harness ran on the main thread. The server runs
  these calls on tokio worker threads.

## Decision

We will wipe the stack below every `PacketCipher` operation, and keep
the key-bearing state of both ciphers on the heap.

### 1. Both cipher states live behind a `Box`

`PacketCipher::ChaCha` holds `Box<ChaCha20Poly1305Openssh>`, as
`PacketCipher::Gcm` already holds `Box<Aes256GcmOpenssh>`. A
`PacketCipher` then carries pointers, and moving one copies no key.

### 2. Each public operation wipes after its work

`PacketCipher::new`, `seal` and `open` each become a thin wrapper. The
wrapper calls an inner function that does the work, then calls
`zeroize::zeroize_stack`, then returns the result. `body_len` does the
same on its ChaCha20 arm only: the AES-GCM arm reads no key and gets no
wipe.

- The inner function is `#[inline(never)]`, as the documentation of
  `zeroize_stack` requires: if it were inlined, the wipe would cover the
  wrong region.
- The wipe is inside `PacketCipher`, not at its call sites. The
  transport calls these four functions in five places, and a caller
  cannot forget what it never had to do.
- An AES-GCM packet sent and received therefore takes two wipes, not the
  three the cost table measured.
- Dropping a `PacketCipher` gets no wipe. It left nothing in any run.

### 3. The wipe is 16 KiB

One constant, `16 * 1024`, for every wipe.

- 4 KiB was the smallest size that cleared every case on aarch64.
- 16 KiB leaves a margin of four, for x86_64, which was not measured,
  and for frame sizes that move when the toolchain or a primitive crate
  does.
- The margin costs about 40 to 60 ns more per wipe on small packets and
  nothing measurable on large ones.

The draft said that if the test of §5 showed that 16 KiB did not hold
on x86_64, the implementing PR would raise the constant before this ADR
was accepted. It holds. On `x86_64-unknown-linux-gnu`, with
`rustc 1.100.0`, run
[44138618905](https://github.com/gonzafg2/quantumssh/actions/runs/44138618905)
of #285 passed every test of §5 with 16 KiB: in the dev profile, in the
release profile, and in the release profile with the software AES
backend, whose control also passed.

### 4. `zeroize` 1.9 becomes the floor

`zeroize_stack` arrived in `zeroize` 1.9.0. The workspace requirement
moves from `"1"` to `"1.9"`. `Cargo.lock` already resolves 1.9.1, and no
package is added.

### 5. A test keeps it true

`#[inline(never)]` is a hint and the wipe is best effort, so a test
binds the behaviour. It runs on Linux, in safe Rust, and reads the
stack of the thread it runs on through `/proc/self/maps` and
`/proc/self/mem`. The harness confirmed that this works on a spawned
thread, which is where `cargo test` runs a test.

The test is built like the measurement. Each operation runs under a
padding frame and one caller frame, so the probe's own calls do not
overwrite what it looks for, and a copy left in the caller's frame stays
visible. It checks three things:

- **The probe sees.** A value planted at the depth the operations run
  at is found, and is gone after a wipe. Without this, a probe that had
  stopped seeing anything would pass every time.
- **The public operations leave no key.** After `new`, `seal`,
  `body_len` and `open`, none of the 16-byte chunks of the keys the test
  supplied is on the stack: the two ChaCha20 keys and the AES key. This
  is asserted for every operation, including those the table shows
  leaving nothing today.
- **The software AES backend leaves no schedule.** See below.

On the hardware AES backends the key is the first two round keys, and
in every run it appeared and disappeared together with the rest of the
schedule.

The software backend's schedule is a bitsliced form that no public API
exposes, and its key never appears on the stack. With
`--cfg aes_backend="soft"` the `aes::Aes256` object is the compact
schedule, so the test reads that object's bytes through
`/proc/self/mem`, in safe Rust, and computes the expanded form from
them. The backend could change how it holds its schedule without anyone
noticing, so this case has a control of its own: the inner functions of
`new` and of `seal`, called without the wipe, must leave those bytes on
the stack, as they did in the measurement (15 chunks of 15, and 60 of
60). The public functions must then leave none. CI runs the tests once
more with `--cfg aes_backend="soft"` for this.

The draft had the test use a schedule recorded by a script. The
implementing PR dropped that: the script read the cipher object through
`unsafe`, and code in this repository is first-party wherever it is
built (ADR-0018).

No other operation has a control of that kind. Hardware AES leaves
nothing after a packet, so there is nothing an un-wiped call could be
required to show.

The tests run in `build (ubuntu-latest)`, which is x86_64: in the dev
profile with the rest of the suite, then in the release profile, then
in the release profile with the software backend. That step fails if
the tests it names did not run, because a filter that matches nothing
passes.

### 6. Scope

This decision covers the transport ciphers and nothing else. The key
exchange, the host-key signature and the key derivation stay as #277
records them: not measured. Each needs its own measurement before a
wipe is placed around it.

**Why an ADR, not an RFC.** `docs/rfcs/README.md` sends a change to the
default cryptographic algorithms, a new public API, or a dependency
that widens the trust base to an RFC. This is none of them:

1. No algorithm, name-list or negotiation rule changes.
2. No dependency is added. `zeroize` is already in the graph, and the
   function is safe.
3. `PacketCipher` changes the type one variant holds. `quantumssh-core`
   is not published (ADR-0017), and nothing outside `cipher.rs` names
   that variant's contents.

## Consequences

### Positive

- The transport ciphers stop leaving session keys and AES schedules on
  the stack in every case measured here, including the software AES
  backend that upstream will not change.
- Threat model §4.3 can drop `aes` as a named case outside the
  guarantee, and its sentence about session keys gets closer to what
  the code does.
- The mechanism costs no dependency and no `unsafe`, and it sits in one
  file.
- A toolchain or crate bump that makes an operation leave a key fails a
  check instead of passing unnoticed.

### Negative

- **It is best effort.** A wipe clears a region of the stack. It does
  not clear registers, and it cannot reach a copy the compiler places
  above the wrapper's frame. The test covers the cases it can name on
  the targets CI runs.
- **A cost on every packet.** About 110 to 150 ns per wipe on small
  packets. For a 64-byte packet sent and received that takes
  ChaCha20-Poly1305 from about 1.6 µs to about 2.0 µs, and AES-GCM with
  hardware support from about 0.32 µs to about 0.55 µs. On a 32 KiB
  packet it is one to two percent. The figures come from a container on
  one machine.
- **The software-backend control can fail for a harmless reason.** If a
  compiler or an `aes` release stops leaving the schedule on the
  un-wiped path, or changes how the cipher object holds it, that control
  fails and someone has to look. That is the price of not passing
  blindly.
- **One more CI build.** The software-backend run compiles the
  dependency tree again with a different configuration.
- **aarch64 on Linux has no automated check.** CI runs the test on
  x86_64. The aarch64 figures are the ones in this ADR.

### Neutral

- `ChaCha20Poly1305Openssh` gains one heap allocation per cipher, made
  at key exchange and at each re-key.
- While a session is live its keys are in memory in any case. What this
  changes is what remains once the keys are replaced or the session
  ends, and what an idle worker thread's stack holds in between.

## Alternatives considered

### Alternative 1: leave it as documented

§4.3 already says the stack copies are outside the guarantee. Rejected:
the measurement shows the default cipher leaves both session keys on the
stack after every key exchange, and a mitigation exists that needs no
`unsafe` and no dependency.

### Alternative 2: wipe at the call sites in the transport

The transport would call `zeroize_stack` after each cipher call.
Rejected: five call sites today, each a place to forget, and the fuzz
entry points and tests would call the ciphers without it.

### Alternative 3: wipe once, when the keys are retired

One wipe at re-key or at session end. Rejected: the runtime is
multi-threaded, and a wipe reaches only the stack of the thread that
calls it. The packets of one session are sealed and opened on whichever
worker ran the task.

### Alternative 4: run the ciphers on a dedicated thread

A thread whose stack is wiped or unmapped when it ends. Rejected: every
packet would cross threads, for a result the wrapper gets in place.

### Alternative 5: wait for upstream, or patch `aes`

Rejected: upstream closed the report as not planned, and a fork of a
primitive crate widens what this project has to audit. It would not
cover the ChaCha20 copies or the copy made by moving a `PacketCipher`
either.

### Alternative 6: offer AES-GCM only where hardware runs it

The server would drop `aes256-gcm@openssh.com` on CPUs without the AES
instructions. Rejected: the hardware backend leaves the key and the
schedule at construction, and the default cipher leaves keys too, so
this removes one of the three cases measured. It would also change the
negotiation profile of ADR-0021.

### Alternative 7: compiler-level stack scrubbing

GCC has `-fstrub` and LLVM has a proposal. Rejected: nothing of the
kind is in stable Rust, and ADR-0039 keeps one pinned stable toolchain.

## Links

- Implementation, in #285: `crates/quantumssh-core/src/cipher.rs` with
  its `stack_residue` tests, the `zeroize` requirement in `Cargo.toml`,
  the stack-residue step of `.github/workflows/ci.yml`, and threat
  model §4.3.
- #277 for the upstream report, its measurements and the upstream
  position; #280 and #281 for the two changes this follows.
- `zeroize::zeroize_stack`, `zeroize` 1.9.1, `src/stack.rs`.
- Related ADRs: ADR-0017, ADR-0018, ADR-0021, ADR-0039.
