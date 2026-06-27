# ADR 0026: Re-key after 1 hour or 1 GiB per direction in Phase 1

- **Status:** Proposed
- **Date:** TBD (advances to Accepted when the re-keying implementation lands; tracked with the Phase-1 ADR status sweep, issue #86)
- **Deciders:** Project lead
- **Related:** Implements [issue #60](https://github.com/gonzafg2/quantumssh/issues/60); builds on [ADR-0021](0021-phase-1-negotiation-profile.md) (the negotiation profile and strict-kex mechanics the re-key reuses) and [ADR-0022](0022-phase-1-async-runtime-tokio.md) (the handshake budget reused as the re-key completion deadline); adds an event to [ADR-0024](0024-phase-1-log-event-schema.md) (log schema); realises `docs/threat-model.md` §2.4/§6.1 (ephemeral-secret hygiene, forward secrecy). Implemented in the `transport`/`channel` modules of `quantumssh-core` (M6).

## Context

[ADR-0021](0021-phase-1-negotiation-profile.md) fixes the `SSH_MSG_KEXINIT` profile and the strict-kex mechanics, and notes — but does not set — a re-keying policy: it says only that sequence numbers reset after *every* `SSH_MSG_NEWKEYS` and that the `kex-strict-*`/`ext-info-*` pseudo-algorithms are ignored on re-key KEXINITs. Through M5 the transport ran exactly one key exchange per connection, so a long-lived session protected an unbounded amount of traffic under a single set of session keys.

RFC 4253 §9 allows either party to start a new key exchange at any time. **BSI TR-02102-4 §3.3.1 (2026-01)** — the strictest published SSH-specific guidance — recommends re-keying after **one hour or one gigabyte of transferred data, whichever comes first**. This is plain key hygiene that bounds the traffic any single session key protects; it imposes nothing post-quantum-specific and does not touch the wire profile (the re-key uses the same `mlkem768x25519-sha256` KEX ADR-0021 already mandates). This ADR records the policy; the mechanism lives in code.

## Decision

The Phase 1 server **initiates a re-key** when, since the last completed (re-)key exchange, **either** of the following is reached, whichever first:

- **1 GiB (2³⁰ bytes) transferred in *either* direction** — inbound and outbound payload bytes are counted separately, and the threshold is per-direction (a re-key fires when *either* counter reaches it). BSI/RFC say "1 GB"; we read that as **1 GiB**, matching OpenSSH's `RekeyLimit` and crypto convention. Counting payload (decrypted/pre-seal) bytes, not wire frames, is the natural measure of "data protected under this key" and is symmetric across directions.
- **1 hour elapsed.** Measured with a monotonic clock (`tokio::time::Instant`) from the last completed exchange, so a quiet connection still re-keys on schedule.

Both counters and the interval timer **reset on every completed exchange** (initial and re-key).

Operative rules:

- **Initiator.** The server initiates on threshold. It also **responds** to a client-initiated re-key (an inbound `SSH_MSG_KEXINIT` during the data phase). Simultaneous initiation resolves to a single exchange.
- **The re-key runs encrypted.** Unlike the initial KEX (plaintext before the first NEWKEYS), every re-key message (`KEXINIT`, `KEX_HYBRID_INIT`/`REPLY`, `NEWKEYS`) is sealed under the *current* keys; new keys install per-direction — send-side right after our `NEWKEYS`, receive-side right after the peer's — and the matching sequence counter resets to zero (the strict-kex discipline ADR-0021 already mandates).
- **Session id is invariant.** Per RFC 4253 §7.2 the session identifier stays the **first** exchange hash `H` for the connection's life; a re-key produces a new `H_r` and new keys but never a new session id. Key derivation already takes the session id separately from the current `H`.
- **Re-key KEXINITs omit the markers.** The `kex-strict-*` marker is not advertised on a re-key KEXINIT, and `ext-info-*`/`SSH_MSG_EXT_INFO` are not re-sent (RFC 8308 is an initial-handshake concern). `negotiate` ignores the absent strict marker on re-key, consistent with ADR-0021.
- **Completion deadline.** A re-key must complete within the handshake budget ([ADR-0022](0022-phase-1-async-runtime-tokio.md): 30 s default, `Config.handshake_timeout`). A peer that does not finish in time is disconnected with `SSH_DISCONNECT_KEY_EXCHANGE_FAILED` (3). A re-key is the same bounded crypto request/response as the initial handshake; a peer that cannot complete one in the time the initial handshake was allowed is broken or hostile.
- **Client re-key abuse bound.** RFC 4253 §9 lets a peer start a re-key at any time, and a client with a low `RekeyLimit` legitimately re-keys very frequently (sub-second on a fast link) — so a *time-based* rate limit is wrong: it rejects conforming clients (an early implementation's 1 s floor broke stock OpenSSH with `RekeyLimit=16K`). The abuse bound is instead structural: **only one re-key may be in progress at a time** (enforced by the phase machine), and each re-key is a full multi-round-trip handshake, so a flood costs the peer as much as the server. The one genuinely new attacker-controlled quantity — the ML-KEM decapsulation per re-key — is cheap (microseconds) and gated by that one-at-a-time rule; the per-message length bounds already cover the rest.
- **Ephemeral secrets are zeroized.** The superseded epoch's shared secret, exchange hash, and ciphers are erased on drop (`Zeroizing`; threat model §6.1) when the new keys are installed.
- **Audit.** A completed re-key emits a new `rekey.completed` event (the pre-Phase-2 log schema is unversioned; [ADR-0024](0024-phase-1-log-event-schema.md) additions are permitted) with `kex_algorithm`, `host_key_algorithm`, `initiator` (`server`|`peer`), `trigger` (`time`|`bytes`|`peer`), `bytes_rx`, `bytes_tx`, `seconds`. A re-key negotiation rejection **and** a completion-deadline timeout both reuse the existing `kex.failed` event (both go through `rekey_reject`); `connection.closed` additionally records the disconnect reason.

## Consequences

### Positive

- Brings the default profile in line with the strictest credible SSH guidance (BSI TR-02102-4) at no wire-profile cost — the KEX, ciphers, and host-key type are unchanged.
- Bounds the traffic any single session key protects, limiting the blast radius of a session-key compromise and supporting the forward-secrecy goal (threat model §2.4).
- Reuses the existing KEX crypto, strict-kex sequence-reset discipline, and handshake budget — the new surface is the trigger accounting, the half-duplex gating, and the encrypted re-key transport, not new cryptography.
- `rekey.completed` lets operators distinguish initial KEX from re-keys and see what drove each one.

### Negative

- The re-key adds a state machine to the data phase and a half-duplex window (after the server sends its KEXINIT it stops sending channel data until its NEWKEYS), which briefly pauses outbound data while the child keeps running behind backpressure. Bounded by the completion deadline.
- Per-direction independent cipher install must pair each install with its sequence reset, or the AEAD nonce desyncs — a sharp edge, covered by integration tests on both ciphers.
- A client can still force periodic ML-KEM work by transferring data to the threshold; the rate limit caps only *gratuitous* client-initiated re-keys, not threshold-driven ones. Accepted: threshold-driven re-keys are the point.

### Neutral

- The 1 GiB / 1 hour figures are the BSI recommendation, not a hard protocol limit; they are configurable (`Config.rekey`) so deployments and tests can tune them (tests trigger at a few KiB). Defaults are documented.

## Alternatives considered

### Alternative 1: No re-keying in Phase 1 (defer to Phase 2)

The walking skeleton "works" without it. Rejected: re-keying is cheap to add on top of the existing KEX, it is the single concrete hardening gap the June 2026 review found (issue #60), and a server that never re-keys is a documented weakness for long sessions — better closed while the transport is fresh than deferred.

### Alternative 2: Time-only or bytes-only trigger

Simpler accounting. Rejected: BSI recommends both, and they cover different risks — a high-throughput session hits the byte bound long before an hour, a near-idle one hits the time bound first. Whichever-first is the standard reading.

### Alternative 3: Count summed (both-directions) bytes against one threshold

A single counter for in+out. Rejected: per-direction matches OpenSSH `RekeyLimit` semantics and bounds each key's exposure independently; a single summed counter would re-key twice as often on symmetric traffic for no extra security and is harder to reason about per-direction.

## Links

- Implementation: the `transport` (re-key state machine, encrypted re-KEX, cipher reinstall) and `channel` (loop integration, trigger, half-duplex gating) modules of `quantumssh-core` (M6), reusing `kex::{build_rekey_kexinit, hybrid_exchange, exchange_hash, derive_key, negotiate}`.
- Related ADRs: [ADR-0021](0021-phase-1-negotiation-profile.md) (negotiation profile + strict-kex), [ADR-0022](0022-phase-1-async-runtime-tokio.md) (handshake budget reused as the re-key deadline), [ADR-0024](0024-phase-1-log-event-schema.md) (`rekey.completed` added to the schema).
- Standards: RFC 4253 §9 (key re-exchange), §7.2 (key derivation, session id); RFC 8308 (EXT_INFO, initial-handshake only); BSI TR-02102-4 §3.3.1 (2026-01).
