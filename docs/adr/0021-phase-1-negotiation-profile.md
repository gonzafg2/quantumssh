# ADR 0021: Fix the Phase 1 `SSH_MSG_KEXINIT` negotiation profile

- **Status:** Proposed
- **Date:** TBD (advances to Accepted when the first Phase 1 crate lands)
- **Deciders:** Project lead
- **Related:** Implements [RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) (greenfield stack) at the wire level; consumes [ADR-0019](0019-phase-1-ml-kem-crate-rustcrypto.md) (ML-KEM crate); realises `docs/threat-model.md` §6.1 (cryptographic posture) and §5.2 (key-exchange attack vectors); its KEX selection and no-downgrade behaviour are exercised end-to-end by [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md) (OpenSSH interop gate). Planned implementation (TBD): the `kex` and `transport` modules of `quantumssh-core`, which do not exist yet — the first crate has not landed.

## Context

[RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) committed Phase 1 to a greenfield SSH-2 transport. The first thing that transport does on every connection is exchange `SSH_MSG_KEXINIT` (RFC 4253 §7.1), which carries ten name-lists that, intersected with the peer's, decide every algorithm the session uses. What QuantumSSH places in those name-lists *is* its cryptographic posture on the wire — and once a public client population exists (Phase 2, `0.1.0`), the profile becomes a compatibility contract that cannot be narrowed without breaking peers.

RFC-0003, the README, and `docs/threat-model.md` §6.1 each state pieces of the intended profile (hybrid PQ KEX only, Ed25519 host keys, AEAD ciphers, no legacy, strict-kex required) but none assembles the *complete* set of ten name-lists an implementer must hard-code into the `kex` module (TBD). This ADR is that assembly. It does not re-open any algorithm choice RFC-0003 already made; it fixes the exact strings, their order, and the failure behaviour, so the implementation and the ADR-0020 interop tests have one authoritative reference.

A specific subtlety this ADR must settle: SSH AEAD ciphers (`chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`) provide integrity inherently. The `mac_algorithms` name-lists are still sent in `SSH_MSG_KEXINIT`, but when an AEAD cipher is the negotiated encryption algorithm **MAC selection is skipped entirely and the contents of `mac_algorithms` are ignored** — no separate MAC is computed or applied, and an empty MAC intersection is never a connection failure (per the chacha20-poly1305@openssh.com and OpenSSH AES-GCM specifications: "MAC negotiation MUST be skipped", "failures … MUST NOT cause connection failure"). Because QuantumSSH offers AEAD ciphers *only*, the negotiated MAC is never exercised in any session. The decision below states what nonetheless goes in that field and what that means for the dependency set.

## Decision

We will advertise exactly the following `SSH_MSG_KEXINIT` profile in Phase 1. Per RFC 4253 §7.1 the negotiated algorithm in each slot is the first entry on the **client's** name-list that the server also offers — the server expresses preference by what it offers, not by its order. The order below is kept stable for readability and fingerprinting consistency.

**1. `kex_algorithms`**
```
mlkem768x25519-sha256          # only real key exchange (draft-ietf-sshm-mlkem-hybrid-kex)
kex-strict-s-v00@openssh.com   # Terrapin (CVE-2023-48795) defence — server marker
```

**2. `server_host_key_algorithms`**
```
ssh-ed25519                    # RFC 8709
```

**3. `encryption_algorithms_client_to_server`** and
**4. `encryption_algorithms_server_to_client`** (identical):
```
chacha20-poly1305@openssh.com  # no AES-NI dependency, uniform timing
aes256-gcm@openssh.com         # hardware-accelerated where AES-NI exists
```

**5. `mac_algorithms_client_to_server`** and
**6. `mac_algorithms_server_to_client`** (identical):
```
hmac-sha2-512-etm@openssh.com  # nominal only — never exercised under AEAD (see below)
```

**7. `compression_algorithms_client_to_server`** and
**8. `compression_algorithms_server_to_client`** (identical):
```
none                           # no compression — closes the compression attack surface
```

**9. `languages_client_to_server`** and
**10. `languages_server_to_client`**: empty (RFC 4253 §7.1: MAY be ignored, SHOULD be empty absent language preferences; a peer's non-empty list is ignored and is never a negotiation failure).

Additional binding decisions:

- **`first_kex_packet_follows` is `FALSE`.** Phase 1 never sends a guessed/optimistic KEX packet; it waits for the peer's KEXINIT before computing the exchange. If a peer sets the flag `TRUE`, the KEX packet that follows is processed when the guess was right and silently ignored when it was wrong, per RFC 4253 §7.1. The guessed packet is announced by the flag in the peer's KEXINIT, so it is not an "unexpected packet" under the strict-kex rule below; OpenSSH applies the same one-packet skip with strict kex active.
- **The MAC name-list is nominal, and `hmac` is not a Phase 1 dependency.** Because both offered ciphers are AEAD, MAC selection is always skipped. `hmac-sha2-512-etm@openssh.com` — the same MAC RFC-0003 names — is listed for robustness and as a documented extension point, but no HMAC code runs in Phase 1, so the `hmac` crate from RFC-0003's primitive list is **omitted from the Phase 1 `Cargo.toml`**. It is added only if and when a non-AEAD cipher is ever introduced (an RFC-gated change, implemented by a superseding ADR).
- **`strict-kex` is required, not merely offered.** If the client's **initial** KEXINIT does not contain `kex-strict-c-v00@openssh.com`, the server sends `SSH_MSG_DISCONNECT` with reason code `SSH_DISCONNECT_KEY_EXCHANGE_FAILED` (3) before NEWKEYS; in subsequent (re-key) KEXINITs the pseudo-algorithms are ignored, per the extension — OpenSSH omits them when re-keying. With strict kex active, both packet sequence numbers reset to zero after **every** `SSH_MSG_NEWKEYS` sent or received, for the duration of the connection; and during the initial key exchange any unexpected or out-of-sequence packet — including `SSH_MSG_IGNORE`/`SSH_MSG_DEBUG`, or a first packet that is not KEXINIT — terminates the connection, enforced structurally by RFC-0003's type-state transport. This is the structural Terrapin defence `docs/threat-model.md` §6.1 names.
- **`SSH_MSG_EXT_INFO` is honoured minimally, gated on the client.** If the client's initial KEXINIT offers `ext-info-c` (RFC 8308), the server sends one `SSH_MSG_EXT_INFO` carrying `server-sig-algs = ssh-ed25519` and nothing else, immediately after its first `SSH_MSG_NEWKEYS`; otherwise none is sent. The server does **not** advertise `ext-info-s`: that marker would oblige it to accept client extensions (RFC 8308 §2.2), which Phase 1 makes no use of — and it is not needed to send `server-sig-algs`, since the client's `ext-info-c` is what enables that. `ssh-ed25519` is the only public-key signature algorithm Phase 1 accepts for user authentication; advertising it lets a modern OpenSSH client select it without guessing.
- **Negotiation failure is explicit.** The marker pseudo-algorithms (`kex-strict-*`, `ext-info-*`) are never selectable: they are filtered out before selection and before any emptiness check (RFC 8308 §2.2 requires disconnect if an indicator ends up negotiated as a key exchange method). The negotiated key exchange **must be** `mlkem768x25519-sha256`; if the client does not offer it, the server sends `SSH_MSG_DISCONNECT` with reason code `SSH_DISCONNECT_KEY_EXCHANGE_FAILED` (3) and closes. The same disconnect applies to an empty intersection on any other required name-list (server host key, encryption); the MAC list is never a failure under the AEAD-only profile, and languages never participate. There is no fallback to any other key exchange. This is the wire realisation of the README non-goal "if your client cannot speak modern, hybrid-PQ SSH, it does not connect." ADR-0020's negative interop test asserts exactly this.
- **Failure of either hybrid half aborts.** Per `docs/threat-model.md` §5.2.1 and §6.1, a failure of the ML-KEM half or the X25519 half of `mlkem768x25519-sha256` aborts the handshake; there is no fallback to the surviving half. This must be enforced explicitly — FIPS 203 decapsulation uses implicit rejection and never fails on its own.
- **The negotiated lists are bound.** The full `I_C`/`I_S` KEXINIT payloads are bound into the exchange hash (RFC 4253 §8); per `docs/threat-model.md` §5.2.2, a test must verify that mutating either party's KEXINIT aborts the handshake.
- **Exclusion is at compile time.** Everything this profile omits — SSH-1, RSA, DSA, ECDSA-NIST, CBC modes, legacy Diffie-Hellman, `ssh-rsa`, compression — is not compiled into the implementation, not merely configured off (MANIFIESTO #3). The name-lists above are the complete compiled-in algorithm set; there is nothing to re-enable.

## Consequences

### Positive

- One authoritative source for the wire profile: the `kex` module (TBD) and the ADR-0020 interop tests are to reference this ADR rather than scattered prose across RFC-0003, the README, and the threat model.
- Every name-list is the smallest set consistent with the MANIFIESTO and the two-AEAD resilience hedge recorded in Alternative 1: one KEX, one host-key type, two AEAD ciphers, no compression, no legacy. MANIFIESTO #3 ("zero legacy") is mechanically auditable against this file.
- Dropping `hmac` from the Phase 1 dependency set removes a crate that would otherwise be compiled but never called — consistent with MANIFIESTO #4 ("small attack surface").
- The `SSH_DISCONNECT_KEY_EXCHANGE_FAILED` behaviour makes the "no downgrade" guarantee a testable property, not an aspiration.

### Negative

- Offering a single KEX algorithm means any future migration (e.g. ML-KEM-1024 for issue #42, or a `-v01` strict-kex) is a profile change that must supersede this ADR and update the interop fixtures together. That coupling is deliberate — the profile is security-load-bearing — but it is friction.
- Listing `hmac-sha2-512-etm@openssh.com` while not implementing HMAC is a small honesty gap: a reader of the KEXINIT could expect the MAC to be available. It is mitigated by the fact that the MAC is structurally unreachable under an AEAD-only cipher list, and by this ADR documenting the gap explicitly.
- The minimal `SSH_MSG_EXT_INFO` reply adds a small amount of transport code (a gate on the client's `ext-info-c` plus a single post-NEWKEYS send) that a strict "exec-only walking skeleton" reading of Phase 1 could argue against. The benefit is clean interop with the OpenSSH client the ADR-0020 gate depends on.

### Neutral

- The profile matches OpenSSH 10.x's default *KEX* (`mlkem768x25519-sha256`) but is deliberately narrower on every other axis (OpenSSH offers many ciphers, MACs, and host-key types; QuantumSSH offers the minimum). Interop holds because OpenSSH's broad offer always intersects QuantumSSH's narrow one.
- `aes256-gcm@openssh.com` is kept as a second cipher rather than going ChaCha-only. This is a hedge: on hardware with AES-NI it is faster, and a second independent AEAD construction is cheap insurance if a weakness is found in one. Issue #42 (algorithm agility) will decide the longer-term policy on multiple ciphers.

## Alternatives considered

### Alternative 1: ChaCha20-Poly1305 only (drop AES-GCM)

A single AEAD cipher is the most literal reading of "smallest surface". Rejected because a second, independently-constructed AEAD is cheap insurance against a future weakness in either, and `aes256-gcm@openssh.com` is materially faster on AES-NI hardware (most servers). The marginal surface of one extra well-studied AEAD is small; the resilience benefit is real. Revisited under issue #42.

### Alternative 2: Include a real HMAC and a non-AEAD cipher (e.g. CTR + ETM)

Offering `aes256-ctr` with `hmac-sha2-512-etm@openssh.com` would make the MAC name-list load-bearing and keep `hmac` in the tree. Rejected: Encrypt-then-MAC with CTR is strictly weaker ergonomics than AEAD, adds a non-AEAD code path (more state, more room for a Terrapin-shaped bug), and pulls a crate we otherwise do not need. AEAD-only is both smaller and safer.

### Alternative 3: Offer `mlkem1024nistp384-sha384` alongside the 768 profile

The draft registers this name; offering it would court NSS-adjacent operators. Rejected for Phase 1: it brings NIST P-384 (an additional ECDH primitive and curve) into the pre-auth path, contradicting "small surface", and `docs/threat-model.md` §8.7 already scopes NSS/CNSA 2.0 out. If demand is real it is an additive, RFC-gated change tracked by issue #42 — not a Phase 1 default.

### Alternative 4: Empty `mac_algorithms`

Since the MAC is never used, the field could be left empty. Rejected: an empty MAC name-list is a robustness risk against peers whose negotiation code does not special-case it, and it reads as an omission rather than a decision. A single nominal ETM entry is clearer and harmless.

## Links

- Implementation: TBD — when the first crate lands, the KEXINIT construction and negotiation will live in the `kex` and `transport` modules of `quantumssh-core`. These paths do not exist in the repository yet (same posture as ADR-0020's "Implementation: TBD").
- Interop assertions: ADR-0020's hard acceptance subset (its verbose-KEX assertion and its no-hybrid negative test); ADR-0020 owns the test identifiers and asserted strings.
- Related ADRs: [ADR-0019](0019-phase-1-ml-kem-crate-rustcrypto.md) (ML-KEM crate), [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md) (interop gate), [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md) (`unsafe_code = "forbid"`).
- Standards: RFC 4253 §7.1 (KEXINIT), RFC 8308 (`ext-info-c`, `server-sig-algs`), RFC 8709 (`ssh-ed25519`), `draft-ietf-sshm-mlkem-hybrid-kex-10` (`mlkem768x25519-sha256`), the `kex-strict-{c,s}-v00@openssh.com` extension (CVE-2023-48795 / Terrapin).
- Future policy: issue #42 (algorithm agility — what operators may add/remove and how migrations land).
