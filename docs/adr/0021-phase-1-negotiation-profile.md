# ADR 0021: Fix the Phase 1 `SSH_MSG_KEXINIT` negotiation profile

- **Status:** Proposed
- **Date:** TBD (advances to Accepted when the first Phase 1 crate lands)
- **Deciders:** Project lead
- **Related:** Implements [RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) (greenfield stack) at the wire level; consumes [ADR-0019](0019-phase-1-ml-kem-crate-rustcrypto.md) (ML-KEM crate); realises `docs/threat-model.md` §6.1 (cryptographic posture) and §5.2 (key-exchange attack vectors); enforced end-to-end by [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md) (OpenSSH interop gate). Planned implementation (TBD): the `kex` and `transport` modules of `quantumssh-core`, which do not exist yet — the first crate has not landed.

## Context

[RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) committed Phase 1 to a greenfield SSH-2 transport. The first thing that transport does on every connection is exchange `SSH_MSG_KEXINIT` (RFC 4253 §7.1), which carries ten name-lists that, intersected with the peer's, decide every algorithm the session uses. What QuantumSSH places in those name-lists *is* its cryptographic posture on the wire — and once a public client population exists (Phase 2, `0.1.0`), the profile becomes a compatibility contract that cannot be narrowed without breaking peers.

RFC-0003, the README, and `docs/threat-model.md` §6.1 each state pieces of the intended profile (hybrid PQ KEX only, Ed25519 host keys, AEAD ciphers, no legacy, strict-kex required) but none assembles the *complete* set of ten name-lists an implementer must hard-code into `kex.rs`. This ADR is that assembly. It does not re-open any algorithm choice RFC-0003 already made; it fixes the exact strings, their order, and the failure behaviour, so the implementation and the ADR-0020 interop tests have one authoritative reference.

A specific subtlety this ADR must settle: SSH AEAD ciphers (`chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`) provide integrity inherently. The `mac_algorithms` name-lists are still sent in `SSH_MSG_KEXINIT`, but when an AEAD cipher is the negotiated encryption algorithm the **result of the MAC negotiation is discarded** — no separate MAC is computed or applied (per the chacha20-poly1305@openssh.com and OpenSSH AES-GCM specifications). Because QuantumSSH offers AEAD ciphers *only*, the negotiated MAC is never exercised in any session. The decision below states what nonetheless goes in that field and what that means for the dependency set.

## Decision

We will advertise exactly the following `SSH_MSG_KEXINIT` profile in Phase 1. Order is preference order (most preferred first); the server's first match against the client's list wins per RFC 4253 §7.1.

**1. `kex_algorithms`**
```
mlkem768x25519-sha256          # only real key exchange (draft-ietf-sshm-mlkem-hybrid-kex)
kex-strict-s-v00@openssh.com   # Terrapin (CVE-2023-48795) defence — server marker
ext-info-s                     # RFC 8308 — signal willingness to send SSH_MSG_EXT_INFO
```

**2. `server_host_key_algorithms`**
```
ssh-ed25519                    # RFC 8709
```

**3. `encryption_algorithms_client_to_server`** and
**4. `encryption_algorithms_server_to_client`** (identical):
```
chacha20-poly1305@openssh.com  # preferred — no AES-NI dependency, uniform timing
aes256-gcm@openssh.com         # fallback — hardware-accelerated where AES-NI exists
```

**5. `mac_algorithms_client_to_server`** and
**6. `mac_algorithms_server_to_client`** (identical):
```
hmac-sha2-256-etm@openssh.com  # nominal only — never exercised under AEAD (see below)
```

**7. `compression_algorithms_client_to_server`** and
**8. `compression_algorithms_server_to_client`** (identical):
```
none                           # no compression — closes the compression attack surface
```

**9. `languages_client_to_server`** and
**10. `languages_server_to_client`**: empty (RFC 4253 §7.1 — always empty in practice).

Additional binding decisions:

- **`first_kex_packet_follows` is `FALSE`.** Phase 1 never sends a guessed/optimistic KEX packet; it waits for the peer's KEXINIT before computing the exchange.
- **The MAC name-list is nominal, and `hmac` is not a Phase 1 dependency.** Because both offered ciphers are AEAD, the negotiated MAC is always skipped. `hmac-sha2-256-etm@openssh.com` is listed for robustness and as a documented extension point, but no HMAC code runs in Phase 1, so the `hmac` crate from RFC-0003's primitive list is **omitted from the Phase 1 `Cargo.toml`**. It is added only if and when a non-AEAD cipher is ever introduced (which would itself require a new ADR).
- **`strict-kex` is required, not merely offered.** If the client's KEXINIT does not contain `kex-strict-c-v00@openssh.com`, the server aborts before NEWKEYS. The sequence number is reset across the strict-kex boundary per the extension. This is the structural Terrapin defence `docs/threat-model.md` §6.1 names.
- **`ext-info-s` is honoured minimally.** After the first `SSH_MSG_NEWKEYS`, the server sends one `SSH_MSG_EXT_INFO` carrying `server-sig-algs = ssh-ed25519` and nothing else. This is the only public-key signature algorithm Phase 1 accepts for user authentication; advertising it lets a modern OpenSSH client select it without guessing.
- **Negotiation failure is explicit.** If the intersection on the KEX name-list is empty — most importantly, if the client does not offer `mlkem768x25519-sha256` — the server sends `SSH_MSG_DISCONNECT` with reason code `SSH_DISCONNECT_KEY_EXCHANGE_FAILED` (3) and closes. There is no fallback to any other key exchange. This is the wire realisation of the README non-goal "if your client cannot speak modern, hybrid-PQ SSH, it does not connect." ADR-0020's `integration::negative_no_hybrid` test asserts exactly this.

## Consequences

### Positive

- One authoritative source for the wire profile: `kex.rs` and the ADR-0020 interop assertions reference this ADR rather than scattered prose across RFC-0003, the README, and the threat model.
- Every name-list is the smallest set that satisfies the MANIFIESTO: one KEX, one host-key type, two AEAD ciphers, no compression, no legacy. MANIFIESTO #3 ("zero legacy") is mechanically auditable against this file.
- Dropping `hmac` from the Phase 1 dependency set removes a crate that would otherwise be compiled but never called — consistent with MANIFIESTO #4 ("small attack surface").
- The `SSH_DISCONNECT_KEY_EXCHANGE_FAILED` behaviour makes the "no downgrade" guarantee a testable property, not an aspiration.

### Negative

- Offering a single KEX algorithm means any future migration (e.g. ML-KEM-1024 for issue #42, or a `-v01` strict-kex) is a profile change that must touch this ADR and the interop fixtures together. That coupling is deliberate — the profile is security-load-bearing — but it is friction.
- Listing `hmac-sha2-256-etm@openssh.com` while not implementing HMAC is a small honesty gap: a reader of the KEXINIT could expect the MAC to be available. It is mitigated by the fact that the MAC is structurally unreachable under an AEAD-only cipher list, and by this ADR documenting the gap explicitly.
- `ext-info-s` plus a minimal `SSH_MSG_EXT_INFO` adds a small amount of transport code that a strict "exec-only walking skeleton" reading of Phase 1 could argue against. The cost is ~30 lines; the benefit is clean interop with the OpenSSH client the ADR-0020 gate depends on.

### Neutral

- The profile matches OpenSSH 10.x's default *KEX* (`mlkem768x25519-sha256`) but is deliberately narrower on every other axis (OpenSSH offers many ciphers, MACs, and host-key types; QuantumSSH offers the minimum). Interop holds because OpenSSH's broad offer always intersects QuantumSSH's narrow one.
- `aes256-gcm@openssh.com` is kept as a second cipher rather than going ChaCha-only. This is a hedge: on hardware with AES-NI it is faster, and a second independent AEAD construction is cheap insurance if a weakness is found in one. Issue #42 (algorithm agility) will decide the longer-term policy on multiple ciphers.

## Alternatives considered

### Alternative 1: ChaCha20-Poly1305 only (drop AES-GCM)

A single AEAD cipher is the most literal reading of "smallest surface". Rejected because a second, independently-constructed AEAD is cheap insurance against a future weakness in either, and `aes256-gcm@openssh.com` is materially faster on AES-NI hardware (most servers). The marginal surface of one extra well-studied AEAD is small; the resilience benefit is real. Revisited under issue #42.

### Alternative 2: Include a real HMAC and a non-AEAD cipher (e.g. CTR + ETM)

Offering `aes256-ctr` with `hmac-sha2-256-etm@openssh.com` would make the MAC name-list load-bearing and keep `hmac` in the tree. Rejected: Encrypt-then-MAC with CTR is strictly weaker ergonomics than AEAD, adds a non-AEAD code path (more state, more room for a Terrapin-shaped bug), and pulls a crate we otherwise do not need. AEAD-only is both smaller and safer.

### Alternative 3: Offer `mlkem1024nistp384-sha384` alongside the 768 profile

The draft registers this name; offering it would court NSS-adjacent operators. Rejected for Phase 1: it brings NIST P-384 (an additional ECDH primitive and curve) into the pre-auth path, contradicting "small surface", and `docs/threat-model.md` §8.7 already scopes NSS/CNSA 2.0 out. If demand is real it is an additive, RFC-gated change tracked by issue #42 — not a Phase 1 default.

### Alternative 4: Empty `mac_algorithms`

Since the MAC is never used, the field could be left empty. Rejected: an empty MAC name-list is a robustness risk against peers whose negotiation code does not special-case it, and it reads as an omission rather than a decision. A single nominal ETM entry is clearer and harmless.

## Links

- Implementation: TBD — when the first crate lands, the KEXINIT construction and negotiation will live in the `kex` and `transport` modules of `quantumssh-core`. These paths do not exist in the repository yet (same posture as ADR-0020's "Implementation: TBD").
- Interop assertions: ADR-0020 `integration::openssh_verbose_kex` (asserts `kex: algorithm: mlkem768x25519-sha256`) and `integration::negative_no_hybrid` (asserts `SSH_DISCONNECT_KEY_EXCHANGE_FAILED`).
- Related ADRs: [ADR-0019](0019-phase-1-ml-kem-crate-rustcrypto.md) (ML-KEM crate), [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md) (interop gate), [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md) (`unsafe_code = "forbid"`).
- Standards: RFC 4253 §7.1 (KEXINIT), RFC 8308 (`ext-info-s`, `server-sig-algs`), RFC 8709 (`ssh-ed25519`), `draft-ietf-sshm-mlkem-hybrid-kex-10` (`mlkem768x25519-sha256`), the `kex-strict-{c,s}-v00@openssh.com` extension (CVE-2023-48795 / Terrapin).
- Future policy: issue #42 (algorithm agility — what operators may add/remove and how migrations land).
