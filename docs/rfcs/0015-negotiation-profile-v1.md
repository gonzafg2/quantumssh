# RFC 0015: Negotiation profile version 1 — the `SSH_MSG_KEXINIT` contract `0.1.0` freezes

- **Status:** Accepted (2026-10-31)
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-10-29
- **Roadmap issue:** [#109](https://github.com/gonzafg2/quantumssh/issues/109)
- **Implementation PR:** TBD

## Summary

Cutting `0.1.0` turns the server's `SSH_MSG_KEXINIT` offer into a
public compatibility contract: clients, scanners and configuration
guides will depend on it. This RFC freezes that offer as **negotiation
profile version 1**:

- **The lists** are [ADR-0021](../adr/0021-phase-1-negotiation-profile.md)'s,
  unchanged, except the server host key, which
  [RFC-0012](0012-composite-host-key-cutover.md) already moves to
  `ssh-mldsa44-ed25519` before the tag.
- **The rules** say which later changes are additive and which break
  the contract.
- **The preconditions** list what must hold before the tag, beyond the
  lists themselves.

It is the second item of the `0.1.0` freeze checklist
([`docs/plans/phase2-scoping.md`](../plans/phase2-scoping.md)). The
review behind it found nothing in ADR-0021 to change, so this RFC
changes no algorithm.

## Motivation

ADR-0021 fixed the Phase-1 profile and says, in its Consequences, that
any change to it is "a profile change that must supersede this ADR and
update the interop fixtures together". It does not say which changes a
deployed client survives. Once a release exists, that distinction is
the contract: removing a name can lock clients out, while adding one
cannot.

A review on 2026-10-29 checked the profile against the code, the
standards and the current OpenSSH:

- **The code matches ADR-0021 list by list**
  (`crates/quantumssh-core/src/kex.rs`, `KEX_LIST` to
  `COMPRESSION_LIST`, pinned by `our_kexinit_matches_the_adr_0021_profile`).
- **The KEX is now an RFC.** `draft-ietf-sshm-mlkem-hybrid-kex`
  became [RFC 10042](https://www.rfc-editor.org/rfc/rfc10042)
  (Informational, August 2026). The method name, `K = HASH(K_PQ ‖ K_CL)`
  over fixed-length byte arrays (§2.4), and `K` encoded as a `string` in
  `H` and in key derivation (§2.5) all match the implementation
  (`kex.rs` `exchange_hash`, `derive_key`). The RFC publishes no test
  vectors, so [#216](https://github.com/gonzafg2/quantumssh/issues/216)'s
  golden vectors are still needed.
- **IETF names are coming for three pre-standard names.** Working-group
  and individual drafts register standard names for algorithms the
  profile already offers under OpenSSH's vendor names:
  - `kex-strict-c` and `kex-strict-s` (`draft-ietf-sshm-strict-kex-02`).
    Its §3.1 says an implementation SHOULD offer both forms, and MUST NOT
    enable strict KEX when one side offers only the standard name and
    the other only the pre-standard one;
  - `chacha20-poly1305` (`draft-ietf-sshm-chacha20-poly1305-04`), defined
    as identical to `chacha20-poly1305@openssh.com`;
  - `aes256-gcm` (`draft-miller-sshm-aes-gcm-01`), identical to
    `aes256-gcm@openssh.com`.

  None of the three is registered yet.
- **OpenSSH 10.4 tightened re-keying.** It disconnects a peer that sends
  non-KEX messages during a post-authentication key re-exchange. The
  server already stops sending channel data from its KEXINIT to its
  NEWKEYS ([ADR-0026](../adr/0026-phase-1-rekeying-policy.md)'s
  half-duplex window; `channel.rs` holds output while `rekey_active()`).
  But the interop gate's client is OpenSSH 10.0p2
  ([ADR-0034](../adr/0034-openssh-interop-client-pinned-to-image-build-snapshot.md)),
  older than the rule, so no test exercises it.
- **Nothing else in OpenSSH 10.1–10.6 touches the profile.** No release
  renames or removes a KEX, cipher, MAC or marker the profile offers.
  10.6's compression change does not apply, since the profile offers
  only `none`.

## Guide-level explanation

Version 1 starts at `0.1.0`. The earlier pre-alpha release, `0.0.1`,
offered `ssh-ed25519` as its host key and carries no compatibility
promise, so §1's host-key entry is the version-1 starting point, not a
removal under §3. A client that connects to `0.1.0` will keep
connecting to every later release with `negotiation profile version 1`. A later release may add
names to a list, so a client gains choices, but it never removes a name
the version-1 lists carry. A release that must remove one, for example
because a primitive is disallowed (RFC-0009), says so as version 2, with
its own RFC and a CHANGELOG migration note.

## Reference-level explanation

### 1. The version-1 lists

The server's initial `SSH_MSG_KEXINIT`, slot by slot:

| Slot | Version 1 | Source |
|---|---|---|
| `kex_algorithms` | `mlkem768x25519-sha256`, `kex-strict-s-v00@openssh.com` | ADR-0021; the method is RFC 10042 |
| `server_host_key_algorithms` | `ssh-mldsa44-ed25519` | RFC-0012, superseding ADR-0021's slot 2 |
| `encryption_algorithms_*` | `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com` | ADR-0021 |
| `mac_algorithms_*` | `hmac-sha2-512-etm@openssh.com`, nominal, never used under AEAD | ADR-0021 |
| `compression_algorithms_*` | `none` | ADR-0021 |
| `languages_*` | empty | ADR-0021 |

A re-key KEXINIT carries the same lists without the strict-KEX marker,
as ADR-0021 and the strict-KEX extension specify.

### 2. The version-1 behaviour

These ADR-0021 and ADR-0026 rules are part of the contract, because a
client observes them:

- **`mlkem768x25519-sha256` is the only key exchange.** A client that
  does not offer it is disconnected with
  `SSH_DISCONNECT_KEY_EXCHANGE_FAILED` (3). There is no fallback.
- **Strict KEX is required.** A client whose initial KEXINIT does not
  offer a strict-KEX marker the server also offers is disconnected with
  code 3.
- **`first_kex_packet_follows` is false** in the server's KEXINIT.
- **`SSH_MSG_EXT_INFO`** is sent once, after the first NEWKEYS, only to
  a client that offered `ext-info-c`. It carries `server-sig-algs` with
  the accepted user-authentication algorithms, which are `ssh-ed25519`
  in version 1.
- **Re-keying is half-duplex.** From its own KEXINIT to its NEWKEYS, the
  server sends only what RFC 4253 §7.1 allows: transport-layer generic
  messages (1–19, never `SSH_MSG_SERVICE_REQUEST` or `_ACCEPT`),
  algorithm negotiation (20–29, no second KEXINIT) and key-exchange
  messages (30–49). OpenSSH 10.4 enforces this rule. The channel layer
  sends no data, window adjustment or channel reply in the window, and
  it defers the peer's connection-layer messages until the re-key ends
  (`channel.rs`, `rekey_active()`; ADR-0026).

### 3. Compatibility rules

**Additive changes keep version 1.** A client of version 1 still
connects:

- **adding a name to a list**, which gives clients one more choice;
- **adding a standard name next to a pre-standard one** for the same
  algorithm, under §4;
- **accepting an additional client marker**, such as `kex-strict-c`,
  under §4;
- **adding a user-authentication algorithm** to `server-sig-algs`;
- **reordering a list.** Selection follows the client's order (RFC 4253
  §7.1), so order changes nothing a client can observe. The order is
  still kept stable, as ADR-0021 says.

"Additive" describes the wire contract, not the size of the change.
The negotiation code returns the single entries `KEX_ALGORITHM` and
`HOST_KEY_LIST`, and the wrong-guess skip for `first_kex_packet_follows`
compares against them (`kex.rs`). Adding a name to either list therefore
also changes selection and that skip, which run before authentication
and get the pre-authentication review rules.

**Breaking changes require version 2,** with their own RFC and a
CHANGELOG migration note:

- removing a name from any list, `ssh-mldsa44-ed25519` included;
- making an optional behaviour mandatory, or a mandatory one stricter,
  in a way a version-1 client can fail. Requiring a newer strict-KEX
  marker that clients do not offer is an example;
- changing a §2 behaviour a client observes.

**Governance is unchanged by these rules.** A new key exchange, cipher
or host-key algorithm is a change to the default cryptographic profile,
and it needs an RFC even when it is additive (`CLAUDE.md`, "RFC vs ADR
vs plain PR"). Only §4's aliases, which add no algorithm, go through an
ADR.

### 4. Standard names for pre-standard algorithms

RFC 4251 §6 reserves names without an at-sign for assignment by IETF
consensus. Until a standard name is registered, the server offers and
accepts only the vendor names of §1. Once an IETF document registers a
standard name for an algorithm the profile offers, an ADR adds it, as
an additive change:

- **Ciphers** (`chacha20-poly1305`, `aes256-gcm`): offered next to the
  `@openssh.com` names, which stay.
- **Strict KEX** (`kex-strict-c`, `kex-strict-s`): the server offers
  both server markers. It enables strict KEX when the client offers the
  matching form, standard or pre-standard. It never pairs forms
  across, per `draft-ietf-sshm-strict-kex` §3.1. Requiring strict KEX
  then means requiring either matching pair. When a client offers both
  forms, both pairs match and the protocol changes are the same, so
  which pair enabled it is not recorded. The audit log carries no
  marker field (RFC-0014).
- **The host key** (`ssh-mldsa44-ed25519`) follows the name OpenSSH 10.6
  uses for `draft-ietf-sshm-composite-sigs`, which is not yet
  registered. If the registered name differs, it is added as an alias
  next to the version-1 name, which stays.

### 5. Preconditions for the `0.1.0` tag

- **RFC-0012's cut-over has landed,** so `server_host_key_algorithms` is
  `ssh-mldsa44-ed25519` (§1).
- **The interop gate runs OpenSSH ≥ 10.6 and passes its re-key step,**
  as RFC-0012's subsidiary ADR 3 already requires for the composite host
  key. The `RekeyLimit` step on that client is the first test of
  OpenSSH 10.4's rule (§2), which the 10.0p2 client cannot exercise, so
  a green run of that step on that client is the exit criterion.
- **The citations name RFC 10042.** The threat model, the code comments
  and the operator-facing text cite the RFC instead of the draft.
  Accepted ADRs and RFCs keep their text, as the project does not edit
  them in place.

### 6. Changes to accepted decisions

None. ADR-0021's decisions stand. This RFC makes them a versioned
contract and adds §3–§5. RFC-0012 already supersedes ADR-0021's slot 2
through its own subsidiary ADR, and this RFC only records the result in
§1.

## Drawbacks

- **Version 1 needs OpenSSH 10.6 or later.** No earlier release offers
  the name `ssh-mldsa44-ed25519` (10.4 and 10.5 had only the
  experimental `@openssh.com` form, off by default), so after the tag an
  older client never connects (RFC-0012's Drawbacks).
- **Version 1 has one key exchange.** A client that cannot do
  `mlkem768x25519-sha256` never connects, by design (README non-goal).
  Adding `mlkem1024nistp384-sha384` later is additive, but it needs an
  RFC (§3).
- **The IETF names will arrive after the tag.** Until §4 applies, a
  future client that offers only `kex-strict-c` is refused, because
  strict KEX is required. No such client is known, and OpenSSH offers
  the pre-standard markers.
- **The MAC entry stays nominal.** Removing it later would be breaking
  under §3, so version 1 keeps ADR-0021's documented honesty gap.

## Rationale and alternatives

### Alternative 1: an ADR instead of an RFC

The profile would be frozen faster. But it is a public contract with
compatibility rules, the same kind of decision RFC-0014 made for the
audit log, and that lane is an RFC (`CLAUDE.md`).

### Alternative 2: offer the standard names now

`draft-ietf-sshm-strict-kex` recommends offering both forms. But the
names are not registered, and RFC 4251 §6 reserves them for IETF
assignment. Offering them early risks a collision if the registered
definition differs. §4 adds them when they are registered.

### Alternative 3: drop the nominal MAC before freezing

It would close ADR-0021's honesty gap. Rejected for the reason
ADR-0021's Alternative 4 gives: an empty MAC name-list is a robustness
risk against peers whose negotiation code does not special-case it.

### Alternative 4: freeze nothing

Each release could change the profile at will. That leaves clients and
scanners without a guarantee, which is what a release is for.

## Prior art

- **RFC 9142** updates SSH key exchange recommendations by adding and
  deprecating methods over time, which is the additive-then-removal
  pattern §3 encodes.
- **OpenSSH** keeps a vendor name offered next to the IETF name
  registered for the same method later, as with
  `curve25519-sha256@libssh.org` and `curve25519-sha256`.

## Unresolved questions

- **When the IETF names are registered,** which RFC or registry action
  triggers §4 for each, and whether the server then prefers the
  standard form first.
- **ML-KEM-1024** ([#42](https://github.com/gonzafg2/quantumssh/issues/42))
  stays outside version 1. Adding it would be an RFC-gated additive
  change.

## Future possibilities

- A version-2 profile that retires a pre-standard name once its
  standard form is universally offered.
- Golden KEXINIT vectors in the interop gate that pin version 1 byte
  for byte.
