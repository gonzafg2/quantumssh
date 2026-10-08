# RFC 0012: Cut host authentication over to `ssh-mldsa44-ed25519` before `0.1.0`

- **Status:** Draft
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-10-08
- **Roadmap issue:** [`#109`](https://github.com/gonzafg2/quantumssh/issues/109) (Phase 2; the `0.1.0` freeze checklist)
- **Implements:** [RFC-0006](0006-post-quantum-host-key-signatures.md) — the "separate implementation RFC" its §Reference-level explanation requires once both adoption gates fire.
- **Docs updated in this PR:** `docs/threat-model.md` §5.2.3, §6.1, §7, §9 (status of the migration); `docs/plans/phase2-scoping.md` (freeze checklist item).
- **Implementation PR:** TBD — after acceptance and the three subsidiary ADRs in [§Subsidiary decisions](#subsidiary-decisions-separate-adrs).

## Summary

This RFC makes **one decision**: QuantumSSH's host authentication moves
from `ssh-ed25519` to the composite **`ssh-mldsa44-ed25519`**
([`draft-ietf-sshm-composite-sigs`](https://datatracker.ietf.org/doc/draft-ietf-sshm-composite-sigs/))
in a **single cut-over that lands before the `0.1.0` tag**. After the
cut, `server_host_key_algorithms` carries exactly one name,
`ssh-mldsa44-ed25519`; no release ever offers both algorithms side by
side.

Both of RFC-0006's adoption gates have fired, so the migration it
gated is now due. Because the identifier is now the WG's, this RFC also
records the final name (without the `@openssh.com` suffix RFC-0006
anticipated) and excludes the draft's second variant,
`ssh-mldsa87-p384`, which rests on ECDSA over a NIST curve. The primitive
crate, the negotiation-profile entry, and the interop client version are
subsidiary decisions, each delegated to its own ADR.

## Motivation

**The gates have fired.** RFC-0006 required two events before any
implementation:

1. *SSHM WG adoption of the draft.* `draft-ietf-sshm-composite-sigs-00`
   ("Post-Quantum Composite Signatures in SSH") became an SSHM working
   group document on **2026-08-22**, replacing the individual
   `draft-miller-sshm-composite-sigs` lineage RFC-0006 tracked.
2. *A stock OpenSSH release shipping it.* OpenSSH **10.4** (2026-07-06)
   added it as experimental, off by default, under
   `ssh-mldsa44-ed25519@openssh.com`. OpenSSH **10.6** (2026-10-06)
   enabled it under the final name: *"enable hybrid post-quantum
   ssh-mldsa44-ed25519 signature algorithm. Note that this no longer
   uses the "@openssh.com" vendor extension suffix that the previous
   experimental implementation used."*

RFC-0006 also resolved its parameter-level question by deferring to the
WG; the WG kept ML-DSA-44 for the Ed25519 pairing.

**The `0.1.0` freeze makes the timing one-way.**
[#109](https://github.com/gonzafg2/quantumssh/issues/109) and
[`docs/plans/phase2-scoping.md`](../plans/phase2-scoping.md) record that
cutting `0.1.0` turns the negotiation profile into a public compatibility
contract. The host-key algorithm is slot 2 of that profile
([ADR-0021](../adr/0021-phase-1-negotiation-profile.md)). Tagging `0.1.0`
on `ssh-ed25519` and migrating afterwards is exactly the unplanned
breaking change RFC-0006 §Motivation ("Why decide now, in Phase 2") set
out to avoid. Before the tag there is no deployed population to migrate:
the crates are at `0.0.1` and nothing has been released.

**The external clock moved.** This is context, not a gate. On
2026-03-31 Google Quantum AI published a zero-knowledge proof of quantum
circuits for the 256-bit elliptic-curve discrete logarithm at roughly
1,200 logical qubits — about a tenfold reduction on prior published
estimates — and an Oratomic estimate put P-256 at about 10,000
neutral-atom qubits. Cloudflare moved its full post-quantum target to
2029 and named long-lived *remote-login keys* as the first authentication
casualty; U.S. Executive Order 14412 (2026-06-22) sets 2031 for
post-quantum signatures in federal high-value systems. None of these
changes RFC-0006's trigger; they shrink the room for slipping it.

## Guide-level explanation

**What changes for an operator.** The host key becomes a composite key:
one SSH key type carrying an ML-DSA-44 public key and an Ed25519 public
key, where every host signature is a pair that a client must verify in
full. The operator generates it with OpenSSH ≥ 10.6:

```
ssh-keygen -t mldsa44-ed25519 -N '' -f /path/to/host_key
```

It is stored in the same unencrypted `openssh-key-v1` container
QuantumSSH reads today. The key is **new**: the draft forbids reusing
component key material between composite and non-composite keys, so the
Ed25519 half must not come from an existing `ssh-ed25519` host key. A
host-key file of any other type — including `ssh-ed25519` — makes the
server refuse to start, with an error that names the required type.

**What changes for clients.** The client must speak
`ssh-mldsa44-ed25519`: OpenSSH 10.6 or later, or any client implementing
the WG draft identifier. Older clients fail key exchange with "no
matching host key type". This is the same trade the project already
makes for key exchange, where `mlkem768x25519-sha256` excludes pre-9.9
OpenSSH.

**What changes for an existing test deployment.** A client that has the
old Ed25519 key for the host in `known_hosts` must remove it
(`ssh-keygen -R <host>`) and learn the composite key out of band. The
removal is part of the security story, not housekeeping: see
[§Why exactly one algorithm](#why-exactly-one-algorithm).

**What does not change.** User authentication stays `ssh-ed25519`
publickey ([ADR-0021](../adr/0021-phase-1-negotiation-profile.md));
post-quantum user keys are a separate decision (RFC-0006 §Future
possibilities). The key exchange is untouched.

**Cost.** Each handshake carries a 1,344-byte public key and a
2,484-byte signature (2,420 + 64) where Ed25519 used 32 and 64 — about
3.7 KB more, once per connection.

## Reference-level explanation

**Algorithm.** `ssh-mldsa44-ed25519` as specified by
`draft-ietf-sshm-composite-sigs-00` §4.1.1 and §4.2.2.1, which maps
`COMPSIG-MLDSA44-Ed25519-SHA512` from
[`draft-ietf-lamps-pq-composite-sigs`](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/):

- Public key blob: `string "ssh-mldsa44-ed25519"`,
  `string (mldsa_pk[1312] || ed25519_pk[32])`.
- Signature blob: `string "ssh-mldsa44-ed25519"`,
  `string (mldsa_sig[2420] || ed25519_sig[64])`.
- Message representative:
  `M' = "CompositeAlgorithmSignatures2025" || Label || len(ctx) || ctx || SHA512(M)`,
  where `Label = "COMPSIG-MLDSA44-Ed25519-SHA512"` and the SSH context
  `ctx` is the empty string. ML-DSA-44 signs `M'` with its FIPS 204
  context set to `Label`; Ed25519 signs `M'`.
- Private key: the two 32-byte seeds (`mldsa_seed || ed25519_seed`), with
  ML-DSA expanded by `ML-DSA.KeyGen_internal` (FIPS 204 §6.1).

**The verification invariant** is inherited unchanged from RFC-0006: a
composite signature is valid only if **both** component signatures
verify. QuantumSSH signs host authentications and, in its own tests,
verifies them; it never accepts a composite on one half.

**Negotiation.** `server_host_key_algorithms` is exactly:

```
ssh-mldsa44-ed25519
```

The superseding ADR for ADR-0021's slot 2 records the profile; this RFC
fixes that the slot holds one name.

**Not compiled in.**

- `ssh-mldsa87-p384` — the draft's other variant pairs ML-DSA-87 with
  ECDSA P-384, which is on the zero-legacy floor
  ([RFC-0011](0011-zero-legacy-floor-reconciliation.md)).
- `ssh-mldsa44-ed25519@openssh.com` — the experimental OpenSSH 10.4/10.5
  name. OpenSSH 10.6 requires those keys to be regenerated; QuantumSSH
  never accepted them.
- `ssh-mldsa44-ed25519-cert` — host certificates belong to the
  certificate-authentication lane
  ([RFC-0008](0008-ssh-certificate-authentication.md)), which has not
  adopted host certificates.

### Why exactly one algorithm

Offering `ssh-ed25519` next to the composite during a migration window
protects nobody, for two independent reasons.

1. **Stock clients would never pick the composite.** In OpenSSH 10.6
   (`myproposal.h`, tag `V_10_6_P1`) `ssh-mldsa44-ed25519` is the
   **last** entry of the default `HostKeyAlgorithms`, after
   `ssh-ed25519`. The client's `order_hostkeyalgs()` (`sshconnect2.c`)
   moves the algorithms for which `known_hosts` already holds a key to
   the front, keeping the configured order among them. With both
   offered, a stock client negotiates `ssh-ed25519` unless the only key
   it knows for the host is the composite one. A dual offer ships the
   composite without it being used.
2. **The classical path stays forgeable.** An adversary able to forge
   Ed25519 does not need to strip anything from a negotiation (the
   KEXINIT lists are bound into the exchange hash). It impersonates the
   server and offers `ssh-ed25519` alone, which every client still
   trusting the Ed25519 key accepts. What closes this is the client no
   longer trusting the Ed25519 key — so the server stops offering it,
   and the operator guidance requires removing it from `known_hosts`.

`ssh-ed25519` is not legacy ([RFC-0009](0009-zero-legacy-moving-frontier.md)
reserves that word for what NIST or IETF disallow), and nothing here
moves it onto the floor. The reason for one algorithm is the single
posture this project already keeps for key exchange, where
`mlkem768x25519-sha256` is the only method offered
([RFC-0005](0005-hybrid-pq-key-exchange.md)).

### Subsidiary decisions (separate ADRs)

Each is one decision in its own ADR citing this RFC. The implementation
PR does not merge until all three are Accepted.

1. **The ML-DSA primitive crate**, paralleling
   [ADR-0019](../adr/0019-phase-1-ml-kem-crate-rustcrypto.md). The
   leading candidate on 2026-10-07 is RustCrypto `ml-dsa` 0.1.1 (pure
   Rust, `unsafe_code = "forbid"` in the crate itself, ACVP and
   Wycheproof vectors). Facts the ADR must weigh: it has **no
   independent audit**; constant-time fixes merged in
   [RustCrypto/signatures#1386](https://github.com/RustCrypto/signatures/pull/1386)
   are not yet in a published release; and it depends on `signature`
   3.x while `ed25519-dalek` 2.x uses 2.x, which ties into the
   coordinated dalek 3.x bump already planned on
   [#109](https://github.com/gonzafg2/quantumssh/issues/109). The ADR
   also fixes the signing mode (hedged or deterministic); OpenSSH signs
   hedged, and byte-for-byte parity with OpenSSH is not required
   because verifiers accept either.
2. **The negotiation-profile entry** — an ADR superseding ADR-0021's
   slot 2 (`ssh-ed25519` → `ssh-mldsa44-ed25519`). ADR-0021 is
   Accepted and changes only by supersession.
3. **The interop client** — an ADR superseding
   [ADR-0034](../adr/0034-openssh-interop-client-pinned-to-image-build-snapshot.md)'s
   pin, because the [ADR-0020](../adr/0020-phase-1-ci-openssh-interop-gate.md)
   gate can only exercise the composite with OpenSSH ≥ 10.6. On
   2026-10-07 Debian ships `1:10.6p1-1` only in sid (accepted
   2026-10-06); forky has 10.5p1 and trixie-backports 10.3p1. Which base
   the gate uses is that ADR's decision.

### Ordering

The cut-over is a `0.1.0` freeze-checklist item: the tag does not happen
on `ssh-ed25519`. If a subsidiary ADR blocks — for example, the crate
decision waits for a release carrying the constant-time fixes — `0.1.0`
waits with it. Shipping the tag first is the alternative this RFC
rejects.

### Restatements the implementation PR updates

These describe the shipped posture, so they change when the code does,
not in this RFC's PR: `README.md` line 23 ("Ed25519 host keys") and
line 112 ("✅ Ed25519 host key"); `README.md` line 53, whose "Signatures
— host keys and user authentication — remain classical Ed25519" becomes
true of user authentication only; and `docs/threat-model.md` §6.1, the
"Ed25519 host keys" bullet and the host-key half of "Signatures are
classical, by deliberate sequencing". The migration-window example in
`CLAUDE.md` hard rule 3 and `AGENTS.md` (`ssh-ed25519` under RFC-0006)
stays valid: `ssh-ed25519` remains the user-authentication algorithm.

## Drawbacks

- **The client floor jumps to OpenSSH 10.6, released 2026-10-06.** No
  stable distribution ships it today. Until distributions catch up,
  users of QuantumSSH must run a recent client. For a pre-alpha project
  with no public release this is acceptable; the inverse — freezing
  `0.1.0` on the classical key — is not reversible.
- **An unaudited ML-DSA implementation enters host authentication.**
  The composite contains the risk: a forgery still needs a valid
  Ed25519 signature, so a defect confined to the ML-DSA half degrades
  host authentication to Ed25519 alone — today's posture — rather than
  breaking it. A defect in the composition itself (an accidental OR in
  verification, or shared key material) would not be contained, which is
  why the AND invariant and fresh key generation are normative above.
- **`0.1.0` now depends on two external clocks**: the crate's maturity
  and a pinnable OpenSSH 10.6 for the interop gate.
- **Existing test deployments need a manual re-trust step** (remove the
  Ed25519 `known_hosts` entry, learn the composite key).
- **No SSHFP for the composite yet.** The draft registers the algorithm
  name in the SSH Public Key Algorithm Names registry but assigns no
  SSHFP algorithm number, and this project will not invent one. Until
  one is assigned, operators distribute the host key through
  `known_hosts` or another out-of-band channel; the SHA-256 fingerprint
  remains as compact as Ed25519's.
- **Not SUF-CMA.** The draft notes the composite is EUF-CMA but not
  strongly unforgeable. SSH host authentication signs a per-session
  exchange hash and does not rely on SUF-CMA, so this costs nothing
  here; it is recorded so a future use (for example, signed artefacts)
  does not assume otherwise.
- **The draft is at `-00`.** The identifier is the WG's, but the
  encoding can still change before it becomes an RFC. A change before
  `0.1.0` is absorbed by the implementation; after `0.1.0` it goes
  through the [RFC-0007](0007-cryptographic-primitive-migration-procedure.md)
  procedure.

## Rationale and alternatives

- **Offer both algorithms for a window, remove `ssh-ed25519` later
  through RFC-0007.** Rejected: stock clients would keep negotiating
  `ssh-ed25519` (see [§Why exactly one algorithm](#why-exactly-one-algorithm)),
  the classical path would stay open for the whole window, and `0.1.0`
  would freeze `ssh-ed25519` into the public profile.
- **Offer both and implement OpenSSH's `hostkeys-00@openssh.com`
  (`UpdateHostKeys`)** so clients learn the composite key and later drop
  the Ed25519 one automatically. Rejected for now: it adds a post-auth
  protocol extension to migrate a population that does not exist yet.
  Recorded under Future possibilities for later rotations.
- **Tag `0.1.0` on `ssh-ed25519`, migrate afterwards.** Rejected:
  RFC-0006 §Motivation; the freeze makes it a breaking change.
- **Keep `ssh-ed25519` behind an opt-in flag for older clients.**
  Rejected: it reopens the forgeable path per deployment and breaks the
  single-posture discipline of the key-exchange profile. The objection
  is about posture, not the floor — `ssh-ed25519` is not legacy.
- **Wait for the draft to become an RFC.** Rejected: RFC-0006 chose WG
  adoption as the identifier-stability gate on purpose, and waiting for
  publication would push the cut past `0.1.0`.
- **Pure ML-DSA, or `ssh-mldsa87-p384`.** Rejected: RFC-0006 fixed
  hybrid-only; the P-384 variant is on the zero-legacy floor.

## Prior art

- [`draft-ietf-sshm-composite-sigs-00`](https://datatracker.ietf.org/doc/draft-ietf-sshm-composite-sigs/)
  (SSHM WG, 2026-08-22) — the construction and wire format.
- [`draft-ietf-lamps-pq-composite-sigs`](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/)
  — `COMPSIG-MLDSA44-Ed25519-SHA512`, the underlying scheme.
- [OpenSSH release notes](https://www.openssh.org/releasenotes.html):
  10.4 (experimental, 2026-07-06) and 10.6 (enabled, 2026-10-06);
  `myproposal.h`, `sshconnect2.c` and `ssh-mldsa-eddsa.c` at tag
  `V_10_6_P1` of
  [openssh-portable](https://github.com/openssh/openssh-portable).
- [RFC 10042](https://datatracker.ietf.org/doc/rfc10042/) (2026-08-31) —
  the published form of the hybrid ML-KEM key exchange for SSH this
  project already runs; the KEX-side precedent for a single hybrid
  method.
- [RFC-0005](0005-hybrid-pq-key-exchange.md) — the project's
  single-posture precedent.
- [Cloudflare, "Cloudflare targets 2029 for full post-quantum security"](https://blog.cloudflare.com/post-quantum-roadmap/)
  (2026-04-07) and [Executive Order 14412](https://www.federalregister.gov/documents/2026/06/25/2026-12909/securing-the-nation-against-advanced-cryptographic-attacks)
  — the external timeline context in Motivation.

## Unresolved questions

- **Crate readiness** — whether the crate ADR requires a release
  carrying RustCrypto/signatures#1386 before implementation. Decided in
  subsidiary ADR 1.
- **Interop base** — sid at a snapshot, or forky once `10.6p1` migrates.
  Decided in subsidiary ADR 3.
- **SSHFP** — whether and when an SSHFP algorithm number is assigned for
  composite keys. Tracked; no project-defined codepoint in the meantime.

## Future possibilities

- `hostkeys-00@openssh.com` (`UpdateHostKeys`) to rotate host keys after
  `0.1.0` without a manual re-trust step.
- Composite keys for **user authentication** — a separate decision with
  its own urgency profile (RFC-0006).
- **Host certificates** (`ssh-mldsa44-ed25519-cert`) through RFC-0008's
  lane.
- A post-quantum DNSSEC chain for SSHFP anchoring, once both an SSHFP
  number and ML-DSA DNSSEC (`draft-westerbaan-dnssec-mldsa`) reach the
  root.
