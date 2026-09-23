# RFC 0011: One zero-legacy floor, stated once — MANIFIESTO #3 reconciliation

- **Status:** Draft
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-09-23
- **Roadmap issue:** [`#109`](https://github.com/gonzafg2/quantumssh/issues/109) (Phase 2, the current roadmap phase); the reconciliation [RFC-0009](0009-zero-legacy-moving-frontier.md) §Scope boundary deferred
- **Amends:** MANIFIESTO commitment #3 ("Cero legacy") — the fixed list only; the moving frontier RFC-0009 added stays as it is.
- **Implementation PR:** this RFC's own PR (docs only: `MANIFIESTO.es.md`, `docs/threat-model.md` §6.1)

## Summary

This RFC makes **one decision**: the permanent floor of commitment #3 is the
list the project already enforces — **SSH-1, RSA (any size), DSA, ECDSA over
NIST curves, CBC modes, `diffie-hellman-group1-sha1` and
`diffie-hellman-group14-sha1`, `ssh-rsa`, password authentication, and
compression — none of it compiled in, not merely configured off**. It writes
that list into the manifesto, whose commitment #3 still carries the founding
wording (`RSA-1024`, `group1` only, password auth only "en el perfil por
defecto"), and into the one restatement in `docs/threat-model.md` §6.1 that
still disagrees. It does not touch the moving frontier
[RFC-0009](0009-zero-legacy-moving-frontier.md) layered on top of the list, and
it changes no code: the binary has enforced this floor since Phase 1.

## Motivation

**The floor is stated in five places and they do not agree.** Since PR
[#51](https://github.com/gonzafg2/quantumssh/pull/51) (2026-06-10) `CLAUDE.md`
hard rule #3 has told every reviewer — human and automated — to reject RSA, DSA,
ECDSA-NIST, CBC, `group1/14-sha1`, `ssh-rsa`, password authentication and
compression, "not merely configured off". `AGENTS.md` carries the same list.
PR [#159](https://github.com/gonzafg2/quantumssh/pull/159) (2026-09-22) brought
`README.md` "Zero legacy" to it. But the two documents this repository calls
authoritative for the commitment say something narrower:

- `MANIFIESTO.es.md` #3: "Sin RSA-1024" (so RSA-2048+ is not named), only
  `diffie-hellman-group1-sha1`, "Sin autenticación por contraseña **en el perfil
  por defecto**" (so a non-default profile with passwords is left open), and no
  mention of ECDSA-NIST, `ssh-rsa` or compression.
- `docs/threat-model.md` §6.1 "No legacy primitives": `RSA-1024` again, and no
  mention of ECDSA-NIST, password authentication or compression.

**RFC-0009 saw the gap and deferred it on purpose.** Its §Scope boundary reads:
"Reconciling any gaps between the manifesto prose and CLAUDE.md's list (e.g.
`RSA-1024` vs all RSA, password 'en el perfil por defecto' vs never-compiled) is
a **separate** concern, not opened here." This RFC is that concern.

**The gap already cost a PR round.** PR
[#164](https://github.com/gonzafg2/quantumssh/pull/164) tried to align the
manifesto as a docs correction; all three automated reviewers (Codex, opencode,
claude-review) blocked the hunk for the same reason — `CLAUDE.md` puts anything
that "contradicts or refines a `README.md` / `MANIFIESTO.es.md` commitment" in
the RFC lane. The hunk was dropped; the decision belongs here.

**What goes wrong if the founding text stays as it is.** A reader of the
manifesto can conclude that RSA-2048 host keys or a password-enabled profile are
compatible with the project's commitments. Neither is: commitment #2
(post-quantum by default) makes *every* RSA key size classical-only and
Shor-breakable, not just 1024 bits; and the code has no password path at all
(see below). The founding text should not promise less than the project already
delivers and reviews against.

## Guide-level explanation

Commitment #3 keeps its shape — a fixed list (the **floor**) plus the
standards-defined frontier RFC-0009 added on top. This RFC only fixes the list.
After it, "is X legacy?" is answered by one list, identical wherever it is
stated (`MANIFIESTO.es.md`, `README.md`, `docs/threat-model.md` §6.1,
`CLAUDE.md`, `AGENTS.md`), plus "has NIST or the IETF disallowed X?" from
RFC-0009.

Three items change meaning, not just wording:

- **`RSA-1024` → RSA.** The founding text named the key size that was already
  broken classically. Under commitment #2 the whole family is legacy in the KEX
  and signature roles, regardless of size; the code accepts only `ssh-ed25519`
  user keys (`crates/quantumssh-core/src/auth.rs`, `AuthError::UnsupportedKeyType`)
  and offers only `mlkem768x25519-sha256` ([ADR-0021](../adr/0021-phase-1-negotiation-profile.md)).
- **Password authentication: "en el perfil por defecto" → never.** The
  qualifier implied a second profile could exist. None does and none is
  planned: the server answers any non-`publickey` method with failure
  (`crates/quantumssh-core/tests/accept.rs`, `auth_rejects_non_publickey_method`
  sends `password` and asserts the rejection), and `CLAUDE.md` states
  "Public-key authentication only".
- **Compression, ECDSA-NIST, `ssh-rsa`, `group14-sha1`: named.** They were
  already excluded in practice — `COMPRESSION_LIST` is `"none"`
  (`crates/quantumssh-core/src/kex.rs`, ADR-0021 §7–8, with a test that a
  zlib-only client is rejected), and no NIST-curve or RSA code exists — but the
  manifesto never said so.

"Not compiled in" is the operative phrase and it is literal: there is no
feature flag, configuration key, or non-default profile that turns any of these
on, because the code that would implement them does not exist in the binary.

## Reference-level explanation

### The amendment (the decision)

`MANIFIESTO.es.md` commitment #3's opening list becomes (Spanish, matching the
manifesto; the RFC-0009 passage that follows it is unchanged):

> **Cero legacy.** Sin SSH-1. Sin RSA. Sin DSA. Sin ECDSA sobre curvas NIST.
> Sin modos CBC. Sin `diffie-hellman-group1-sha1` ni
> `diffie-hellman-group14-sha1`. Sin `ssh-rsa`. Sin autenticación por
> contraseña. Sin compresión. Nada de eso se compila: no es que venga apagado,
> es que no existe en el binario
> ([RFC-0011](0011-zero-legacy-floor-reconciliation.md)). Nos rehusamos a
> heredar 25 años de *"sigue ahí porque el router de alguien lo necesita"*. […]

### Restatements this RFC's PR aligns

- `docs/threat-model.md` §6.1 "No legacy primitives": `RSA-1024` → RSA; adds
  ECDSA over NIST curves, password authentication, compression, and "none of it
  compiled in". The RFC 9142 anchor stays.
- `README.md` "Zero legacy", `CLAUDE.md` hard rule #3, `AGENTS.md`: already
  carry the list; untouched.

### What this RFC does not touch

- **The moving frontier.** RFC-0009's passage in the manifesto and its
  deprecation-vs-disallowance rule stay word for word; this RFC edits only the
  list that passage sits on top of.
- **The classical-signature interim.** `ssh-ed25519` under
  [RFC-0006](0006-post-quantum-host-key-signatures.md) is unaffected — it is
  neither on the floor nor disallowed.
- **`CLAUDE.md`.** It stays a restatement, not the authority; the manifesto is
  the commitment (RFC-0009 §Motivation records why that ordering matters).
- **Code and configuration.** No code changes; the Phase-2 configuration file
  ([RFC-0010](0010-configuration-file.md)) gains no knob from this RFC.

### Compatibility

None at the protocol level: the offered algorithm sets do not change. A client
that needs anything on the floor already fails to connect today; the manifesto
now says so.

## Drawbacks

- **Amending founding text a second time.** RFC-0009 noted that touching the
  manifesto "should be rare". Justified: this is the reconciliation RFC-0009
  itself scheduled, and the alternative is a founding text that promises less
  than the code and the review rule enforce.
- **A longer list can read as an invitation to keep editing it.** It is not:
  the floor is permanent, and everything that becomes legacy from now on enters
  through RFC-0009's frontier, not by re-enumeration. This RFC expects to be the
  last edit of the list.

## Rationale and alternatives

- **Write the enforced list into the manifesto and the threat model (this
  RFC).** Chosen: one list, stated identically everywhere, matching the binary.
- **Leave the manifesto's founding wording.** Rejected: it contradicts the
  code, `CLAUDE.md` and `README.md`, and it was already the reason three
  reviewers blocked #164's hunk.
- **Narrow `README.md` / `CLAUDE.md` / `AGENTS.md` back to the founding
  wording.** Rejected: it would re-admit RSA-2048+ and a password profile on
  paper, against commitment #2 and against code that has never had them.
- **Make `CLAUDE.md` the authority for the list.** Rejected: the same
  governance inversion RFC-0009 §Motivation records from PR #93 — the manifesto
  is the commitment; guidance files restate it.

**Impact of not doing this:** every future manifesto-adjacent docs PR trips the
same reviewer block, and the founding text keeps saying `RSA-1024` in a project
whose second commitment is post-quantum by default.

## Prior art

- [RFC-0009](0009-zero-legacy-moving-frontier.md) — the frontier layered on the
  list; its §Scope boundary names this reconciliation as the deferred separate
  concern.
- [ADR-0021](../adr/0021-phase-1-negotiation-profile.md) — the negotiation
  profile that implements the floor on the wire (single hybrid KEX, AEAD-only,
  compression `none`).
- PR [#51](https://github.com/gonzafg2/quantumssh/pull/51) (`CLAUDE.md` rule #3),
  PR [#159](https://github.com/gonzafg2/quantumssh/pull/159) (`README.md`
  alignment) and the PR [#164](https://github.com/gonzafg2/quantumssh/pull/164)
  review threads that routed the manifesto edit here.
- OpenSSH's own trajectory: `ssh-rsa` signatures disabled by default in 8.8
  (2021), DSA removed in 10.0 (2025) — the ecosystem's floor has moved past the
  founding wording too.

## Unresolved questions

- None blocking. The comment period (`docs/rfcs/README.md` §How the process
  works, step 5) applies; the project lead may shorten it on the PR since the
  policy itself has been in force since #51 and only the founding text lags.

## Future possibilities

- None specific. Additions to what is forbidden arrive through RFC-0009's
  frontier; changes to what is *offered* stay RFC-gated one at a time
  (RFC-0005/0006, procedure in RFC-0007).
