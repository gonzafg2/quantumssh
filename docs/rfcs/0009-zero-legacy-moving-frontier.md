# RFC 0009: "Zero legacy" is a standards-defined moving frontier — MANIFIESTO #3 amendment

- **Status:** Accepted (2026-07-18 — comment period through 2026-07-16 closed by lazy consensus per [`docs/rfcs/README.md`](README.md) §5, no substantive objection)
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-07-02
- **Roadmap issue:** deferred from [RFC-0007](0007-cryptographic-primitive-migration-procedure.md) §Future possibilities; research recorded in [`#42`](https://github.com/gonzafg2/quantumssh/issues/42)
- **Amends:** MANIFIESTO commitment #3 ("Cero legacy").

## Summary

This RFC makes **one shape-determining decision**: it refines MANIFIESTO
commitment #3 ("Cero legacy") so that legacy is **not only the fixed list** the
prose names, but also **anything NIST or IETF has *disallowed*** — a
standards-defined moving frontier on top of the existing list. It fixes the one
distinction the fixed-list wording cannot express: *deprecation* (which merely
triggers a managed migration) versus *disallowance* (which is the legacy line).
It scopes deliberately narrow — it does **not** re-enumerate or re-authority the
existing blocklist, touch CLAUDE.md, or reopen the classical-signature interim;
those are separate concerns. It makes no code change and amends only one existing
document — `MANIFIESTO.es.md`; the *how* of a migration is
[RFC-0007](0007-cryptographic-primitive-migration-procedure.md), and this RFC is
the *what-counts-as-legacy* the manifesto now states.

## Motivation

**The zero-legacy paradox.** MANIFIESTO #3 forbids legacy, but *today's modern
algorithm is tomorrow's legacy*: `mlkem768x25519-sha256` and `ssh-ed25519` are
current now and will be deprecated eventually. Stated as a **frozen blocklist**,
"zero legacy" cannot express this — the moment NIST disallows something not on
the list, the commitment is silent, and the list itself never ages out anything.
A project whose motto is "SSH for the next 30 years" needs a commitment that
*stays true* as the standards move, not one that quietly goes stale.

**Why a dedicated RFC.** [RFC-0007](0007-cryptographic-primitive-migration-procedure.md)
(the migration *procedure*) described this moving-frontier notion but deliberately
did **not** amend the manifesto — folding a founding-commitment change into a
procedure RFC bundled two decisions and (in review) inverted the governance
hierarchy by trying to make CLAUDE.md normative. Amending a MANIFIESTO commitment
is the highest RFC lane and deserves its own decision. This is that decision.

**What breaks without it.** RFC-0006 (Accepted, immutable) keeps `ssh-ed25519`
through the 2030–2035 window, and RFC-0007's live-only class waits until the NIST
IR 8547 *disallow* date. Under a literal "deprecated = legacy = forbidden"
reading, Ed25519 would be simultaneously forbidden and permitted in 2030–2035 —
the manifesto would contradict two immutable documents. The deprecation/disallow
distinction is not pedantry; it is what keeps the commitment coherent with the
rest of the corpus.

## Guide-level explanation

Commitment #3 keeps its fixed list — those algorithms are barred permanently and
are the **floor**. What changes is that the list is no longer the *whole*
definition of legacy. On top of the floor:

- An algorithm becomes **legacy** — must be gone, never compiled in — once NIST
  or IETF **disallows** it. **Deprecation** is the earlier signal that *starts*
  the migration clock (per RFC-0007's procedure); it does not by itself make the
  algorithm legacy. So a deprecated-but-not-yet-disallowed primitive (Ed25519 in
  the 2030–2035 window) is legitimately still in use while its managed migration
  runs.
- A classical algorithm participating in a **hybrid** is not made legacy by that
  participation — e.g. X25519 inside the `mlkem768x25519-sha256` KEX. Zero-legacy
  forbids classical-*only* where a hybrid is the established mechanism; it does
  not forbid classical-*plus*-PQ. (This says nothing about the classical
  *signature* interim — RFC-0006 governs that, and this RFC does not reopen it.)

For a reader, the commitment now answers "is X legacy?" with "is X on the list,
or has a standards body disallowed it?" — a question with a checkable answer that
does not depend on the manifesto being re-edited every time the field moves.

## Reference-level explanation

### The amendment (the decision)

`MANIFIESTO.es.md` commitment #3 gains a short passage after its fixed list. The
prose (Spanish, matching the manifesto) reads:

> Y "legacy" no es solo esta lista fija: sobre ella, es legacy todo primitivo
> criptográfico que NIST o IETF haya **prohibido** (*disallowed*). La
> **deprecación** de un algoritmo activa su migración gestionada; la
> **prohibición** marca la línea que no cruzamos. (Que un algoritmo clásico
> participe de un híbrido —como X25519 en el KEX— no lo vuelve legacy: cero
> legacy prohíbe lo clásico-*solo* donde el híbrido es el mecanismo, no lo
> clásico-*más*-PQ.) La definición está en
> [RFC-0009](0009-zero-legacy-moving-frontier.md); el procedimiento de
> migración, en [RFC-0007](0007-cryptographic-primitive-migration-procedure.md).

The amendment adds the moving frontier *on top of* the existing list; it does
not restate, broaden, or re-authority the list itself.

### Scope boundary (what this RFC deliberately does not touch)

To keep the decision single, this RFC does **not**:

- **Re-enumerate or re-authority the existing blocklist.** Whatever the floor is
  today (per the manifesto prose and CLAUDE.md hard rule #3) stays exactly as it
  is; this RFC only adds the disallow-frontier on top. Reconciling any gaps
  between the manifesto prose and CLAUDE.md's list (e.g. `RSA-1024` vs all RSA,
  password "en el perfil por defecto" vs never-compiled) is a **separate**
  concern, not opened here.
- **Touch CLAUDE.md** or relocate authority between documents.
- **Reopen the classical-signature interim** — RFC-0006 governs `ssh-ed25519`
  host/user keys until its gates fire; this RFC's frontier does not change that.

The one external anchor: [RFC 9142](https://www.rfc-editor.org/rfc/rfc9142.html)
(the IETF's maintained SSH-KEX MUST-NOT / SHOULD-NOT lists, already cited in
threat-model §6.1) is the precedent that "legacy" is a standards-body-maintained
moving target. This RFC makes no code change and amends only `MANIFIESTO.es.md`;
the migration *mechanism* stays in RFC-0007.

## Drawbacks

- **Amending a founding commitment is heavy.** Touching the manifesto is not
  routine and should be rare. Justified: the paradox is real (a frozen list
  cannot stay zero-legacy for 30 years), and the change *strengthens* the
  commitment — it makes it track the standards rather than go stale — rather than
  retreating from it.
- **Risk of reading as crypto-agility licence.** "The frontier moves" could be
  misread as endorsing casual algorithm churn (against commitment #4). Guarded:
  the floor is permanent, and the frontier moves in one direction in practice —
  standards disallow *more* over time, essentially never less (an un-disallow is
  vanishingly rare; see Future possibilities). Crucially, the frontier only
  governs what is *forbidden*; **what is *offered* never widens here** — adding or
  swapping any offered algorithm stays RFC-gated one-at-a-time (RFC-0005/0006,
  procedure in RFC-0007). Even the rare un-disallow would not re-introduce an
  algorithm into the offered set; it would merely stop *forbidding* it, and
  offering it again would still require its own RFC.

## Rationale and alternatives

- **Amend commitment #3 to the floor-plus-frontier definition (this RFC).**
  Chosen: keeps "zero legacy" true over 30 years, resolves the paradox at its
  source (the commitment text), and is coherent with RFC-0006/0007.
- **Leave #3 as a fixed list.** Rejected: it goes stale the first time NIST
  disallows something not listed, and under a literal reading it already
  contradicts RFC-0006 (Ed25519 in 2030–2035). A commitment that contradicts an
  immutable RFC is worse than one that is merely incomplete.
- **Leave the definition only in RFC-0007 (descriptive), never in the
  manifesto.** Rejected: the *commitment* is what readers and contributors treat
  as authoritative for "what does zero-legacy mean"; a definition that lives only
  in a procedure RFC leaves the founding text saying something the project no
  longer means. The manifesto should state what it commits to.

**Impact of not doing this:** the paradox stays open in the founding text; #42's
migration work rests on a commitment whose literal wording contradicts it; and
every future migration re-litigates "but the manifesto says *no* legacy" against
"but the standard only deprecated it."

## Prior art

- [RFC-0007](0007-cryptographic-primitive-migration-procedure.md) — the migration
  procedure this definition serves; it names this amendment as deferred future
  work in its §Future possibilities.
- [RFC-0005](0005-hybrid-pq-key-exchange.md) / [RFC-0006](0006-post-quantum-host-key-signatures.md)
  — the two migrations that established the classical-plus-PQ hybrid posture this
  amendment protects (classical-only forbidden, classical-plus-PQ permitted).
- **NIST IR 8547** — the deprecation/disallow timeline that supplies the frontier
  dates; **[RFC 9142](https://www.rfc-editor.org/rfc/rfc9142.html)** — the
  standards-maintained-moving-target precedent.
- The review history of PR #93, where the deprecation-vs-disallow and
  governance-inversion issues were surfaced and which motivated separating this
  amendment into its own RFC.

## Unresolved questions

- Whether the manifesto passage should also appear in the English `README.md`
  vision text, or stay Spanish-only in `MANIFIESTO.es.md` (the manifesto is the
  Spanish canonical document; the README paraphrases). Deferred as an editorial
  follow-up, not a blocker.

## Future possibilities

- If a standards body ever *un-disallows* something (historically vanishingly
  rare), the frontier definition already handles it without a manifesto edit —
  the floor is the only permanent set.
