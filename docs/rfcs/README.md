# RFCs

The QuantumSSH RFC process exists for one reason: to make sure that
substantial design decisions are written down, debated in public, and
revisitable later. It is **not** a paperwork tax. We want it to be the
shortest path between *"I think we should change X"* and *"X is changed,
and the reasoning is on record"*.

We borrow shamelessly from the [Rust RFC process](https://github.com/rust-lang/rfcs)
but keep things lighter, in line with the project's current size.

## When you need an RFC

Open one when the change is meaningfully shape-determining for the
project, for example:

- A new protocol extension or change to default cryptographic algorithms.
- A new public API surface, or a breaking change to an existing one.
- A new dependency that materially expands the trust base (anything in
  the crypto, networking, or process-spawning paths).
- A change to defaults that users would notice (configuration, CLI
  behaviour, file formats).
- Anything that contradicts or refines a commitment in `README.md` or
  `MANIFIESTO.es.md`.

## When you do **not** need an RFC

For everything else, just open an issue or a pull request. Examples:

- Bug fixes.
- Refactors that do not change behaviour.
- Performance improvements that do not change interfaces.
- Documentation, examples, comments.
- Adding tests.

If you are not sure, open an issue first and ask. Maintainers can
upgrade an issue into an RFC if the discussion turns out to need one.

## How the process works

1. **Copy `0000-template.md`** to a new file. Pick a slug describing the
   proposal: `0001-hybrid-pq-key-exchange.md`. Use the next free number;
   numbering is strictly chronological by merge order, not creation
   order, so do not stress about collisions.
2. **Fill it in.** The template sections exist for a reason; if a
   section genuinely does not apply, write *N/A* and one sentence
   explaining why.
3. **Open a draft pull request** that adds the file under
   `docs/rfcs/`. Tag it with the `rfc` label.
4. **Discussion happens on the PR.** Major points raised in side
   channels should be summarised back into the PR thread so the public
   record is complete.
5. **Comment period.** A non-trivial RFC stays open for at least
   **14 days** before merge, to give the wider community time to weigh
   in. Maintainers can shorten this for time-sensitive issues, but the
   bar to do so should be high and stated explicitly on the PR.
6. **Resolution.** When discussion settles:
   - If accepted, the RFC is merged with its number assigned. Implementation
     PRs reference the RFC number.
   - If rejected, the RFC is closed (not merged) with a summary of why
     written into the PR thread. Rejected RFCs are valuable: they
     document roads not taken.
   - If postponed, the RFC stays open with a `postponed` label and a
     note explaining what would need to change for it to be reconsidered.

## Decision rule

RFCs are decided by **lazy consensus**. If the comment period closes
with no substantive unresolved objection from a maintainer, the RFC is
accepted. *Substantive* means the objection identifies a concrete
problem; "I don't like it" is not, on its own, substantive.

If consensus cannot be reached, the project lead (during Phases 0–2) or
a majority of the maintainer team (after the transition described in
`GOVERNANCE.md`) makes the call, with the reasoning written into the PR.

## After acceptance

- The RFC file remains in the repository as the source of truth for the
  decision.
- Implementation tracks the RFC; deviations during implementation that
  meaningfully change the design are noted in a follow-up RFC, not
  silently absorbed.
- If a future change makes an old RFC obsolete, the new RFC explicitly
  links to and supersedes the old one. We do not edit accepted RFCs in
  place; we layer new ones on top.

## A note on language

RFCs may be written in **Spanish or English**. If an RFC is in Spanish,
we encourage (but do not require) an English summary at the top, and
vice versa, so that the project remains accessible to contributors from
both language communities.
