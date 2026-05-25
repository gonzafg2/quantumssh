# RFC 0000: <Title>

- **Status:** Draft
- **Authors:** <Name(s)>
- **Created:** YYYY-MM-DD
- **Roadmap issue:** TBD (relevant Phase tracking issue, e.g. `#9` for Phase 1)
- **Implementation PR:** TBD or PR link

## Summary

One paragraph explaining what this RFC proposes. A reader should be
able to understand the change at this level alone.

## Motivation

Why are we doing this? What problem does it solve, for whom, and what
goes wrong if we do not solve it? Cite real situations, not hypothetical
ones, where possible.

## Guide-level explanation

Explain the proposal as if it were already part of QuantumSSH, to a
reader who knows the project but has not seen this RFC. Use the
project's vocabulary. Show concrete examples of configuration, API
usage, or operator workflow as appropriate.

This section should be the bulk of an end-user-facing RFC.

## Reference-level explanation

The technical guts. Describe the design at a level of detail sufficient
for an experienced contributor to implement it without further design
work. Include:

- Data structures and their invariants.
- Protocol changes, message formats, wire encoding.
- Cryptographic constructions and the rationale for parameter choices.
- Error and failure modes, including adversarial ones.
- Compatibility implications (forward, backward, with other tools in
  the ecosystem).

## Drawbacks

Why might we *not* want to do this? What are the costs — in
implementation effort, attack surface, maintenance burden, performance,
ergonomic regression, or community fragmentation?

A good RFC author argues against their own proposal here as honestly as
they argued for it above.

## Rationale and alternatives

- Why is this design the right one in the space of possible designs?
- What other designs were considered, and why were they not chosen?
- What is the impact of *not* doing this?

## Prior art

Discuss prior or related work in the SSH ecosystem, in other Rust
projects, in academic literature, or in standards bodies (IETF, NIST,
IRTF). Reference specific RFCs, papers, or implementations where
applicable.

## Unresolved questions

What parts of the design are still open? What needs to be resolved
before, during, or after implementation? Mark each clearly so that
reviewers know where to focus and so that future maintainers know what
was deliberately left for later.

## Future possibilities

Natural extensions of this work. Out-of-scope-for-now ideas that this
proposal makes possible (or harder). This section is for orientation,
not commitment: nothing here is being proposed.
