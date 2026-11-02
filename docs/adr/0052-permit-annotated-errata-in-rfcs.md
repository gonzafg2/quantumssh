# ADR 0052: Permit annotated post-acceptance errata in RFCs

- **Status:** Proposed
- **Date:** — (set on acceptance; drafted 2026-11-02)
- **Deciders:** Project lead
- **Related:** Extends [ADR-0015](0015-permit-annotated-errata-in-adrs.md)'s errata mechanism from ADRs to RFCs, and updates the "After acceptance" section of [`docs/rfcs/README.md`](../rfcs/README.md). Its first use corrects [RFC-0015](../rfcs/0015-negotiation-profile-v1.md) and [RFC-0016](../rfcs/0016-config-schema-v1.md) in the same PR, after the opencode reviews of [#223](https://github.com/gonzafg2/quantumssh/pull/223), [#224](https://github.com/gonzafg2/quantumssh/pull/224) and [#233](https://github.com/gonzafg2/quantumssh/pull/233).

## Context

`docs/rfcs/README.md` says accepted RFCs are not edited in place: a
change is a new RFC layered on top. ADR-0015 made one exception for
ADRs, factual errata, because the strict rule had no path for a claim
that was simply wrong when the record was accepted. RFCs have the same
gap.

RFC-0015 and RFC-0016 were accepted on 2026-10-31. Reviews after
acceptance found statements in them that were false on that date:

- RFC-0016's version-1 key table omits `auth.trusted_user_ca_keys`. The
  key had shipped the day before, and ADR-0050 §3 places it in schema
  version 1.
- RFC-0016 §4 and RFC-0015 §6 each say the RFC changes no accepted
  decision, but each changes one: RFC-0016 §3 changes ADR-0028's rule
  for tuning a default, and RFC-0015 §4 refines RFC-0012's one-name
  host-key slot.
- RFC-0015 describes ADR-0047's supersession of ADR-0021's slot 2 as
  done, and its profile as pinned by a test that only checked two
  names.

None of these changes a decision. A new RFC for each would put a
correction through the full RFC process, which exists for decisions.

## Decision

We will allow **factual errata** in accepted RFCs, under the same rule
ADR-0015 sets for ADRs:

- **What qualifies:** a factual claim that was wrong at acceptance. That
  includes a typographical, numerical, descriptive or logical error, an
  omission from a list the RFC presents as complete, or a wrong
  statement of what the RFC changes in other accepted records.
- **How it is marked:** a `Post-acceptance errata` banner near the top
  of the RFC, citing this ADR. Each entry gives the date, the PR that
  makes the edit, and what was corrected. Git history keeps the
  original wording.
- **What does not qualify:** a decision change. Revising, narrowing,
  broadening or reversing what the RFC decides still needs a new RFC
  that supersedes it.

When an erratum corrects what an RFC changes in another accepted record,
that record's Status field states the supersession, as for an ADR.

## Consequences

### Positive

- A wrong statement in an accepted RFC can be fixed in the file that
  readers treat as the source of truth, and the banner shows that it
  was.
- RFCs and ADRs follow one errata rule.

### Negative

- Reviewers must tell an erratum from a decision change. The same test
  as ADR-0015 applies: "we said X but X is incorrect" is an erratum, and
  "we decided X, now we decide Y" needs a new RFC.

### Neutral

- The RFC process itself, lazy consensus and the comment period, does
  not change.

## Alternatives considered

### Alternative 1: An amending RFC for each correction

Rejected. It opens a comment period, and a merge, for statements that
change no decision, and the original RFC keeps the false sentence.

### Alternative 2: Leave the RFCs as accepted, and record the corrections in the ADRs and PRs

Rejected. The RFC is the source of truth for its decision, and readers
would keep finding the false statements there.

## Links

- Extends: [ADR-0015](0015-permit-annotated-errata-in-adrs.md).
- Updates: [`docs/rfcs/README.md`](../rfcs/README.md) "After acceptance".
- First use: RFC-0015 and RFC-0016, in this PR.
