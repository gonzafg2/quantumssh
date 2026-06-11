---
name: Design question / RFC trigger
about: A design gap, open question, or MANIFIESTO commitment that needs a formal RFC or ADR to resolve.
title: "design: <short description>"
labels: [rfc, design]
assignees: []
---

<!--
Spanish or English are both welcome.

Use this template when something is *missing* from the project's design —
not when you want a new feature. The question "what would we decide here
if we had to implement this tomorrow?" should have no clear answer.

For feature requests, use the feature_request template.
For bugs, use bug_report.
For security issues, see SECURITY.md — never file here.
-->

## What decision is missing or underspecified?

<!-- One or two sentences. Be precise about what needs to be decided,
not just described. Finish this sentence: "There is no answer to the
question of whether QuantumSSH will ___." -->

## MANIFIESTO commitment at stake

<!-- Which of the five commitments does this touch? Check all that apply. -->

- [ ] #1 Memory-safe by construction
- [ ] #2 Post-quantum by default, not by opt-in
- [ ] #3 Zero legacy
- [ ] #4 Small attack surface, sharp edges
- [ ] #5 Permanently open source

## Threat model reference

<!-- Which section of docs/threat-model.md covers this?
If none, say "none — and that absence is the gap." -->

## What breaks if this is never resolved?

<!-- Technically, architecturally, or against stated project commitments.
Concrete is better than abstract. -->

## Earliest phase this becomes blocking

<!-- Phase 1 / 2 / 3 / 4. "Blocking" means we cannot ship that phase
without a resolution. -->

## RFC or ADR?

<!-- RFC: protocol extensions, crypto defaults, public API changes,
anything that touches README.md or MANIFIESTO.es.md commitments.
ADR: operational or tooling decisions that do not change protocol behaviour. -->

- [ ] RFC
- [ ] ADR
- [ ] Unclear — needs discussion first

## Open questions

<!-- What would need to be true or known to write the RFC or ADR?
What are the hardest sub-questions? -->
