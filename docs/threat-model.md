# QuantumSSH Threat Model

> **Status:** Skeleton. The substantive content of this document will
> be written as part of Phase 0 of the roadmap. The section structure
> below is committed; the contents of each section are TBD.

This document describes what QuantumSSH is defending, against whom,
under what assumptions, and where the boundaries of those defences
sit. It is meant to be read by implementers, auditors, and operators
who need to reason about whether QuantumSSH is appropriate for their
deployment.

The model will evolve. Updates go through the RFC process when they
materially change what the project promises.

## Assets

What the project is trying to protect. To be filled in.

## Threat actors

Who we are defending against, at what capability level, and with what
resources and goals. To be filled in. Particular attention will be paid
to harvest-now-decrypt-later adversaries, which are the motivating
threat for the project's post-quantum-by-default stance.

## Trust boundaries

Where trust changes hands inside the system. Network boundary,
process boundary, key-material boundary, configuration boundary,
operator-vs-user boundary. To be filled in.

## Attack vectors

The classes of attack the project considers in scope, and how the
design responds to each. To be filled in.

## Mitigations

The architectural and implementation choices that respond to the
identified attacks. Cross-references to the relevant RFCs and code
modules where they exist. To be filled in.

## Out of scope

Threats that QuantumSSH does **not** attempt to defend against, with a
brief rationale for each. Being explicit about non-goals here is as
important as being explicit about goals: it tells operators what
additional controls they need around the system. To be filled in.

## References

Standards, papers, and prior threat models consulted while building
this one. To be filled in.
