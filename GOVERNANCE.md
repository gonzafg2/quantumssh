# Project Governance

This document describes how decisions are made in QuantumSSH, who has
the authority to make them, and how that authority will evolve as the
project matures. It also documents the structural commitments that
protect the project's open-source character against future drift.

It is intentionally short. Governance documents that try to anticipate
every situation tend to be ignored when situations actually arise. We
prefer a small set of explicit principles and a culture of writing
things down when they matter.

## Current model: temporary BDFL

QuantumSSH is in **Phase 0 to Phase 2** of the roadmap (see `README.md`).
During this period, the project is led by a single benevolent dictator:

- **Gonzalo Fleming Garrido** (Fleming Science and Technologies SpA),
  project lead and initial maintainer.

This concentration of authority is deliberate and explicitly temporary.
Early-stage projects need someone who can make a call, ship, and move
on. As the project earns contributors and history, that authority is
designed to dilute.

## Transition to a maintainer team

The project will transition from BDFL governance to a multi-maintainer
model when both of the following conditions are met:

1. There are **at least three regular contributors** other than the
   project lead, where "regular" means having authored merged
   contributions across at least six consecutive months.
2. The project has shipped a **`0.1.0` public release**, marking the end
   of Phase 2 of the roadmap.

When those conditions hold, the project lead will:

- Invite qualifying contributors to become maintainers, with public
  discussion in an issue or RFC.
- Document the maintainer team in this file.
- Step down from BDFL status to one-among-equals on the maintainer team.

If the conditions are met but the project lead does not act on this
clause within a reasonable period, this clause is itself a public
commitment that the community can reference.

## How decisions are made

In all phases:

- **Day-to-day technical decisions** (bug fixes, refactors, small
  features) are decided by the maintainer who reviews and merges the
  pull request, in line with the existing code and design.
- **Substantial design decisions** (new protocol extensions, breaking
  changes to defaults, cryptographic agility decisions, dependency
  additions of meaningful weight) require an **RFC** under `docs/rfcs/`.
  See `docs/rfcs/README.md` for the process. RFCs are merged by **lazy
  consensus**: if no maintainer has substantively objected after the
  comment period, the RFC is accepted.
- **Project-shaping decisions** (governance changes, license-related
  decisions, code of conduct changes, scope changes that contradict the
  README) require explicit affirmation from the project lead during
  Phases 0-2, and from a majority of the maintainer team thereafter.

Lazy consensus does not mean silence is approval forever. If you object
to an RFC, say so on the RFC pull request before the comment period
closes. Substantive objections must be addressed; "I don't like it" is
not, on its own, a substantive objection.

## The license commitment (binding)

The `Open source, really` section of `README.md` is treated as a
**binding public commitment** of this project, not a marketing
statement. It is reproduced here in compressed form for the avoidance
of doubt:

- **No source-available licensing.** This project is and will remain
  Apache 2.0. We will not adopt licenses that restrict commercial use,
  forking, redistribution, or modification.
- **No NDAs to read or contribute to the code.** Every line is in the
  public repository from the first commit. Always.
- **No bifurcated codebase.** If commercial services exist around the
  project, they will be services *around* the open project, not a
  parallel closed version.
- **No relicensing rug-pull.** Contributions remain licensed under the
  terms they were contributed under.
- **Patent grant flows in both directions.** Apache 2.0's patent grant
  is preserved.

Any change to the project's license, or any change that would weaken any
of the commitments above, requires:

1. **Unanimous agreement** of all current maintainers (during Phases 0-2,
   this means the project lead), and
2. A **public comment period of at least 60 days**, announced on the
   project's main communication channels and pinned as a repository
   issue.

There is no shorter path. There is no "exceptional circumstances"
override. If the project ever needs to make such a change, it can take
the 60 days.

If a future version of `README.md` quietly removes or weakens the
`Open source, really` section, that itself is a public signal that
something has changed, and the community is invited to react accordingly.

## Communication

- **Public design discussion**: GitHub Issues and RFCs in this
  repository.
- **Security disclosure**: see `SECURITY.md`.
- **Code of Conduct reports**: `conduct@quantumssh.org`.
- **General questions**: GitHub Discussions on this repository.

We try to keep important conversations in writing and in public. Out-of-
band conversations happen, but decisions made in them are summarised
back into the public record.

## Amendments

This document can be amended through the normal RFC process, with one
exception: the `The license commitment (binding)` section can only be
modified through the procedure that section itself describes.
