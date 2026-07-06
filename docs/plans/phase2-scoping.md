<!--
  Governance status (2026-07-06):
  Non-authoritative design note (ADR-0027). Scopes the Phase-2 ("Usable",
  0.1.0) milestone; tracked in #109. It sequences the workstreams and
  records the one-way release-freeze constraint so each eventual RFC/ADR
  does not start from a blank page. It decides nothing.
  Authoritative decisions live in ADRs/RFCs: none yet for Phase 2 except
  RFC-0008 (SSH certificate authentication, Accepted). This file is
  retained for rationale and is not a source of truth.
-->
# Phase-2 ("Usable") — scoping note (non-normative)

**Status:** scoping only. This note does **not** choose any architecture, and
nothing here is a decision. Phase 2 is a *milestone*, not a single decision, so —
unlike a feature RFC — it needs several shape-determining decisions, each in its
own RFC/ADR. This note exists to (a) record the one load-bearing sequencing
constraint the whole milestone turns on, (b) map each Phase-2 workstream to the
RFC/ADR lane it will need and what it unblocks, and (c) enumerate a suggested
ordering and its rationale. Every "should" below is sequencing rationale for the
eventual RFCs to weigh, never a locked choice (ADR-0027 anti-split rule).

The milestone is tracked in [#109](https://github.com/gonzafg2/quantumssh/issues/109)
(analogous to [#9](https://github.com/gonzafg2/quantumssh/issues/9) for Phase 1);
this note scopes it.

## What Phase 2 is

The canonical catalogue is [`README.md`](../../README.md) ("Phase 2 — Usable"),
five items, first public release `0.1.0`:

- Interactive PTY allocation
- Configuration file (TOML, not `sshd_config`)
- SFTP subsystem
- systemd integration
- First public release: `0.1.0`

Everything the Phase-1 ADRs and the threat model defer "to Phase 2" resolves to
one of these. Note the boundary with Phase 3 ("Hardening", `0.5.0`): continuous
fuzzing, conformance tests, the security audit, and per-user privilege
separation are **Phase 3**, not Phase 2 ([`README.md`](../../README.md);
[`phase3-privsep-scoping.md`](phase3-privsep-scoping.md)).

## The load-bearing constraint: the `0.1.0` freeze is one-way

Cutting `0.1.0` converts two things from private implementation detail into
**public compatibility contracts that cannot later be narrowed without breaking
peers**:

1. **The negotiation profile.** The KEXINIT name-lists become a compatibility
   contract "once a public client population exists (Phase 2, `0.1.0`)"
   ([ADR-0021](../adr/0021-phase-1-negotiation-profile.md) §Consequences).
2. **The audit-log schema.** It "becomes a public interface from Phase 2 onward"
   and gains a `schema_version` "when Phase 2 cuts `0.1.0`"
   ([ADR-0024](../adr/0024-phase-1-log-event-schema.md) §Consequences;
   threat-model §"stable interface from Phase 2 onward").

Consequence for sequencing: any change wanted in either of these must land
**before** the `0.1.0` tag, because after it the change is a breaking one. This
is the single constraint that orders the milestone — it makes the release tag a
gate, not a formality. The freeze checklist below exists for exactly this.

`unsafe_code = "forbid"` ([ADR-0018](../adr/0018-phase-1-unsafe-code-forbid-workspace.md))
also still binds: PTY allocation touches privileged, syscall-level surface
(`/dev/ptmx`, slave ownership) that must go through a safe wrapper (the
`rustix`-style path Phase 1 already uses for `getuid`/process-group kill), never
first-party `unsafe`.

## Workstream map

Each row is a Phase-2 feature, what it unblocks, the RFC/ADR lane it will need,
and its hard dependencies. Lanes follow the `CLAUDE.md` RFC/ADR contract (RFC for
a new public interface or shape-determining change; ADR for a locked operational
choice); the exact lane is for the workstream's author to confirm, not decided
here.

| Workstream | Unblocks | Likely lane | Depends on |
|---|---|---|---|
| **Configuration file (TOML)** | `env`/`SetEnv` policy; cert-trust config; the Phase-3 key→UID mapping | **RFC** — a new public interface (the schema) | — (keystone; nothing blocks it) |
| **Interactive PTY** | `pty-req`, `shell`, `window-change`; `exit-signal` reporting | **ADR** extending [ADR-0023](../adr/0023-phase-1-channel-layer-scope.md) channel scope; forces the runtime decision below | Runtime decision |
| **Runtime / concurrency** | Real concurrent connections; per-source rate-limits; half-open caps; graceful shutdown | **ADR** extending [ADR-0022](../adr/0022-phase-1-async-runtime-tokio.md) | — |
| **SFTP subsystem** | The `subsystem` request; second concurrent channel | **RFC or ADR** (new protocol surface) | Channel multiplexing (PTY/second-channel work) |
| **SSH certificate auth** | Cert-based auth (threat-model §5.3.2 mitigant) | **RFC-0008 — already Accepted**; needs implementation | Config file (cert-trust surface) |
| **systemd integration** | Service deployment | **ADR** (operational) | Graceful shutdown |
| **Release `0.1.0`** | First public release | tag + the freeze checklist below | All of the above + freezes |

## Suggested ordering (non-normative)

The dependency edges above, plus the one-way freeze, suggest this order — offered
as rationale for the RFCs to weigh, not as a plan of record:

1. **Config file first.** It is the keystone: `env` policy hangs off it
   ([ADR-0023](../adr/0023-phase-1-channel-layer-scope.md) §Consequences, "`env`
   … revisited with the config work in Phase 2"), RFC-0008's cert-trust surface
   depends on it, and it is one of the three Phase-3 privsep prerequisites
   ([`phase3-privsep-scoping.md`](phase3-privsep-scoping.md) §"Why the full RFC
   is premature"). Nothing else blocks it, and much waits on it.
2. **Runtime / concurrency rework, in parallel.** Removing the immediate
   post-accept join is called out as "not a refactor"
   ([ADR-0022](../adr/0022-phase-1-async-runtime-tokio.md) §Consequences); the
   per-source rate-limits and half-open caps that "land with Phase 2" (same ADR)
   also close the pre-auth availability DoS the Phase-1 security review recorded
   as an accepted pre-alpha ceiling. Independent of the config work.
3. **PTY**, which forces the `tokio::process`-vs-current-`spawn_blocking`
   decision the runtime ADR flagged for "when PTY support lands in Phase 2"
   ([ADR-0022](../adr/0022-phase-1-async-runtime-tokio.md) §Consequences), and
   brings `exit-signal` with it ([ADR-0023](../adr/0023-phase-1-channel-layer-scope.md)).
4. **SFTP** and **certificate auth (RFC-0008 implementation)**, once channel
   multiplexing and the config surface respectively exist.
5. **systemd + graceful shutdown.**
6. **Freeze, then tag `0.1.0`** (checklist below) — last, because the freeze is
   one-way.

## Freeze checklist before tagging `0.1.0`

Because the freeze is irreversible (§"load-bearing constraint"), these must be in
their intended long-term shape *before* the tag, each recorded in its own ADR —
not in this note:

- [ ] **Audit-log schema** carries `schema_version` and its field set is final
      ([ADR-0024](../adr/0024-phase-1-log-event-schema.md) is "the input that
      Phase 2's versioned schema freezes"). Any field rename becomes a migration
      note after this point.
- [ ] **Negotiation profile** (KEXINIT name-lists) reviewed as a
      to-be-frozen contract ([ADR-0021](../adr/0021-phase-1-negotiation-profile.md)).
- [ ] **Config-file schema** stable enough to extend compatibly (it, too, is a
      public interface once shipped).

## Cross-phase: what Phase 3 waits on

Three Phase-2 artifacts are hard prerequisites for the Phase-3 privilege-separation
RFC, which today "is premature until the Phase-2 prerequisites … exist"
([`phase3-privsep-scoping.md`](phase3-privsep-scoping.md)): the multi-user
identity model (key→OS user), the configuration schema, and the PTY ownership
design. Phase-2 config and PTY decisions therefore carry Phase-3 weight and
should not be made in isolation from that scoping note.

## References

- Milestone catalogue: [`README.md`](../../README.md) ("Phase 2 — Usable").
- Freeze sources: [ADR-0021](../adr/0021-phase-1-negotiation-profile.md)
  (negotiation profile as compatibility contract),
  [ADR-0024](../adr/0024-phase-1-log-event-schema.md) (log schema public from
  Phase 2), threat-model §"stable interface from Phase 2 onward".
- Deferral sources: [ADR-0022](../adr/0022-phase-1-async-runtime-tokio.md)
  (runtime, concurrency, rate-limits, shutdown),
  [ADR-0023](../adr/0023-phase-1-channel-layer-scope.md) (PTY, `shell`, SFTP
  `subsystem`, `exit-signal`, `env`).
- Already-designed piece: [RFC-0008](../rfcs/0008-ssh-certificate-authentication.md)
  (SSH certificate authentication, Accepted — a Phase-2 feature, implementation
  PR TBD, config-surface dependency).
- Downstream: [`phase3-privsep-scoping.md`](phase3-privsep-scoping.md) (the
  Phase-3 work Phase-2 artifacts unblock).
- Governance: this note's category is [ADR-0027](../adr/0027-docs-plans-governance-category.md).
