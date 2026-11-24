<!--
  Governance status (2026-11-24):
  Non-authoritative design note (ADR-0027). Scoped the Phase-3
  privilege-separation RFC; tracked in #43. It decides nothing.
  Authoritative decisions: RFC-0019 (Accepted 2026-11-22), the identity
  model, and RFC-0020 (Accepted 2026-11-24), privilege separation: a
  root launcher, an unprivileged network server, and a single-threaded
  helper per session, closest to option C below. RFC-0020's implementing
  decisions are ADR-0063 to ADR-0069, and RFC-0019's are ADR-0068 and
  ADR-0070 to ADR-0072 (all Proposed, drafted 2026-11-24).
  The note is kept as the record of the constraint and the options the
  RFC weighed.
-->
# Phase-3 privilege separation — scoping note (non-normative)

**Status:** scoping only. This note does **not** choose an architecture, and
nothing here is a decision. It exists to (a) record why a full RFC is premature,
(b) lock the load-bearing constraint that any design must satisfy, and (c)
enumerate the option space and the Phase-2 gating decisions the RFC depends on.
The RFC itself is tracked in [#43](https://github.com/gonzafg2/quantumssh/issues/43);
it — not this note — is what will eventually close threat-model §8.12, together
with the Phase-3 implementation (§8.12's stated closure condition).

## The gap being scoped

Today (Phase 1, threat-model §8.12) QuantumSSH runs an authenticated user's
command under the **service account's** UID, not the authenticated user's. The
supported posture is single-user; multi-tenant deployment is explicitly out of
scope. §8.12's closure condition is "Phase-3 privilege separation implemented +
a follow-up RFC superseding this entry." This note scopes that RFC.

## Why the full RFC is premature (do not draft it yet)

Privilege separation is not a self-contained decision — it is normative text
written against three Phase-2 artifacts that **do not exist**:

1. **The multi-user identity model.** How an authenticated public key maps to an
   OS user. Today there is *no* mapping — `authorized_keys` is the service
   account's only, single-user by design. This is the single biggest blocker: a
   privsep design cannot say "drop to the user's UID" until "which user" is
   defined.
2. **The configuration schema.** Phase 2 introduces the config file
   ([RFC-0006](../rfcs/0006-post-quantum-host-key-signatures.md) §Motivation
   notes it arrives with `0.1.0`). The user↔UID mapping policy, and any
   PAM/chroot/`setrlimit` policy, live there. No schema, nothing to design
   against.
3. **The PTY story.** [ADR-0023](../adr/0023-phase-1-channel-layer-scope.md)
   defers PTY to Phase 2. PTY allocation (a privileged operation:
   `/dev/ptmx`, ownership of the slave) determines part of the surface privsep
   must cover, so the privsep boundary cannot be finalised before the PTY design.

Drafting normative privsep text now guarantees a rewrite once these land. What
is valuable now — and all this note claims to be — is the constraint set and
option matrix below.

### Where the three stand (2026-11-20)

The list above is as written on 2026-07-01. Phase 2 has closed since, with
`0.1.0`. Two of the three exist and one does not:

1. **The identity model: decided since 2026-11-22.** On 2026-11-20 it
   was missing: Phase 2 added OpenSSH user certificates
   ([RFC-0008](../rfcs/0008-ssh-certificate-authentication.md)), and no
   key or principal mapped to an OS account. Threat model §6.3 says so:
   "Until Phase 3 maps principals to accounts, the CA file is the access
   boundary". [RFC-0019](../rfcs/0019-identity-model-ssh-user-name-to-os-account.md)
   now decides it: the SSH user name names an operator-listed account,
   whose record comes from `/etc/passwd` and `/etc/group`. It is
   implemented together with the privilege-separation RFC.
2. **The configuration schema: exists.**
   [RFC-0010](../rfcs/0010-configuration-file.md) and
   [ADR-0029](../adr/0029-phase-2-config-file-v1-schema-parser-strictmodes.md).
   RFC-0010 leaves the key→OS-user mapping and the PAM, chroot and
   `setrlimit` policy to the privilege-separation RFC.
3. **The PTY story: exists.**
   [ADR-0038](../adr/0038-phase-2-interactive-pty-sessions.md) allocates
   the PTY through a re-exec helper.

The mapping got an RFC of its own, so the privilege-separation RFC
([#43](https://github.com/gonzafg2/quantumssh/issues/43)) is written
against RFC-0019 and decides only how the server becomes the account.

## The load-bearing constraint (this is the finding worth recording early)

**QuantumSSH is a multi-threaded Tokio runtime ([ADR-0022](../adr/0022-phase-1-async-runtime-tokio.md))
and forbids first-party `unsafe` ([ADR-0018](../adr/0018-phase-1-unsafe-code-forbid-workspace.md)).**
Together these push the privileged→unprivileged transition **out of the async
process entirely**:

- A POSIX `setuid`/`setgid` transition has well-known hazards in a
  multi-threaded process — the credential change is per-thread on Linux and must
  be synchronised across every thread, a pattern that is fragile, easy to get
  wrong, and historically a source of privilege-drop CVEs. Doing it correctly
  from safe Rust inside a live Tokio worker pool is not realistic.
- Therefore the identity transition must happen in an **isolated, single-threaded
  context**: either a short-lived helper process that is `fork`+`exec`'d and
  drops privileges before it ever spawns a thread, or a monitor/worker split
  where an unprivileged worker is created per session. The async server never
  calls `setuid` on itself.

Any option that keeps the `setuid` inside the async process is off the table on
these two ADRs alone. This is the one conclusion the RFC can treat as settled.

## Option matrix (non-normative — for the RFC to evaluate)

| Option | Sketch | Note against the constraint |
|---|---|---|
| A — in-process `setuid` post-auth | The async server drops to the user's UID in-place | **Excluded** by the load-bearing constraint (multi-thread setuid + unsafe-forbid). |
| B — OpenSSH-style monitor | A privileged monitor process; unprivileged per-connection workers via `fork` before threading | Classic, battle-tested; heaviest to build; IPC boundary is new attack surface. |
| C — single-threaded `setuid` helper | The server `fork`+`exec`s a small helper that drops privileges (single-threaded) then `exec`s the command | Fits the constraint cleanly; smallest privileged TCB; the helper is the whole privileged surface. |
| D — long-lived unprivileged worker per user | A resident per-user worker process; the server routes to it | Amortises spawn cost; adds lifecycle/state and a per-user process population to manage. |
| E — delegate to the OS | `systemd` user sessions / PAM `pam_setcred` + `setuid` helper from the platform | Least first-party privileged code; ties the deployment to a specific init/PAM stack (tension with small-surface portability). |

The constraint favours **C or D** (an isolated single-threaded privileged step);
B is the well-trodden fallback; A is excluded; E trades first-party code for a
platform dependency. The RFC picks among these once the Phase-2 prerequisites
exist.

## Phase-2 gating decisions this RFC waits on

- The key→OS-user mapping (config-carried? a `principals` file? cert principals
  once [#41](https://github.com/gonzafg2/quantumssh/issues/41) lands?).
- The config schema that carries UID-resolution / PAM / chroot / rlimit policy.
- The PTY ownership model (who allocates the pty, and on which side of the
  privilege boundary).
- The IPC interface between privileged and unprivileged components (for B/C/D)
  and its own threat surface.

## References

- Scopes the eventual closure of threat-model §8.12 (closed by the Phase-3 RFC
  plus its implementation, not by this note); builds on
  [RFC-0002](../rfcs/0002-threat-model-phase1-uid-model-and-non-goal.md) (the
  Phase-1 UID model and non-goal) and
  [ADR-0016](../adr/0016-phase-1-service-account-uid-model.md) (service-account
  UID model — the entry a Phase-3 RFC supersedes).
- Constraint sources: [ADR-0022](../adr/0022-phase-1-async-runtime-tokio.md)
  (Tokio), [ADR-0018](../adr/0018-phase-1-unsafe-code-forbid-workspace.md)
  (`unsafe` forbidden).
- Governance: this note's category is [ADR-0027](../adr/0027-docs-plans-governance-category.md).
