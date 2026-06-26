# ADR 0016: Run quantumsshd as a dedicated non-root service account in Phase 1

- **Status:** Proposed
- **Date:** TBD (advances to Accepted when Phase 1 implementation begins)
- **Deciders:** Project lead
- **Related:** Operational counterpart to [RFC-0002](../rfcs/0002-threat-model-phase1-uid-model-and-non-goal.md); this ADR depends on the merge of [PR #24](https://github.com/gonzafg2/quantumssh/pull/24) and should land after it.

## Context

[RFC-0002](../rfcs/0002-threat-model-phase1-uid-model-and-non-goal.md) documents the threat-model side: §8.12 declares per-user UID isolation a Phase-1 non-goal, with a closure condition pointing at Phase 3 privilege-separation work. This ADR documents the **operational** side: the concrete OS-level posture Phase 1 deploys to make that non-goal honest.

The threat-model analysis in RFC-0002 §"Motivation" rules out real per-user privilege separation in Phase 1. The work expansion (a privilege-separation monitor analogous to OpenSSH's `sshd-session.c` — roughly 4 kLoC of careful C — plus `passwd`/`nsswitch`/`getpwnam_r` integration, plus PAM, plus the correct `setgid` + `initgroups` + `setuid` sequence) is incompatible with the walking-skeleton scope of Phase 1 and with the MANIFIESTO compromise *"superficie pequeña, bordes afilados"*.

What that analysis leaves open is *which* OS identity executes the SSH-supplied command on receipt of a successful pubkey authentication and an `"exec"` channel request. Three concrete options compete:

1. Run `quantumsshd` as `root` and never drop.
2. Run `quantumsshd` as `root` and drop to a service account after PID-1 initialisation.
3. Run `quantumsshd` as a dedicated non-root service account from PID 1.

This ADR records the choice of option (3) and the operational constraints that come with it. It does not re-litigate the Phase-3-deferral question — that lives in RFC-0002.

## Decision

We will run `quantumsshd` in Phase 1 as a dedicated non-root service account (canonical name `quantumssh:quantumssh`), created at install time, with the following posture:

- Login shell `/usr/sbin/nologin`.
- No entries in `sudoers`.
- Home directory permissions `0750` or stricter, owned by the service account.
- `authorized_keys` for the service account contains exactly the keys the operator wants to grant *the privileges of this account*.

The server-side execution flow for `"exec"` channel requests does **not** call `setuid`, `setgid`, `initgroups`, or `chroot`, and does not integrate with PAM. Commands inherit the service account's UID/GID, supplementary groups, and `$HOME`, with a sanitised environment (`PATH`, `HOME`, `USER`, `SHELL`, `LANG`, `LC_*`).

The audit-record requirement from RFC-0002 §2.7 — logging `executing_uid` distinct from `authenticated_identity` — is implemented by reading the process UID at the boundary via `rustix::process::getuid()`. In Phase 1 the field is a constant per process; the schema is forward-compatible with the Phase 3 per-user value.

> **Note (M5, while Proposed):** this ADR originally named `nix::unistd::Uid::current()`. Phase-1 implementation selected `rustix` (`features = ["process"]`) over `nix` for a smaller dependency surface (MANIFIESTO #4); `rustix::process::getuid()` reads the UID without first-party `unsafe`. The child kill the channel layer needs (ADR-0023, kill-on-early-close) goes through the owned `std::process::Child` handle (`Child::kill()`), not a raw-pid syscall — this avoids a pid-reuse TOCTOU and needs no `kill` from `rustix`. Edited in place because this ADR is still `Proposed`; no superseding ADR is needed.

## Consequences

### Positive

- `quantumsshd` never holds `root` in Phase 1. No `CAP_SETUID`, no `CAP_SETGID`, no privilege-separation monitor. The privileged code path is empty by construction.
- Compatible with `systemd`'s `User=`, `DynamicUser=`, `NoNewPrivileges=`, `ProtectSystem=`, and related directives — operators get OS-level hardening without QuantumSSH-side code.
- The threat model and the implementation agree on what Phase 1 actually delivers: RFC-0002 §2.5's "Phase-bounded reality" paragraph and §8.12's non-goal describe the same posture this ADR enforces.
- Phase 3 privilege-separation work has a clean starting point. The posture changes (the daemon gains a privileged PID-1 plus a per-user drop), but the Phase 1 code path that runs the command does not need to be unwound — it is the post-drop path Phase 3 will reach.

### Negative

- Phase 1 cannot support multi-tenant deployments. Every key in `authorized_keys` is operationally equivalent to a key for the service account. Mitigation: documented as a deferred non-goal in RFC-0002 §8.12; operator-facing guidance to be added to `docs/operations.md` when Phase 1 lands (separate ADR or doc PR, not in scope here).
- File-system and process accesses inherit the service account's authority, not the authenticated user's. A reader of §2.5 alone (without §8.12) could misread the implementation's guarantees. Mitigation: §2.5's "Phase-bounded reality" paragraph forwards the reader to §8.12 explicitly.
- Phase 3 will be a substantive change of posture (running as `root` or with `CAP_SETUID`), not an incremental refinement. Mitigation: that change is gated by its own RFC, named as the closure condition of RFC-0002 §8.12.

### Neutral

- The `executing_uid` log field is intentionally first-class even though it returns a constant in Phase 1. This is forward-compatibility, not redundancy: the Phase 3 implementation populates the same field with the per-user value, and a grep against historical logs spans both phases without schema migration.

## Alternatives considered

### Alternative 1: Run `quantumsshd` as `root` and never drop

Rejected. The Phase 1 server does not need `root` for any of its declared operations (no `setuid`, no `chroot`, no `bind` to a privileged port if the deployment uses a high port or a reverse proxy, no PAM). Holding `root` would buy nothing and cost the full surface of OS-level privilege checks; any RCE in `quantumsshd` would be a `root` RCE.

### Alternative 2: Run `quantumsshd` as `root`, drop to the service account post-spawn (no per-user setuid)

Rejected. End-state equivalent to the chosen option, but the privileged window between PID-1 startup and the drop is itself an attack surface: signal-handler ordering, initialisation-path error handling, any code that bails before the drop. For Phase 1's deliverables this window has no justification. The chosen option is strictly safer because the window is zero by construction.

### Alternative 3: Run `quantumsshd` as a non-root service account from PID 1

**Chosen.** No privileged window, no `setuid` machinery, no PAM, no `passwd` resolution. The implementation surface is the smallest of the three options. The cost — Phase 1 cannot enforce per-user UID isolation — is exactly the non-goal that RFC-0002 §8.12 documents and accepts.

### Alternative 4: Per-user UID isolation in Phase 1 (full OpenSSH-style privsep)

Rejected at the RFC-0002 level. The work expansion (the OpenSSH `sshd-session.c` model, PAM, `nsswitch`, `getpwnam_r`, correct `setuid` ordering, error-path handling) is incompatible with the walking-skeleton scope. Deferred to Phase 3 under its own RFC.

### Alternative 5: `CAP_SETUID` + `CAP_SETGID` on Linux instead of root

Variant of Alternative 4 with a smaller privileged blast radius. The Phase 1 reasoning still applies: any code path ending in `setuid` requires the upstream `passwd`/`nsswitch` machinery, which Phase 1 does not have and which is itself the scope expansion Phase 1 is avoiding. May resurface as an optimisation *inside* the Phase 3 RFC's design space; not a Phase 1 option.

## Links

- Threat-model counterpart: [RFC-0002](../rfcs/0002-threat-model-phase1-uid-model-and-non-goal.md), §2.5 "Phase-bounded reality" and §8.12 "Per-user UID isolation until Phase 3".
- Roadmap: Phase 1 / Hito 1 — [`#9`](https://github.com/gonzafg2/quantumssh/issues/9).
- Implementation: TBD (Phase 1 listener and exec-channel handler — no code has landed yet; see [ADR-0009](0009-workspace-no-members-during-phase-0.md) for the current workspace state).
- Related future work: a separate ADR will record the operational scope of "single-command execution" (the channel-layer subset of RFC 4254, supported message types, stdin handling, exit-status propagation). That ADR cites this one for the UID question.
