# RFC 0002: Threat model — Phase 1 UID model honesty and non-goal §8.12

- **Status:** Draft
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-05-13
- **Tracking issue:** [`#9`](https://github.com/gonzafg2/quantumssh/issues/9) (Phase 1 / Hito 1)
- **Implementation PR:** TBD

## Summary

This RFC refines [`docs/threat-model.md`](../threat-model.md) §2.5
(Command execution authority) and adds §8.12 (Out of scope).

This RFC proposes two coupled refinements to `docs/threat-model.md` so
that the document continues to describe what QuantumSSH *actually*
enforces during Phase 1, rather than what it intends to enforce once
privilege-separation lands in Phase 3:

1. **§2.5 (Command execution authority).** Acknowledge that during
   Phase 1 the executed command runs under the operating-system identity
   of the QuantumSSH service account — *not* the authenticated user —
   and that the goal *"authority on the host as the authenticated
   user"* applies only from Phase 3 onward (when privilege separation
   and per-user `setuid` land).
2. **§8 (Out of scope).** Add a new §8.12 *"Per-user UID isolation
   until Phase 3"* that names this gap explicitly, in the same form the
   threat model already uses for §5.5.4 (Operator-account compromise,
   out of scope) and §8.1 (Compromise of the host kernel or operator
   account).

The non-goal has a **closure condition**: it lifts when the Phase 3
privilege-separation work lands and a follow-up RFC removes §8.12.
Stating that condition inline makes the entry a temporary
disclosure, not a permanent exemption.

## Motivation

The walking-skeleton scope captured in `README.md` §"Phase 1" specifies
five deliverables: a listener, hybrid PQ KEX, an Ed25519 host key,
public-key authentication, and **single-command execution**. The
design work supporting this RFC examined what "single-command
execution" must minimally deliver in RFC 4254 terms and how the
host-side authority should be bounded. The conclusion reached,
supported by inspection of
OpenSSH's `sshd-session.c` and `do_setusercontext`, is that real
per-user privilege separation requires:

- Running `quantumsshd` as `root` (or, less commonly, with
  `CAP_SETUID` + `CAP_SETGID` on Linux).
- Resolving the authenticated user's `passwd` entry, including their
  `uid`, `gid`, supplementary groups, home directory, and login shell.
- Calling `setgid` + `initgroups` + `setuid` in the correct order, with
  the correct error handling, *before* `execve`.
- Optionally integrating with PAM for session establishment, audit
  records, and resource limits — each of which is its own attack
  surface.
- A `chroot` or namespacing story for environments where the user's
  authority must be further bounded.

Implementing this in Phase 1 expands the walking-skeleton scope by an
order of magnitude. The MANIFIESTO compromise *"Superficie pequeña,
bordes afilados"* (small surface, sharp edges) makes that expansion
incompatible with the phase's stated intent — the walking skeleton is
deliberately the smallest thing that demonstrates the cryptographic
posture works, not the smallest thing that is operationally adequate
for a shared host.

The pragmatic and honest path is to:

- Run `quantumsshd` in Phase 1 as a **dedicated non-root service
  account** (e.g. a `quantumssh` user with `/usr/sbin/nologin` and no
  `sudo`).
- Restrict the Phase 1 `authorized_keys` to the keys of that same
  service account's intended operator (single-user posture).
- Execute the SSH-supplied command as the service account's UID, with
  a documented, sanitised environment.
- **Tell operators and auditors this is what we are doing,** so the
  threat model and the code agree.

The threat model today does *not* tell that story. §2.5 reads:

> **What.** The bounded ability to run programs and access files on the
> host as the authenticated user, with the privileges that user holds
> in the operating system.

A reader who deploys Phase 1 and trusts that sentence will deduce —
incorrectly — that the host enforces `uid_user == uid_authenticated`.
The Phase 1 implementation cannot make that guarantee. The threat model
must say so.

The non-goal at §8 is the structural place for this. The document
already uses §8 to disclose what it does not defend against; §5.5.4 and
§8.1 use a near-identical pattern for the operator-account case. The
proposal here is to follow that established shape.

## Guide-level explanation

The change is best understood by reading §2.5 and the proposed §8.12
side by side.

### Proposed refinement to §2.5

The existing **What**, **Where**, and **Goal** subsections remain
substantively in place; a closing paragraph is appended that scopes the
goal to Phase 3 and points the reader at §8.12 for the Phase 1 reality.

> ### 2.5 Command execution authority
>
> **What.** The bounded ability to run programs and access files on the
> host as the authenticated user, with the privileges that user holds
> in the operating system.
>
> **Where.** The session's connection to the host OS — process creation,
> PTY allocation, file system access — established after authentication.
>
> **Goal.** Integrity (channel — execution requests must match the
> authenticated user's intent, not an attacker's substitution),
> authenticity (the user the host believes is executing the command is
> the user who authenticated). Confinement *beyond* what the host OS
> provides for that user is **not** a QuantumSSH-side goal; see §8.
>
> **Phase-bounded reality.** The authority described above is the
> Phase-3 target. During Phase 1 the server runs commands as the OS
> identity of the QuantumSSH service account itself, not as the
> authenticated user. The Phase-1 posture is documented as a temporary
> non-goal in §8.12; per-user UID isolation is part of the
> privilege-separation work scheduled for Phase 3 and gated by its own
> RFC.

### Proposed §8.12 (new non-goal)

> #### 8.12 Per-user UID isolation until Phase 3
>
> Until the privilege-separation work scheduled for Phase 3 lands,
> QuantumSSH executes the authenticated user's command under the
> operating-system identity of the QuantumSSH service account (the same
> account that owns the listening process), **not** under the OS
> identity of the authenticated user. Two consequences follow.
>
> First, operators must deploy Phase 1 with the assumption that any key
> in `authorized_keys` is operationally equivalent to a key for the
> service account; multi-tenant deployments are not in scope for
> Phase 1. The supported posture is single-user: one operator, one set
> of keys, one account.
>
> Second, file-system and process accesses performed by commands run
> through QuantumSSH inherit the service account's authority, not the
> authenticated user's. Auditors reading server logs must read
> `executed by <uid of quantumsshd>` rather than
> `executed by <uid of user>`; the §2.7 audit record records the
> *authenticated identity* and the *executing UID* as separate fields
> precisely so this gap is visible to anyone reviewing logs.
>
> The closure condition for this non-goal is the Phase 3 privilege-
> separation RFC. When that RFC lands and per-user UID isolation is
> implemented, a follow-up RFC supersedes this entry and removes §8.12.
> The non-goal is, by design, temporary.

### Proposed amendment elsewhere

**§2.7 (Audit record).** The existing entry lists *"authentication
outcomes (success and failure)"*. To make the Phase 1 reality
auditable, the entry should also commit to recording the executing UID
on each command boundary, distinct from the authenticated identity.
This is a one-sentence addition; it lets §8.12's second paragraph rest
on a concrete log field rather than a hope.

## Reference-level explanation

### Operational shape of Phase 1

The Phase 1 service account is created at install time with the
following constraints (these are operator guidance, not enforced by
QuantumSSH itself):

- Dedicated UID/GID, e.g. `quantumssh:quantumssh`.
- Login shell `/usr/sbin/nologin`.
- No entries in `sudoers`.
- Home directory permissions `0750` or stricter.
- `authorized_keys` for the service account contains exactly the keys
  the operator wants to grant *the privileges of this account*, not
  some other user's.

The server-side execution flow on receipt of a successful pubkey
authentication and `"exec"` channel request:

```text
authenticate(user, key)   → ok, authenticated_identity = key fingerprint
open_session_channel()    → ok
exec_request(command)     →
    spawn /bin/sh -c <command>
      uid  = getuid()  (the service account's UID, unchanged)
      gid  = getgid()
      cwd  = $HOME of the service account
      env  = sanitised: PATH, HOME, USER, SHELL, LANG, LC_*
    stdin  = /dev/null
    stdout, stderr → SSH channel
    exit-status     → SSH channel
```

The server **does not** call `setuid`, `setgid`, `initgroups`, or
`chroot`. It does not load `/etc/passwd` for the authenticated user.
It does not integrate with PAM. Each of these is deferred to Phase 3.

### Audit record fields (Phase 1)

The structured log emitted via `tracing` for an `exec` boundary in
Phase 1 should include, at minimum:

| Field | Source | Notes |
|---|---|---|
| `authenticated_identity` | key fingerprint of the public key that authenticated | The user-facing identity. |
| `executing_uid` | `nix::unistd::Uid::current()` | The OS-facing identity. In Phase 1 this is always the service account's UID. |
| `command_sha256` | `sha256(command_bytes)` | The plaintext command is not logged; a content hash and length suffice for forensic linkage. |
| `command_len` | `command_bytes.len()` | Sidecar to the hash. |
| `exit_status` | server-side wait | From the spawned process. |
| `duration_ms` | wall-clock between exec and close | Bounded by the channel lifetime. |

Recording `executing_uid` as a first-class field is what makes §8.12's
honesty operationally checkable: an operator who greps `executing_uid`
in their logs will see the service account's UID on every line, not
a per-user value, and the gap §8.12 names becomes self-evident.

### Phase 3 trajectory

A future Phase 3 RFC will propose:

- A privilege-separation monitor process (analogous to OpenSSH's
  `do_setusercontext` path).
- Per-user UID/GID resolution from `passwd`, with explicit handling of
  the cases where the authenticated identity has no `passwd` entry
  (reject) or has a shell of `/usr/sbin/nologin` (reject).
- `setuid` + `setgid` + `initgroups` invocation before `execve`, with
  the post-condition that `getuid() != 0` is asserted before the child
  process is started.
- A revised §2.5 that drops the Phase-bounded paragraph and an updated
  §8 that removes §8.12.

This RFC commits to the direction without committing to the design
details of the Phase 3 RFC; that document will be written when the
work begins.

### Compatibility implications

This RFC does **not** change anything about QuantumSSH's protocol
behaviour, configuration surface, or wire format. It is a documentation
change that makes the threat model match the implementation that
Phase 1 will deliver.

The operator-facing implication is one paragraph of installation
guidance: deploy Phase 1 as a single-user posture, with one service
account and one operator. This guidance belongs in
`docs/operations.md` when Phase 1 lands, not in the threat model.

## Drawbacks

1. **Risk of normalising the gap.** Adding a non-goal makes the gap
   visible, but a determined reader might interpret §8.12 as a permanent
   exemption rather than a temporary disclosure. Mitigation: the
   closure-condition paragraph in §8.12 names the Phase 3 RFC by
   reference and asserts the non-goal is temporary. A reader who reads
   §8.12 to its end cannot reasonably infer permanence.

2. **Risk of weakening §2.5.** A reviewer could argue that adding a
   Phase-bounded paragraph to §2.5 dilutes the asset definition.
   Mitigation: the asset definition itself is unchanged; the new
   paragraph reports an implementation phase fact, not a redefinition
   of the asset. The asset remains "command execution authority"; the
   note explains when the strong form of the goal becomes operative.

3. **Risk of operator misuse during Phase 1.** Operators reading the
   Phase-1-bounded version of §2.5 might choose to deploy in
   multi-tenant scenarios anyway, on the grounds that "post-quantum
   crypto is fine". The implementation does not currently refuse to
   start in such scenarios. Mitigation: a follow-up addition to
   `docs/operations.md` documents the single-user assumption with the
   same emphasis the README uses for "no backward compatibility";
   that document is not in scope for this RFC but is named as a
   dependency.

4. **Drift between this RFC and the implementation if the
   implementation evolves before Phase 3.** If a later refinement to
   Phase 1 or Phase 2 quietly introduces a partial privsep (for
   example, dropping privileges to a child of the service account), the
   §8.12 wording becomes slightly inaccurate. Mitigation: any such
   change is a code-level change that has to update the threat model
   in the same PR; the maintenance clause at the top of `threat-model.md`
   already requires it.

## Rationale and alternatives

### Why a non-goal in §8 rather than a deferred goal in §2.5

§2.5 is an asset definition. The asset itself does not change between
Phase 1 and Phase 3 — *"command execution authority"* describes the
same thing in both phases. What changes is the strength of the goal
QuantumSSH enforces around it. Goals that the project chooses not to
enforce are §8's natural home; §2.5's phase-bounded paragraph points at
§8.12 rather than carrying the disclosure inside the asset definition.

### Why add a phase-bounded paragraph to §2.5 at all

If §8.12 names the gap, §2.5 could remain entirely as-is. The reason
to add a short note inside §2.5 is *findability*: an implementer
writing Phase 1 code reads §2.5 to understand what their code must
deliver. Pointing them at §8.12 from inside §2.5 is the difference
between *"I have to implement per-user UID isolation"* and *"I have to
implement the channel-level integrity property; per-user UID isolation
is not Phase 1's responsibility per §8.12"*.

### Why not bundle this with a "single-command execution" ADR

A separate ADR will record the operational scope of "single-command
execution" (channel-layer subset of RFC 4254, supported message types,
stdin handling, exit-status propagation, etc.). That ADR is the right
place for the choice *"run as the service account UID"*. This RFC, in
contrast, is the right place for the *threat-model consequences* of
that choice — what guarantees the model promises, and what it does
not. The two artefacts cite each other but do different work.

### Why not delay this RFC until Phase 1 code lands

Two reasons. First, the threat model's maintenance clause requires an
RFC for non-goal additions; landing the code before the RFC inverts
that order. Second, the RFC sets the bar an implementation must clear:
the Phase 1 code, when it lands, must implement what the threat model
says, not the reverse. Writing the RFC first is the project's stated
process and it serves the design.

### Why not preemptively implement per-user UID isolation in Phase 1

This was the alternative the research panel weighed before recommending
the service-account-UID model. The costs are large:

- `quantumsshd` must run as `root`, expanding the privileged code path
  by every line that runs before the `setuid` call.
- A privilege-separation monitor is needed to keep the post-auth code
  off the privileged binary; OpenSSH's `sshd-session.c` is roughly
  4,000 lines of careful C precisely because this is hard.
- PAM, `nsswitch`, and `getpwnam_r` integration each carry their own
  attack surface and platform variation.
- The MANIFIESTO compromise of *"superficie pequeña, bordes afilados"*
  pushes the project in the opposite direction at this phase.

The trade-off is therefore Phase 3 work, not Phase 1 work, and §8.12
is the disclosure mechanism that makes the deferral honest.

## Prior art

- **OpenSSH** delivers per-user UID isolation via a privilege-separation
  monitor and the `do_setusercontext` family of functions in
  `sshd-session.c`. The OpenSSH code is the reference implementation
  the Phase 3 work will study most closely.
- **wolfSSH** (C, scope similar to QuantumSSH Phase 1–2) also defers
  certain operational guarantees to operator-supplied integration,
  rather than implementing them inside the server. This is a precedent
  for the model proposed here: small server, operator owns the host
  identity boundary.
- **rustls** (TLS, not SSH) is a useful prior-art reference for the
  principle that a security-critical Rust library should describe its
  guarantees honestly and explicitly, including the guarantees it does
  not provide. The rustls manual sections on implementation
  vulnerabilities and threat assumptions follow the same pattern of
  named non-goals.
- **NIST SP 800-30 Rev.1 Appendix D**, already cited throughout the
  current threat model, supports the qualitative-disclosure style this
  RFC adopts (the framework distinguishes adversarial from
  non-adversarial sources and from system-imposed deferrals; the
  Phase-3 deferral here is the latter).

## Unresolved questions

1. **Whether §8.12 should commit to a date.** The RFC names the
   closure condition by Phase, not by calendar. The roadmap in
   `README.md` says *"Phase 3 will take a year or more"*, which is a
   range, not a deadline. A reviewer might prefer a *no-later-than*
   date to keep the deferral from becoming indefinite. The author's
   judgement is that calendar dates on multi-year roadmaps degrade
   silently and that the closure condition (a follow-up RFC + a
   privsep landing) is the right anchor. Reviewers may differ.

2. **Whether to refuse to start in multi-user-looking environments.**
   QuantumSSH could refuse to launch if its service account is `root`,
   if `authorized_keys` lists more than one key, or if the host has
   more than one shell-bearing user account. Each of these is
   heuristic — a single-key, root-running deployment is not by itself
   wrong — and the proposal here is to *document* the assumption, not
   to enforce it programmatically. A separate RFC could revisit
   whether enforcement is desirable.

3. **Naming of the executing-UID log field.** The reference section
   above proposes `executing_uid`. Alternatives include `service_uid`,
   `process_uid`, or `os_uid`. Bike-shed on the PR.

4. **Whether the audit-record addition deserves its own RFC.** §2.7
   today lists the events recorded but does not enumerate fields. The
   "record executing UID" requirement is a small addition to a field
   list that does not exist yet. If reviewers feel this addition is
   substantial enough to warrant its own RFC, split it; the author's
   judgement is that it is small enough to ride with this one.

## Future possibilities

- **Phase 3 privilege-separation RFC.** The follow-up that supersedes
  §8.12. Will specify the privsep monitor, the `passwd`/`nsswitch`
  resolution path, the order of `setuid`/`setgid`/`initgroups`, and
  the PAM integration boundary.
- **`From=` and `command=` per-key restrictions** (Phase 2 candidate).
  Even within the single-user Phase-1 posture, restricting individual
  keys to specific source addresses or specific commands reduces the
  blast radius of an off-host key compromise (§5.3.2).
- **Capability-based confinement on Linux.** Once privsep lands, the
  Phase 3 RFC could optionally describe a profile where `quantumsshd`
  uses `CAP_SETUID` + `CAP_SETGID` instead of running as `root`, with
  `prctl(PR_SET_NO_NEW_PRIVS)` to prevent the child from regaining
  privileges. This is an optimisation, not a requirement; named here
  for orientation.
- **`chroot`-style or namespace-style per-user confinement.** The
  threat model already states (§2.5, §4.2, §8.8) that confinement
  beyond what the OS provides is not a QuantumSSH-side goal. A future
  RFC could revise that stance for specific deployment profiles
  (single-tenant batch nodes, for example). Not in scope here.

