# ADR 0069: The threat-model text for account mode

- **Status:** Accepted; the §7 keyring entry of §4 is narrowed by [ADR-0074](0074-each-account-mode-session-joins-its-own-session-keyring.md) §2
- **Date:** 2026-11-25 (accepted with the implementing PR [#308](https://github.com/gonzafg2/quantumssh/pull/308); drafted 2026-11-24)
- **Deciders:** Project lead
- **Related:**
  - It is the last item of [RFC-0020](../rfcs/0020-privilege-separation-root-launcher-and-session-helper.md) §12: "the final text of the threat-model changes (§9)".
  - It states the boundary that [ADR-0063](0063-launcher-protocol-seqpacket-socket-pair-ssh-wire-encoding.md) to [ADR-0067](0067-account-mode-systemd-unit.md) build, and that [ADR-0068](0068-account-mode-conformance-cases-run-as-root-in-the-gate-image.md) checks.
  - It also writes the §2.5 text that [RFC-0019](../rfcs/0019-identity-model-ssh-user-name-to-os-account.md) §9 says "changes with privilege separation". RFC-0019's other threat-model change, §6.3, is its own ADR's.

## Context

RFC-0020 §9 lists the threat-model changes that its implementation
makes:

- **§8.12** is closed for account mode, and stays as the description of
  service-account mode.
- **§2.5's "Phase-bounded reality"** names service-account mode, and
  says that account mode runs each session as its account.
- **§4.2 gains the launcher boundary:**
  - what the launcher trusts from the server, which is nothing;
  - what it checks;
  - what a compromised server reaches.
- **§3.2.1's and §3.2.4's residuals** say the same about a remote
  compromise of the network server.

The threat model describes what the code does, so these changes land
with the implementation, not before it. This ADR fixes their text, so
that the implementing PR applies it rather than drafts it.

Two of RFC-0020 §9's pointers need a reading:

- **§3.2.1 and §3.2.4 have no residual paragraph of their own.** Each
  ends with "Implication for design", and the threat model collects
  residual risk in §7. This ADR therefore adds one sentence to each
  "Implication for design", and one entry to §7.
- **§8.12's closure condition** asks for "a follow-up RFC superseding
  this entry and removing §8.12". RFC-0020 §9 keeps §8.12, scoped to
  service-account mode, because that mode still runs every session as
  the service account. The text below records that.

Two more sections of the threat model state §8.12's gap as if it held
in every mode: §2.7, on the audit fields, and §5.4.5, on the SFTP
helper. RFC-0020 §9 does not list them, but they become wrong for
account mode, so this ADR scopes them to the two modes too.

## Decision

The implementing PR makes the changes below, with this text. Section
numbers do not change, and nothing links to a §8.12 anchor, so no link
breaks. Links inside the quoted text are relative to
`docs/threat-model.md`, where the text goes, so they do not resolve from
this file.

### 1. §2.5, "Phase-bounded reality": replaces the paragraph

> **Phase-bounded reality.** The authority described above holds in
> account mode, which a configuration selects by listing accounts
> (RFC-0019). Each connection logs in to one listed account, and its
> session runs as that account, with its UID, its primary group and its
> supplementary groups. A single-threaded helper sets them; the root
> launcher starts it, and it checks that root cannot be regained before it
> runs anything (RFC-0020; ADR-0064, ADR-0065). Service-account mode, which
> a configuration with no `[[account]]` entry selects and which macOS
> always uses, runs every command as the OS identity of the QuantumSSH
> service account, not as the authenticated user. §8.12 describes that
> posture.

### 2. §3.2.1 and §3.2.4, "Implication for design": one sentence appended to each

§3.2.1:

> A remote compromise of the process that reads the network must not
> directly yield UID 0. In account mode that process runs as the
> unprivileged service account, and reaches the listed accounts only
> through the launcher (§4.2). A listed account's own way to root, such
> as `sudo` or the `docker` group, stays within reach (§4.2, §7).

§3.2.4:

> In account mode, an intruder who compromises the network server can
> start sessions as any listed account, so the operator's list bounds
> what that compromise reaches (§4.2, §7).

### 3. §4.2: a new block after "What the boundary enforces"

> **In account mode, a second boundary: network server ↔ launcher**
> (RFC-0020; ADR-0063 to ADR-0067).
>
> - *Trusted by the launcher from the server:* nothing.
>   - Every message is bounded and read by a fuzzed parser, and a
>     malformed message ends the service (ADR-0063).
>   - No descriptor, path or program crosses from the server.
>   - The values that do cross are the account's name, the session's
>     kind, the `exec` command and, with a PTY, `TERM`, the window size
>     and the terminal modes. Each has a bound (ADR-0063 §3).
>   - `TERM` must match ADR-0038 §2's pattern, and is the only variable
>     of the session's environment that comes from the server
>     (ADR-0065 §3).
>   - The modes go through the parser the server already uses and
>     fuzzes.
>   - Only the account's shell interprets the command.
> - *Checked by the launcher before each session:*
>   - the account is listed;
>   - it resolves now, in files that pass RFC-0019 §8's check;
>   - its UID is neither 0 nor the network server's (ADR-0064).
>
>   The launcher does not check that the connection authenticated as
>   that account.
> - *Reached by a compromised network server:* a session as any listed
>   account, and through it whatever that account can reach.
>   - That includes root, if the account has a way there such as `sudo`
>     or the `docker` group (ADR-0067).
>   - It never includes UID 0 directly, an unlisted account, or a
>     program the launcher did not choose.
>   - The host key, which the network server holds, is exposed as in
>     service-account mode.
>   - So is the audit log. The network server writes every audit
>     record, `authenticated_identity` and `executing_uid` included
>     (ADR-0024, ADR-0066). A compromised server can write false records
>     for the sessions it starts, or none. The launcher knows which
>     accounts got sessions, but writes no record of them: it shares the
>     server's stderr, so the server could imitate any record it wrote
>     there.
> - *Held by the network server:* the service account's UID, no
>   supplementary groups, no capabilities, and `no_new_privs`
>   (ADR-0066).

### 4. §7: two new entries, after "Compromise of the host or operator account"

> - **Compromise of the network server in account mode** (§4.2).
>   - **What it yields:** a remote code-execution bug in the process
>     that reads the network yields a session as every listed account,
>     and whatever those accounts can reach, including root through
>     `sudo` or a group such as `docker`.
>   - **What it does not yield:** UID 0 directly, or an unlisted
>     account.
>   - **What it can falsify:** the audit records of the sessions it
>     starts. No second process writes an independent record (§4.2).
>   - **The bound** is the operator's list. OpenSSH's monitor verifies
>     authentication itself and bounds the same compromise more tightly
>     (RFC-0020, Alternative 3).
>   - **In service-account mode,** the same compromise yields the
>     service account, which every session already runs as.
> - **One kernel session keyring for every account-mode session**
>   (ADR-0065 §4).
>   - **Who shares it.** Under systemd's default `KeyringMode=private`,
>     the unit's processes share one session keyring: every session of
>     every listed account, and the network server.
>   - **What follows.** A key that one session links into that keyring
>     is within reach of the others, and of a compromised network
>     server.
>   - **The advice.** Until each session gets its own keyring, keep no
>     secret in the session keyring of an account-mode session.

### 5. §8.12: the heading and the text are replaced

> ### 8.12 Per-user UID isolation in service-account mode
>
> In service-account mode, QuantumSSH executes the authenticated user's
> command under the operating system identity of the QuantumSSH service
> account (the account that owns the listening process), **not** under
> the OS identity of the authenticated user. A configuration with no
> `[[account]]` entry selects this mode, and it is the only mode on macOS
> (RFC-0019 §1). Two consequences follow.
>
> First, operators must deploy service-account mode with the assumption
> that any key in `authorized_keys` is operationally equivalent to a key
> for the service account. Its supported posture is single-user: one
> operator, one set of keys, one account. Multi-user deployments use
> account mode.
>
> Second, file system and process accesses performed by commands run in
> this mode inherit the service account's authority, not the
> authenticated user's. Every command-execution record of this mode
> carries `executing_uid = <service account UID>`, and `server.started`
> carries `identity_mode` `service_account` (RFC-0019 §6), so the mode is
> visible in the log.
>
> Account mode closes this non-goal: each session runs as its listed
> account (§2.5, §4.2). RFC-0020 is the follow-up RFC that the original
> closure condition named. See
> [RFC-0002](rfcs/0002-threat-model-phase1-uid-model-and-non-goal.md) and
> [ADR-0016](adr/0016-phase-1-service-account-uid-model.md) for the
> original rationale, and
> [RFC-0020](rfcs/0020-privilege-separation-root-launcher-and-session-helper.md)
> for its closure.

### 6. §2.7 and §5.4.5: scoped to the two modes

§2.7, "What.": the last sentence's ending, "as separate fields, so that
the gap documented in §8.12 is visible to anyone reviewing server logs",
becomes:

> as separate fields. In service-account mode they make the gap
> documented in §8.12 visible to anyone reviewing server logs. In
> account mode `executing_uid` is the listed account's UID, and the
> `account` field names it (RFC-0019 §6).

§5.4.5, "Assets at risk.": the ending "and the files the service account
can reach, which QuantumSSH does not protect from that account in Phase 2
(§8.12)" becomes:

> and the files that the session's account can reach: the service
> account's in service-account mode (§8.12), the listed account's in
> account mode.

§5.4.5, "ATT&CK reference.": the ending "because Phase 2 grants no
confinement to escape" becomes:

> because neither mode confines the helper beyond its account's own
> permissions, so there is no confinement to escape.

§5.4.5, "Test handle.": the last bullet is replaced by:

> - The helper runs as the service account in service-account mode. In
>   account mode it runs as the listed account, after ADR-0065's
>   identity change. In both modes nothing confines it beyond that
>   account: any path the account can reach is reachable, which is the
>   access a `shell` session already has. Confinement is
>   [#270](https://github.com/gonzafg2/quantumssh/issues/270)'s.

### 7. Documents that restate §8.12

The same PR updates every document that describes §8.12 as open in all
modes:

- `README.md`'s "not hardened for production" line and its Phase 3 line;
- `CLAUDE.md`'s status paragraph;
- `docs/deployment.md`'s warning (ADR-0067 §4).

Accepted ADRs and RFCs that cite §8.12 keep their text, as ADR-0015
requires. The text above is what they now point to.

## Consequences

### Positive

- **The implementing PR applies reviewed text.** It does not draft the
  threat model under the pressure of a code review.
- **The new boundary is written in the threat model's own terms:** what
  is trusted, what is checked and what is reached, as §4's other
  boundaries are.

### Negative

- **The text can drift from the code before it lands.** This ADR stays
  Proposed until the implementing PR accepts it. If the implementation
  changes a fact stated here, that PR corrects the text before the
  acceptance.

### Neutral

- **§8.12 keeps its number.** Its scope narrows to service-account mode.

## Alternatives considered

### Alternative 1: draft the text in the implementing PR

Rejected. RFC-0020 §12 assigns the final text to the implementing ADRs.
Text drafted alongside the code would also be reviewed as an afterthought.

### Alternative 2: remove §8.12, as its closure condition says

Rejected. Service-account mode still runs every session as the service
account. Removing the section would leave that posture undescribed.
RFC-0020 §9 keeps it.

### Alternative 3: put the launcher boundary in a new §4.6

Rejected. RFC-0020 §9 places it in §4.2. The launcher boundary also
divides the server's side of §4.2 in two, so it reads best there.

## Links

- [RFC-0020](../rfcs/0020-privilege-separation-root-launcher-and-session-helper.md) §9, §12, Alternative 3.
- [RFC-0019](../rfcs/0019-identity-model-ssh-user-name-to-os-account.md) §1, §6, §8, §9.
- [`docs/threat-model.md`](../threat-model.md) §2.5, §2.7, §3.2.1, §3.2.4, §4.2, §5.4.5, §7, §8.12.
- [ADR-0015](0015-permit-annotated-errata-in-adrs.md), errata in accepted ADRs.
