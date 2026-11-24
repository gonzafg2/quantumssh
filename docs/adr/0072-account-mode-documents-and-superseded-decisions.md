# ADR 0072: The documents account mode changes, and the accepted decisions it supersedes in part

- **Status:** Proposed
- **Date:** — (set on acceptance; drafted 2026-11-24)
- **Deciders:** Project lead
- **Related:**
  - It is the last item of [RFC-0019](../rfcs/0019-identity-model-ssh-user-name-to-os-account.md) §9, "how the documents change". It covers the documents RFC-0019 §9 lists, except threat model §2.5, whose text [ADR-0069](0069-threat-model-text-for-account-mode.md) §1 already fixes.
  - It also adds the Status notes that the accepted decisions changed by RFC-0019 and by [RFC-0020](../rfcs/0020-privilege-separation-root-launcher-and-session-helper.md) §10 need. ADR-0069 fixes the rest of the threat-model text.
  - RFC-0019 §9's third item, the conformance cases, is [ADR-0068](0068-account-mode-conformance-cases-run-as-root-in-the-gate-image.md).

## Context

RFC-0019 §9 names the documents that change with account mode:

- threat model §2.5;
- threat model §6.3, "which gains the account binding";
- `docs/deployment.md`, for account mode;
- ADR-0050 §7, "partly superseded: a principal now selects an account".

Two parts of RFC-0019 are document work, not code:

- **Its unresolved question 1** answers locked accounts with a sentence
  in `docs/deployment.md`. The guide says "what stops a locked account
  and when".
- **Its §5** loads key files at startup. So removing a key takes effect
  at a restart, while removing an account takes effect at the next
  connection (§4). An operator needs that difference spelled out.

RFC-0020 §10 changes six accepted decisions in account mode: ADR-0016,
RFC-0002 §8.12, RFC-0019 §4, ADR-0038 §4, §5 and §10, ADR-0041 and
ADR-0043. RFC-0019 §8 narrows ADR-0029's file-owner rule in account
mode. An accepted ADR changes only through a superseding decision, and
its own text may change only in its Status field or by errata
(ADR-0015).

## Decision

The implementing PR makes these changes, with this text.

### 1. Threat model §6.3

The last two sentences of the "User certificates from operator-listed
CAs" bullet are "Until Phase 3 maps principals to accounts, the CA file
is the access boundary: every certificate a trusted CA issued gets in,
whatever its principal." They are replaced by:

> In service-account mode the CA file is the access boundary: every
> certificate a trusted CA issued gets in, whatever its principal. In
> account mode a certificate logs in only to the listed account that its
> principals name, so the operator's list bounds what a trusted CA can
> reach (RFC-0019 §5).

A new bullet follows that one:

> - **Account binding (account mode).** RFC-0019 §2, §3, §5 and §8.
>   Defends §5.3.1 and §5.3.3.
>   - **The user name is fixed at the first request.** The first
>     `SSH_MSG_USERAUTH_REQUEST` fixes it, and a later request with
>     another name ends the connection.
>   - **The name selects one operator-listed account.** A key
>     authorizes only the accounts whose key files list it, and a
>     certificate only the account its principals name.
>   - **An unlisted name fails as a wrong key does,** in its reply and
>     in its timing, so the list is not an enumeration oracle.
>   - **Every file that grants access to an account** is owned by root,
>     with root-owned ancestors and no symlink. The server never reads
>     a user's home.

### 2. `docs/deployment.md`

A new section, "Account mode", after "Write the configuration". It
covers:

- **When to use it.** On Linux, when each person should log in to their
  own account. Service-account mode stays the single-user path, and the
  only one on macOS.
- **Setting it up:**
  - create the accounts;
  - install each key file with `install -m 0644 -o root -g root`;
  - list the accounts in `[[account]]` (ADR-0070);
  - keep the service account `quantumssh`, which must not be listed
    (ADR-0066 §1).
- **The unit.** Install ADR-0067's unit in place of the
  service-account-mode one.
- **File ownership.**
  - The configuration, the CA file and every key file are owned by root,
    in root-owned directories, with no symlink (RFC-0019 §8).
  - The host key stays owned by `quantumssh` with mode `0600`.
- **When a change takes effect:**

  | Change | Takes effect |
  |---|---|
  | Remove an account from `[[account]]` | at the next restart |
  | Remove a key from an account's key file | at the next restart, because key files load at startup |
  | `userdel` the account, or give it UID 0 | at its next connection, which fails as a wrong key does (RFC-0019 §4) |
  | Remove the account from a group | at its next session (ADR-0064 §2) |
  | `passwd -l` or an expiry date | never: account mode does not read `/etc/shadow` (RFC-0019's unresolved question 1). Remove the account from `[[account]]` and restart, or remove it from `/etc/passwd`. Emptying its key file is not enough when `auth.trusted_user_ca_keys` is set: a certificate whose principals include the name still logs in (RFC-0019's Drawbacks, §5) |

- **RFC-0020 §8's warning, as it stands.** List only accounts whose
  whole privilege you accept exposing to a compromise of the network
  server, their ways to become root included.
- **The shared session keyring** of ADR-0065 §4, until
  [#299](https://github.com/gonzafg2/quantumssh/issues/299) closes it.

### 3. Superseded in part, and Status notes

This ADR supersedes **ADR-0050 §7** in account mode:

- A certificate's principal selects the account: the requested listed
  account must be among its principals.
- The CA file stops being the whole access boundary. The list bounds
  what a CA can reach.
- In service-account mode, §7 stands as written.

The implementing PR adds one Status note to each of these documents. It
changes nothing else in them (ADR-0015):

| Document | Note |
|---|---|
| ADR-0016 | Superseded for account mode by RFC-0020 and ADR-0063 to ADR-0067; it still describes service-account mode |
| ADR-0029 | In account mode, RFC-0019 §8 narrows the file owner to root and forbids symlinks (ADR-0070 §3) |
| ADR-0038 | In account mode, §4's allocation and §5's helper run from the launcher (ADR-0064, ADR-0065), and the slave belongs to the account, which settles §10's Phase-3 question |
| ADR-0041 | In account mode, the SFTP server runs in the session helper as the account (ADR-0065 §2) |
| ADR-0043 | Its unit is the service-account-mode unit; account mode uses ADR-0067's |
| ADR-0050 | §7 superseded in part, for account mode, by ADR-0072 §3 |

RFC-0002 §8.12 and RFC-0019 §4 are RFCs. RFC-0020 §10 already records
how they change, so they get no note.

### 4. What ADR-0069 already covers

The threat model's other sections are ADR-0069's:

- §2.5, §2.7, §3.2.1, §3.2.4, §4.2, §5.4.5, §7 and §8.12;
- the `README.md` and `CLAUDE.md` lines that describe §8.12 as open.

This ADR does not repeat them.

## Consequences

### Positive

- **An operator learns from one section** how to set up account mode,
  what it exposes, and when each change takes effect. The silent case,
  `passwd -l`, is called out.
- **A reader of an older ADR is pointed at what changed.** The Status
  notes say so, and no accepted text is rewritten.

### Negative

- **Six Status notes in one PR.** Each one is a line, but each must
  stay true as the implementation lands.

### Neutral

- **Service-account documents keep their meaning.** Every note limits
  itself to account mode.

## Alternatives considered

### Alternative 1: a separate account-mode guide

Rejected. The setup shares the install, the logs and the stop behaviour
with the existing guide, and two guides would drift apart.

### Alternative 2: superseding ADRs for each changed decision

Rejected. RFC-0020 and RFC-0019 are the superseding decisions, and
ADR-0063 to ADR-0072 implement them. A Status note pointing at them is
what ADR-0015 allows, and a new ADR per note would restate them.

### Alternative 3: read `/etc/shadow` so that `passwd -l` works

Rejected by RFC-0019's unresolved question 1. It would mean reading
password hashes in the privileged process.

## Links

- [RFC-0019](../rfcs/0019-identity-model-ssh-user-name-to-os-account.md) §2, §3, §4, §5, §8, §9, unresolved question 1; [RFC-0020](../rfcs/0020-privilege-separation-root-launcher-and-session-helper.md) §8, §10.
- [ADR-0015](0015-permit-annotated-errata-in-adrs.md); [ADR-0050](0050-accept-openssh-user-certificates.md) §7.
- [`docs/threat-model.md`](../threat-model.md) §6.3; [`docs/deployment.md`](../deployment.md).
