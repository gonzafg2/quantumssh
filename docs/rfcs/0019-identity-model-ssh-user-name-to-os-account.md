# RFC 0019: The identity model — which operating-system account a connection logs in to

- **Status:** Accepted (2026-11-22). The project lead shortened the 14-day comment period on [#291](https://github.com/gonzafg2/quantumssh/pull/291), with the reason stated there (`docs/rfcs/README.md`, step 5). The four unresolved questions are resolved at acceptance with the answers proposed below.
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-11-21
- **Roadmap issue:** [#248](https://github.com/gonzafg2/quantumssh/issues/248) (Phase 3); the privilege-separation RFC it unblocks is tracked in [#43](https://github.com/gonzafg2/quantumssh/issues/43)
- **Implementation PR:** TBD

## Summary

Today every session runs as the server's own service account
(ADR-0016). The SSH user name a client sends is ignored for a bare key,
and is only matched against a certificate's principals (ADR-0050 §7).
Per-user privilege separation (#43) needs to know which account a
connection is for before it can switch to that account. This RFC decides
that, and only that:

- **The SSH user name names the account.** The first
  `SSH_MSG_USERAUTH_REQUEST` of a connection fixes it, and a later
  request that names another user ends the connection, as in OpenSSH.
- **Only accounts the operator lists can be reached.** The
  configuration gains one entry per account. An account whose UID is 0
  can never be reached, whatever its name.
- **The account record comes from `/etc/passwd` and `/etc/group`,** read
  by the server's own parser. There is no NSS and no PAM.
- **Each account has its own credentials.** A bare key authorizes a
  connection for an account when it is in that account's key file, which
  the operator keeps outside the user's home. A certificate authorizes
  it when its principals include the account's name.
- **The audit records name the account.**
- **Without account entries, nothing changes.** The server keeps
  today's service-account mode, apart from the user-name rule above.

How the server switches to the account (privilege, process layout,
`setuid`, groups, the session's environment) is the privilege-separation
RFC's decision, not this one. This RFC is implemented with it, because an
account the server cannot switch to is not worth naming.

## Motivation

### The gap

Threat model §8.12 says that until Phase 3 "QuantumSSH executes the
authenticated user's command under the operating system identity of the
QuantumSSH service account". Its closure condition is the Phase 3
privilege-separation work and an RFC that supersedes the entry.

The scoping note for that work,
[`docs/plans/phase3-privsep-scoping.md`](../plans/phase3-privsep-scoping.md),
names three prerequisites and calls the identity model "the single
biggest blocker": "a privsep design cannot say 'drop to the user's UID'
until 'which user' is defined". On 2026-11-20 the note recorded where
they stand: the configuration schema (RFC-0010, ADR-0029) and the PTY
design (ADR-0038) exist, and the identity model does not. #43 left open
whether the model gets its own RFC or is decided inside the
privilege-separation RFC. This RFC answers that question by existing:
the two are separate decisions (README, "one decision per RFC"), and
the second is written against the first.

### What the code does today

- **The user name is parsed and bounded** (256 bytes, UTF-8) by
  `auth::parse_userauth_request`, then used only by the certificate
  path. `auth::resolve` looks a bare key up in the one `authorized_keys`
  the server loaded at startup, whatever the user name.
- **A certificate is checked against the user name** (ADR-0050 §7), but
  ADR-0050 says what that is worth: "the principal match fixes the name
  a certificate logs in under, not whether it gets in. Until Phase 3,
  every certificate a trusted CA issued, for any principal,
  authenticates."
- **The user name may change between requests.** Nothing binds it to
  the connection, because nothing depends on it yet.
- **Every `exec.*` record carries `executing_uid`,** the service
  account's UID on every line. Threat model §8.12 says it is first-class
  "precisely so this gap is visible to anyone reviewing logs".

### Who needs it

Any deployment with more than one person or role on a host. Two
operators who should not act as each other, or an `admin` account and a
`deploy` account, cannot be told apart today. ADR-0016 says "every key
in `authorized_keys` is operationally equivalent to a key for the
service account", and that is the posture the README calls "not
hardened for production".

## Guide-level explanation

### Two modes

- **Service-account mode** is today's server. Every session runs as the
  account the server runs as. It is what a configuration without
  `[[account]]` entries gets, and it stays the only mode on macOS, where
  the documented path is Homebrew's single-user evaluation (ADR-0056).
- **Account mode** starts when the configuration lists at least one
  account. Each connection logs in to one listed account, and its
  session runs as that account once privilege separation exists.

### An operator's view

The operator creates the account as usual, writes its key file where
the server's other files live, and lists the account:

```sh
sudo useradd --create-home --shell /bin/bash alice
sudo install -m 0644 -o root -g root alice.pub /etc/quantumssh/keys/alice
```

```toml
schema_version = 1

[server]
host_key = "/etc/quantumssh/host_key"

[auth]
trusted_user_ca_keys = "/etc/quantumssh/user_ca.pub"

[[account]]
name = "alice"
authorized_keys = "/etc/quantumssh/keys/alice"

[[account]]
name = "deploy"
authorized_keys = "/etc/quantumssh/keys/deploy"
```

The grammar above is a sketch. Its exact keys are an implementing ADR's
(§Reference 9).

Then:

- `ssh alice@host` logs in to `alice` with a key from
  `/etc/quantumssh/keys/alice`.
- `ssh -i deploy_key deploy@host` logs in to `deploy`.
- A certificate signed by the trusted CA with
  `ssh-keygen -s user_ca -n alice` logs in to `alice`, and to no other
  account.
- `ssh root@host`, `ssh postgres@host`, or any name not listed, gets
  "Permission denied (publickey).", as a wrong key does.
- Alice's own `~/.ssh/authorized_keys` is not read. Adding a key is the
  operator's job, as adding a listed account is.

### What the audit records show

The records of a session in account mode name the account next to the
key that authenticated it. Account mode ships with privilege separation
(Summary), so `executing_uid` is the account's UID, not the service
account's:

```json
{"schema_version":1,"timestamp":"2026-12-01T10:00:00.000000Z","level":"INFO","event":"exec.started","peer_addr":"192.0.2.7:50022","authenticated_identity":"SHA256:cp4BNirSzGclLcIrv4GSoYcZD47+bqGl0GdHc/vPJE8","account":"alice","executing_uid":1001,"command":"uptime","request_type":"exec","pty":false}
```

## Reference-level explanation

### 1. The modes, and how a configuration selects one

- **Account mode** is selected by one or more `[[account]]` entries.
- **Service-account mode** is selected by none. It keeps today's
  behaviour, with the one change of §2.
- **The two do not mix.** In account mode, `auth.authorized_keys` and
  `--authorized-keys` are a configuration error: there is no
  connection-wide key file to fall back to. In service-account mode they
  stay required, as now.
- **The mode is fixed for the life of the process.** The configuration
  is read at startup and on restart only (RFC-0010).
- **Account mode exists on Linux only** (§4). Elsewhere `[[account]]` is
  a configuration error.

### 2. The user name binds the connection

- **The first `SSH_MSG_USERAUTH_REQUEST` fixes the user name** for the
  connection.
- **A later request with another user name ends the connection** with
  `SSH_DISCONNECT_PROTOCOL_ERROR` (2), before its method is acted on.
  The service name is already fixed: anything but `ssh-connection` ends
  the connection today.
- **The rule holds in both modes.** In service-account mode the name
  selects nothing, but a client has no reason to change it, and one rule
  is simpler to check than two. OpenSSH applies the same rule: its
  `input_userauth_request` disconnects with "Change of username or
  service not allowed".
- **It can land before the rest** of this RFC, because it needs no
  account.

### 3. Which accounts can be reached

In account mode, a connection can log in to an account when all of these
hold:

1. **The configuration lists it,** by its exact name.
2. **`/etc/passwd` has an entry with that name.** The first entry with
   the name counts, as with `getpwnam`.
3. **Its UID is not 0.** This holds for any name, so `toor` with UID 0
   is refused like `root`.

Names follow the rule `useradd(8)` states:

- letters, digits, underscores or dashes, with an optional trailing `$`;
- no leading dash;
- not fully numeric, and not `.` or `..`;
- at most 256 bytes, the bound the user-name parser already applies.

These are configuration errors, at startup:

- a listed name outside the rule, or a name listed twice;
- a listed account whose UID is 0;
- an entry that names no key file when `auth.trusted_user_ca_keys` is
  not set, because nothing could ever log in to it (§5).

**A listed account that cannot be reached right now is not an error.**
That is one with no entry in `/etc/passwd`, or one whose key file holds
no key when `auth.trusted_user_ca_keys` is not set. The server starts,
that account fails closed alone, and a diagnostic record at startup
names it and the reason. Otherwise an operator who ran `userdel`, or
emptied a key file, would find at the next restart that the server
refused to start for every account.

A request for a name that is not listed fails as a wrong key does: one
`SSH_MSG_USERAUTH_FAILURE`, one attempt spent from the budget of threat
model §5.3.1, and no lookup that a listed name would not also make. The
server must not answer an unlisted name differently from a listed name
whose credential fails, in its reply or in its timing. That is what
keeps the list from becoming an account-enumeration oracle. A
credential that does authorize a listed account is answered
differently, as in every SSH server: Drawbacks covers the `PK_OK` case.

### 4. The account record

- **The record holds** the name, UID, primary GID, home directory and
  login shell, from `/etc/passwd`, and the supplementary groups: every
  group in `/etc/group` that lists the name as a member.
- **The server's own parser reads both files.** It is bounded in file
  size, line length and field count, and has no `unsafe`. There is no
  NSS, and no other source of accounts.
- **Both files pass the account-mode file check of §8,** or the server
  refuses to start.
- **The record is read twice.**
  - At startup, to validate every listed account (§3).
  - When a request's credential has verified, and before the server
    sends `SSH_MSG_USERAUTH_SUCCESS`. That record is the one the
    session uses.
- **If that read fails, the request fails as a wrong key does.** The
  account may have left `/etc/passwd`, its UID may have become 0, or the
  files may now fail the account-mode file check of §8. The server answers
  `SSH_MSG_USERAUTH_FAILURE`, spends an attempt, emits `auth.failed`,
  and leaves a diagnostic record with a fixed reason, as ADR-0050 §5
  does for a refused certificate. `auth.succeeded` is emitted only for a
  record that resolved. So a removed account stops working on its next
  connection, without a restart.
- **The read needs a verified credential.** A peer reaches it only by
  proving a key or a certificate for a listed account. Before that,
  nothing in the authentication path reads a file, as now.
- **Linux only.** On macOS, `/etc/passwd` "is consulted directly only
  when the system is running in single-user mode"; Open Directory holds
  the accounts (the file's own header says so). There the documented
  path is Homebrew's single-user evaluation (ADR-0056), where
  service-account mode is the posture.
- **What the record is used for is the privilege-separation RFC's
  decision:** the order of `setgid`, `setgroups` and `setuid`, the
  working directory, `HOME`, `USER` and `SHELL`, and whether `exec` and
  `shell` run the account's login shell or `/bin/sh`, as they do today
  (ADR-0023, ADR-0038).

### 5. The credentials of an account

- **Bare keys.** An entry may name an `authorized_keys` file for the
  account.
  - Its format and rules are those of today's file: `ssh-ed25519` lines
    only, no options (ADR-0040), and loaded at startup.
  - One rule differs. Today a file with no key is an error. In account
    mode it is allowed: the account then has no bare key, and is reached
    by certificate or, with no CA set, not at all (§3).
  - It passes the account-mode file check of §8.
  - A key authorizes a connection for the account whose file lists it,
    and for no other.
  - A key may appear in two accounts' files, for one person with two
    roles. The user name chooses between them.
- **Certificates.** `auth.trusted_user_ca_keys` stays global.
  - A certificate from a trusted CA authorizes a connection for the
    requested account when its principals include the account's name.
    That is ADR-0050's match, which now selects an account.
  - It is also OpenSSH's rule when no `AuthorizedPrincipalsFile` is set:
    "the username of the user must appear in a certificate's principals
    list".
  - Because only listed accounts can be reached (§3), a trusted CA can
    log in to nothing else. A certificate with the principal `postgres`
    does not log in to the `postgres` system account unless the operator
    listed it.
- **The user's home is not read.** No `~/.ssh/authorized_keys`, and no
  file under any path a user can write.
- **PK_OK.** A probe answers `SSH_MSG_USERAUTH_PK_OK` only for a key the
  requested account's file lists, or a certificate that would authorize
  the requested account.

### 6. Audit records

- **A new field, `account`** (string), on `auth.succeeded`,
  `exec.started` and `exec.finished`. It is present in account mode only.
  RFC-0014 §5 allows a new field on an existing event, "conditional only
  if the change that adds it says so"; this RFC says so. It keeps
  `schema_version` 1.
- **`executing_uid` keeps its meaning,** "the OS-facing identity"
  (RFC-0002). It becomes the account's UID once privilege separation
  switches to the account.
- **`authenticated_identity` does not change:** the fingerprint of the
  key that authenticated (RFC-0014 §4).
- **`server.started` gains `identity_mode`** (enumeration:
  `service_account`, `account`), on every start, in both modes. Without
  it a log consumer could tell account mode from service-account mode,
  or from an older binary, only by the absence of `account`. It is a new
  field on an existing event, additive under RFC-0014 §5.
- **`auth.failed` gains nothing.** Logging the user name a client asked
  for would put an unauthenticated, attacker-chosen string in every
  failure record. RFC-0014 escapes control characters, but threat model
  §5.4.3 counts such strings as log injection for any tool that reads
  the log naively. ADR-0050 §5 keeps the same rule for certificates:
  nothing in one is logged on failure, because nothing in it is
  authenticated yet. That is open as an unresolved question below.

### 7. Configuration compatibility

`[[account]]` is a new section of optional keys, an additive change
under RFC-0016 §2: every version-1 file keeps its meaning, and
`schema_version` stays 1. In account mode `auth.authorized_keys`, which
service-account mode requires, must be absent. That narrows nothing a
version-1 file could do before, because before this RFC there was no
account mode. An older binary fails closed on a file that uses
`[[account]]`, naming the section, which is RFC-0010's accepted trade.

### 8. Security properties

- **Fail closed at startup.** The configuration errors of §3 stop the
  start, and so does any file that fails the account-mode file check
  below. A listed account that cannot be reached right now does not
  stop it: it fails closed alone (§3).
- **Fail closed at login.** An account that stopped resolving, or whose
  UID became 0, fails authentication on its next connection (§4).
- **No new pre-authentication input.** The user name is already parsed
  and bounded. Account mode adds an in-memory lookup of it. The only
  file read in the authentication path comes after a credential has
  verified (§4).
- **Only root may own what grants access.** In account mode, every file
  that decides who reaches which account passes ADR-0029's integrity
  check with its owner narrowed to root:
  - the configuration file;
  - `auth.trusted_user_ca_keys`;
  - every account's key file;
  - `/etc/passwd` and `/etc/group`.

  The rest of the check is ADR-0029's: the file is not group- or
  world-writable, and neither is any ancestor directory up to the root,
  over the canonical path. Account mode adds one condition: every
  ancestor directory is owned by root too. The owner of a directory can
  rename and replace its entries whatever their owner, so a user who
  owned the directory of two root-owned key files could swap them, and
  their key would then authorize the other account.
- **No symlinks on the way.** In account mode, each of those paths, as
  configured, must already be its canonical path: absolute, with no
  symlink in any component. Whoever controls a link chooses the file it
  leads to, and checking only the resolved path cannot see that. A user
  who owned the link `/home/alice/keys/deploy` could point it at
  another account's root-owned key file before startup. A path that
  resolves anywhere but itself is a configuration error.
- **A file that fails either rule stops the start.**
- **Why root only.** ADR-0029 also accepts the process UID, which in
  service-account mode is the account the sessions run as. In account
  mode, a file the server's own account could write would let that
  account give itself any listed account:
  - a line in a key file reaches one account;
  - a CA in `auth.trusted_user_ca_keys` reaches every listed name;
  - an `[[account]]` entry in the configuration reaches any account, at
    the next restart.

  This holds whatever privilege the privilege-separation RFC gives the
  server. The host key keeps ADR-0029's check as it is, because it
  grants no access to an account.
- **No confused deputy on user files.** In account mode, every file that
  grants access to an account is owned by root, and none lies under a
  path a user can write. The host key is the one file the server reads
  that may still be owned by the process UID, as ADR-0029 allows.
- **A trusted CA's reach is the list.** That closes the gap ADR-0050 §7
  records, once account mode is in use.

### 9. What the implementation decides, in ADRs

This RFC fixes the model. These operative choices go to implementing
ADRs that cite it:

- the exact grammar of `[[account]]` and its error messages;
- the parser's bounds, and how it treats a malformed line it does not
  need;
- the conformance cases (ADR-0062 §8);
- how the documents change.

The documents that change are:

- threat model §2.5, whose "Phase-bounded reality" paragraph changes
  with privilege separation;
- threat model §6.3, which gains the account binding;
- `docs/deployment.md`, for account mode;
- ADR-0050 §7, partly superseded: a principal now selects an account.

§8.12 is removed by the privilege-separation RFC, not by this one.

## Drawbacks

- **No directory services.** Accounts from LDAP, SSSD, Active Directory
  or FreeIPA are out of reach, because the server reads local files
  only. A site that keeps its accounts in a directory cannot use account
  mode as this RFC defines it. The release binaries are static musl,
  whose `getpwnam` does not read `/etc/nsswitch.conf` either: it reads
  `/etc/passwd`, and asks `nscd` only when the file has no entry. So a
  libc lookup would add `nscd`, not the directory stack.
- **No self-service.** A user cannot add their own key. The operator
  maintains every account's file. That is the point, but it is work, and
  it differs from what OpenSSH users expect.
- **No PAM.** No `pam_limits`, no `pam_env`, no `pam_systemd` session,
  no account policy from PAM modules. Some of that, such as resource
  limits, is the privilege-separation RFC's to provide another way.
- **`/etc/shadow` is not read.** An account locked with `passwd -l`, or
  past its expiry date, can still log in, by key or by certificate, if
  the operator lists it. What stops it:
  - removing it from `[[account]]`, which takes effect at the next
    restart, because the configuration is read at startup only;
  - removing it from `/etc/passwd`, which takes effect on its next
    connection (§4). The next start reports the account as
    unreachable, and does not fail (§3).

  Emptying its key file is not enough. That file is also read at
  startup only, and a certificate whose principals include the name
  still authorizes it. This is an unresolved question.
- **Two modes in one binary,** with their own tests, until a later
  decision retires one.
- **Names are listed twice:** once in `/etc/passwd` and once in the
  configuration.
- **PK_OK still tells a holder of a public key whether it is authorized
  for an account.** Every SSH server that answers probes does, and the
  attacker needs the public key and spends one attempt per guess.

## Rationale and alternatives

### Why the user name, and not the key, selects the account

Every SSH client, and every operator's habit, writes `ssh alice@host`.
OpenSSH matches a certificate's principals against the account name
unless told otherwise. One key can then serve two roles, and the name a
client asked for is the name the audit record shows.

**Alternative 1: the key selects the account,** from a table of
fingerprints to accounts, and the user name is ignored, as today.
Rejected:

- one key could reach only one account;
- the certificate model, whose principals are names, would need a second
  mapping;
- the client's user name would be meaningless and still logged by
  clients, which misleads.

### Why an operator list

**Alternative 2: every account in `/etc/passwd` is reachable,** as with
OpenSSH, which has no list unless `AllowUsers` is set. Rejected.

- A bare key cannot reach an account with no key file, so the list
  matters less for keys.
- For certificates it matters most. A trusted CA would log in to any
  account whose name it signs, system accounts included.
- A list makes the reachable set explicit and reviewable. That is the
  fail-closed shape the rest of the configuration has.

### Why the operator keeps the key files

**Alternative 3: read `~/.ssh/authorized_keys`,** OpenSSH's default
(`.ssh/authorized_keys .ssh/authorized_keys2`). Rejected for now.

- It has the server read files under paths the user controls. Doing that
  safely means reading them as the user, with ownership and symlink
  checks along the path, which depends on privilege separation.
- It moves key control from the operator to each user.

It stays a future possibility. OpenSSH supports the central form too:
`AuthorizedKeysFile` accepts `%u`, so the keys can live in a root-owned
directory such as `/etc/ssh/authorized_keys/%u`. That is the shape
chosen here.

### Why local files, and the server's own parser

**Alternative 4: `getpwnam_r` through libc,** with a crate such as
`nix`. Rejected.

- It adds a dependency to the privileged path. rustix, which the project
  chose over `nix` (ADR-0016's note), lists `getpwnam` among the
  functions it does not implement.
- In the static musl release binaries it reads `/etc/passwd` and asks
  `nscd` only when the file has no entry; it never reads
  `nsswitch.conf`. So it buys `nscd`, not directory services.
- In a glibc build from source it would load NSS modules into the
  privileged process. The same configuration would then reach different
  accounts in a release binary and in a source build.

**Alternative 5: the configuration declares each account's UID, GID and
home,** with no system lookup. Rejected. The system's user database is
the authority on who UID 1001 is, for file ownership above all. A second
copy can disagree with it, silently.

**Alternative 6: systemd's user database,** over its Varlink socket.
Not chosen now. It reaches more account sources than the files do, but
it ties account mode to systemd. It is a future possibility.

### Why no PAM

**Alternative 7: PAM.** Rejected.

- PAM loads C modules into the process that calls it, which would be
  the privileged one.
- A static musl binary cannot load them.
- Its authentication modules serve methods other than public key, and
  the server compiles in no other method (threat model §6.3, RFC-0011).

### Why not decide this inside the privilege-separation RFC

**Alternative 8: one RFC for both.** Rejected.

- "Which account" and "how to become it" can each be wrong on its own.
  An objection to one would block the other.
- The scoping note already found that the second cannot be written until
  the first is settled.

### A departure from RFC-0002's sketch

RFC-0002's "Phase 3 trajectory" sketched rejecting an account "has a
shell of `/usr/sbin/nologin`", and said it committed "to the direction
without committing to the design details". This RFC does not judge the
shell. The record carries it, and whether a `nologin` account may still
use SFTP, for example, is a session decision for the
privilege-separation RFC. Rejecting such accounts here would rule out an
SFTP-only account before that decision is made.

### What not doing this costs

§8.12 cannot close, and the privilege-separation RFC has nothing to
write against.

## Prior art

- **OpenSSH `sshd`.**
  - The user name names the account.
  - `input_userauth_request` in `auth2.c` disconnects on "Change of
    username or service not allowed".
  - An unknown user is authenticated against a fake `passwd` entry
    (`fakepw()`), so the rest of authentication runs the same way for it,
    and it can never succeed.
  - `AuthorizedKeysFile` defaults to `.ssh/authorized_keys
    .ssh/authorized_keys2` and takes `%u`, `%h`, `%U` and `%%`.
  - Without an `AuthorizedPrincipalsFile`, "the username of the user
    must appear in a certificate's principals list".
  - `PermitRootLogin` defaults to `prohibit-password`.
  - `StrictModes` checks "file modes and ownership of the user's files
    and home directory before accepting login".

  Read on 2026-11-21 at `man.openbsd.org/sshd_config` and
  `openssh-portable` `master`.
- **musl.** `src/passwd/getpw_a.c` opens `/etc/passwd` first, and
  queries `nscd` only when the file has no entry
  (`if (!*res && (rv == 0 || rv == ENOENT || rv == ENOTDIR))`). It never
  reads `/etc/nsswitch.conf`.
- **rustix** lists `getpwnam`, `getpwnam_r`, `getpwuid` and `getpwuid_r`
  under `not_implemented::higher_level`.
- **`useradd(8)`,** from shadow-utils, states the user-name rule §3
  adopts.
- **ADR-0050 §7 and RFC-0002's "Phase 3 trajectory"** are the project's
  own earlier statements of the problem.

## Unresolved questions

All four were resolved at acceptance, with the proposed answer each one gives.

1. **Locked and expired accounts.** Should account mode read
   `/etc/shadow` and refuse an account that `passwd -l` locked or whose
   expiry has passed? It would mean reading a root-only file of password
   hashes in the privileged process. Proposed answer: no. The list is the
   control, and `docs/deployment.md` says what stops a locked account
   and when (Drawbacks).
2. **The requested user name on `auth.failed`.** Proposed answer: not
   logged, for the reasons in §6. An operator who wants to see attempts
   on `root` would lose that view.
3. **The user-name rule ahead of the rest.** §2 can land before account
   mode. Proposed answer: yes, as a plain PR with its conformance case,
   because it tightens the pre-authentication path and needs nothing
   else.
4. **Per-account settings,** such as a forced command, `permit_pty` or
   SFTP only. Proposed answer: not in this RFC. `[[account]]` is where
   they would go.

## Future possibilities

- **More account sources:** `nscd`, or systemd's user database, each
  behind its own decision.
- **Per-user key files,** read as the user once privilege separation
  can do that safely.
- **A principals mapping,** so that a certificate principal such as
  `alice@example.org` maps to the account `alice`, like OpenSSH's
  `AuthorizedPrincipalsFile`.
- **Group-based lists,** so that every member of an operator-named group
  can be reached.
- **Per-account policy** (unresolved question 4).
