# RFC 0013: SFTP subsystem — a first-party SFTP v3 server in a re-exec helper

- **Status:** Draft
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-10-12
- **Roadmap issue:** [#109](https://github.com/gonzafg2/quantumssh/issues/109)
- **Implementation PR:** TBD

## Summary

QuantumSSH honours `exec`, `shell` and `pty-req` but refuses the
`subsystem` request ([ADR-0038](../adr/0038-phase-2-interactive-pty-sessions.md)
§1: "SFTP is its own workstream"). This RFC makes one shape-determining
decision: **QuantumSSH serves the `sftp` subsystem with its own SFTP
version 3 server, written in Rust with no first-party `unsafe`, running as a
helper mode of the `quantumssh` binary that the channel layer starts as an
ordinary pipe child.** The helper is single-threaded and synchronous. It
inherits the channel layer's process supervision, it runs as the same UID
as every other channel child, and it is the place where Phase 3 will drop
privileges.

The RFC also sets the protocol profile (version 3 only, OpenSSH's 256 KiB
packet bound, four `@openssh.com` extensions), the filesystem semantics,
and the audit record. Implementing ADRs lock the details.

## Motivation

- **SFTP is in the `0.1.0` MVP.** "public-key authentication, command
  execution, an interactive PTY shell, and SFTP" (`README.md:57`). The
  Phase-2 roadmap lists it ([#109](https://github.com/gonzafg2/quantumssh/issues/109)).
- **`scp` needs it.** OpenSSH's `scp` uses SFTP by default: `mode =
  MODE_SFTP` (openssh-portable `V_10_6_P1`, `scp.c:458`), and it runs
  `ssh -s host sftp` (`scp.c:1004`). Against today's server both `scp` and
  `sftp` fail, because the client treats a `CHANNEL_FAILURE` on its primary
  session as fatal (`clientloop.c:845-846`).
- **The threat model expects a session-level record of SFTP use.** §5.4.4
  scopes exfiltration out of QuantumSSH-side defence, and names the server's
  contribution as "a session recorded as having opened an SFTP subsystem,
  transferred N bytes, and closed it".
- **It does not need channel multiplexing.** ADR-0038's Consequences
  ("SFTP brings multiplexing") and the Phase-2 scoping note expected that it
  would. It does not: `sftp` and `scp` open one `session` channel and send
  `subsystem "sftp"` on it (`sftp.c:2724-2730`, `clientloop.c:2799-2803`).
  ADR-0023's one channel per connection therefore holds. The implementing
  PR records this correction as a post-acceptance erratum on ADR-0038
  (ADR-0015).

## Guide-level explanation

After this RFC is implemented, the stock OpenSSH tools work against
QuantumSSH:

```sh
sftp -P 2222 user@host          # interactive: ls, cd, get, put, rename, rm, mkdir
scp -P 2222 report.pdf host:    # upload, over SFTP
scp -P 2222 host:logs.tar .     # download, over SFTP
```

What an operator should know:

- **Same identity, same access.** An SFTP session runs as the service
  account, like `exec` and `shell` (ADR-0016; threat model §8.12). It
  starts in the service account's home directory. It can reach exactly the
  files a `shell` session can reach, so SFTP grants no access that the
  server does not already grant. There is no chroot in Phase 2, because it
  needs privileges the service account does not have. Per-user identity
  and confinement are Phase 3.
- **Default on, no new configuration key.** SFTP is part of the MVP, like
  the PTY.
- **One record per session.** `exec.started` and `exec.finished` carry
  `request_type = "subsystem"` and `command = "sftp"`, and `exec.finished`
  carries the bytes moved in each direction. File names and contents are
  not logged.

## Reference-level explanation

### 1. The `subsystem` request

- **When it is honoured.** `subsystem` (RFC 4254 §6.5) with the name `sftp`
  is honoured once, in `Idle`. It is exclusive with `exec` and `shell`, as
  they are with each other (ADR-0038 §1).
- **What is refused.** Any other subsystem name gets
  `SSH_MSG_CHANNEL_FAILURE` when `want_reply` is set. So does `subsystem`
  after a `pty-req`: SFTP is a binary protocol, and a terminal's line
  discipline would corrupt it. No SFTP client asks for a PTY.
- **How it runs.** The child is started on pipes: stdin and stdout carry
  the SFTP stream, and stderr goes out as `EXTENDED_DATA`. It is the
  ordinary pipe child of [ADR-0038](../adr/0038-phase-2-interactive-pty-sessions.md)
  §6:
  - its own process group;
  - the sanitised environment of ADR-0016;
  - reaping, kill guards and early close as for `exec`;
  - `exit-status`, or `exit-signal`, on the way out.

### 2. The helper

- **Process.** The child is the `quantumssh` binary in a reserved helper
  mode, dispatched first in `main` next to the PTY helper (ADR-0038 §5),
  before CLI parsing, configuration, logging or the runtime. The executable
  is the one `server::Config` already names for the PTY helper.
- **Execution model.** The helper is single-threaded and synchronous. It
  uses blocking `std` I/O on fds 0 and 1, the filesystem through `std::fs`
  and `rustix`, no Tokio and no `tracing` subscriber. Its stderr belongs to
  the client, so it never writes there.
- **Lifetime.** It changes to `$HOME` from the sanitised environment, as
  sshd's session child does (`session.c:1586`), or to `/` if `$HOME` is
  missing or unusable. It serves until EOF on stdin, then closes every
  handle and exits 0.
- **Library boundary.** The protocol, its parser and the request handlers
  live in a new `quantumssh-core` module, `sftp`. The parser is a pure
  function over a bounded byte slice, so it can be fuzzed (threat model
  §4.1's rule for parsers, applied here although SFTP is post-auth).

### 3. Protocol profile

The base is version 3, as specified by `draft-ietf-secsh-filexfer-02` and
implemented by OpenSSH ("Newer versions … will not be supported",
`PROTOCOL:4-10`).

- **Handshake.**
  - The first packet must be `SSH_FXP_INIT`. Anything else ends the
    session.
  - The reply is `SSH_FXP_VERSION` with version 3, whatever the client
    offered, as OpenSSH's server answers (`sftp-server.c:707-714`).
- **Framing and bounds.**
  - A packet is `uint32 length`, `byte type` and the payload.
  - A length above **256 KiB** (OpenSSH's `SFTP_MAX_MSG_LENGTH`,
    `sftp-common.h:29`), a truncated field, or bytes read past the packet
    end the session. The helper exits with a nonzero status and the
    channel closes. That is fail-closed, and it is what OpenSSH does
    (`sftp-server.c:1835-1838`).
  - Every bound is explicit:
    - READ lengths are clamped to 256 KiB − 1024 (`sftp-server.c:55`,
      `:808-811`);
    - a READDIR reply holds at most 100 names, and never exceeds the
      packet bound;
    - handles are 4-byte opaque indices into a table with a fixed cap,
      which `limits@openssh.com` reports;
    - an ATTRS extended-attribute count is bounded by the packet;
    - every path and string is bounded by the packet.
  - The server never sends a packet over 256 KiB, and never returns more
    DATA than was requested. The client kills the session otherwise
    (`sftp-client.c:195-199`, `:1768`).
- **Requests.** OPEN, CLOSE, READ, WRITE, LSTAT, FSTAT, SETSTAT, FSETSTAT,
  OPENDIR, READDIR, REMOVE, MKDIR, RMDIR, REALPATH, STAT, RENAME, READLINK
  and SYMLINK, plus EXTENDED.
  - **Every request gets exactly one response** (draft-02: "Exactly one
    response will be returned for each request"). An unknown request type
    gets `SSH_FX_OP_UNSUPPORTED`. OpenSSH sends nothing in that case
    (`sftp-server.c:1876-1877`); QuantumSSH follows the draft.
  - **SYMLINK takes its arguments in OpenSSH's reversed order**, target
    path first. That is the order the deployed client sends
    (`PROTOCOL:386-397`).
- **Responses.**
  - **STATUS** always carries the error message and the language tag,
    because the client parses them unconditionally
    (`sftp-client.c:1068-1070`). Errors map to the v3 codes from errno.
    `NO_CONNECTION` and `CONNECTION_LOST` are never sent ("MUST NOT be
    returned by servers").
  - **ATTRS** carry size, uid/gid, permissions and times.
  - **The NAME longname** uses numeric uid and gid. Resolving names needs
    the platform's account database, which `std` and `rustix` do not
    expose without `unsafe`.
- **Extensions advertised:**

  | Extension | Why |
  |---|---|
  | `limits@openssh.com` | Lets the client size its requests. If advertised it must be answered, or `sftp_init` fails (`sftp-client.c:553-556`). |
  | `posix-rename@openssh.com` | The client's `rename` prefers it (`sftp-client.c:1242`). |
  | `fsync@openssh.com` | `sftp put -f`. Without it the client silently skips the fsync (`:1362-1364`). |
  | `expand-path@openssh.com` | `~` and `~/…` for the service account. `~user` gets `NO_SUCH_FILE` for now, because resolving another account's home needs the account database. |

  Not advertised, with the effect on the 10.6 client: `statvfs`
  (`df` errors), `hardlink` (`ln` without `-s` errors), `lsetstat`
  (`chmod -h` errors), `copy-data` (`cp` errors), `users-groups-by-id`
  (`ls -l` shows the numeric longname) and `home-directory` (unused by the
  10.6 client). None is needed by `scp` or by `sftp`'s get, put, ls,
  rename, rm, mkdir or rmdir.

### 4. Filesystem semantics

- **Who and where.** Operations run as the service account, on paths
  resolved by the kernel relative to the helper's working directory. There
  is no confinement in Phase 2 (see the guide-level explanation).
- **Symlinks.** OPEN, STAT, OPENDIR and SETSTAT follow them; LSTAT does
  not. REALPATH resolves them with a bounded depth and succeeds when only
  the last component is missing, as OpenSSH's does
  (`sftp-realpath.c:161-173`).
- **Open flags and create mode.**
  - `READ`, `WRITE`, `APPEND`, `CREAT`, `TRUNC` and `EXCL` map to the
    corresponding open flags.
  - A created file gets the requested permissions masked to `0777`, so no
    setuid, setgid or sticky bit is created on open. MKDIR is masked the
    same way. The inherited umask applies on top.
  - SETSTAT and FSETSTAT apply `chmod` with `07777`, like chmod(1): a
    `shell` session can already do this.
- **FSETSTAT with SIZE** truncates (`ftruncate`). Every plain `scp`
  upload uses it, because the upload is in place without `TRUNC`
  (`sftp-client.c:2248-2253`).
- **RENAME** refuses to overwrite an existing target. `posix-rename`
  overwrites. These are OpenSSH's two semantics (`sftp-server.c:1274-1314`).

### 5. Audit (ADR-0024, ADR-0038 §9)

- **Events.** A subsystem session emits `exec.started` and
  `exec.finished`, like every child the channel layer starts. They carry
  `request_type = "subsystem"`, `command = "sftp"` and `pty = false`, plus
  the mandatory `authenticated_identity` and `executing_uid`.
- **Byte counts.** `exec.finished` gains `bytes_received` and `bytes_sent`
  for every request type: the channel payload bytes the child received and
  sent. For SFTP this is threat model §5.4.4's "transferred N bytes", and
  it includes protocol framing.
- **Never logged.** Paths, file names, file content and handles.
  Per-operation records would need a side channel from the helper (see
  Future possibilities).
- **Freeze.** This is an additive change before the `0.1.0` audit-schema
  freeze (Phase-2 scoping note, freeze checklist). The implementing PR
  records it in ADR-0024's Status field, as ADR-0038 did.

### 6. Tests

- **Unit tests:** the packet parser (bounds, truncation, the INIT-first
  rule) and each request handler, on a temporary directory.
- **Integration tests:** they drive `subsystem sftp` through the shared
  SSH test client (`crates/quantumssh-core/tests/support`) and re-execute
  the real binary from the binary crate, as the PTY tests do
  (ADR-0038 §11).
- **Interop gate (ADR-0020):** `sftp -b` (put, get, ls, rename, rm, mkdir,
  rmdir) and `scp` in both directions, with a byte-for-byte check.
- **Fuzzing:** the parser is shaped for a `cargo-fuzz` target. The fuzzing
  harness itself is threat model §6.2's Phase-3 deliverable.

## Drawbacks

- **The largest attacker-reachable parser after the transport.** SFTP is
  post-authentication, but every packet field is controlled by the peer,
  and the handlers touch the filesystem. It is first-party code that has to
  earn trust through bounds, tests and fuzzing. OpenSSH's sftp-server has
  had two decades of exposure.
- **No confinement in Phase 2.** The service account's whole view of the
  filesystem is reachable. That matches `shell`, but SFTP makes bulk access
  more convenient. Operators who need confinement must wait for Phase 3,
  or keep the service account's permissions narrow.
- **Partial extension set.** `df`, `ln`, `cp`, `chmod -h` and named
  `ls -l` owners do not work until their extensions are added.
- **More audit fields before the freeze.** `bytes_received` and
  `bytes_sent` widen the schema that `0.1.0` freezes.

## Rationale and alternatives

### Alternative 1: run OpenSSH's `sftp-server` as the subsystem command

This is what sshd's `Subsystem sftp /usr/lib/openssh/sftp-server` does
(`session.c:1939`, `:1672-1676`). It is the least code, and it is
battle-tested. It was not chosen:

- **It is C code in the session path.** The most-used file-transfer surface
  would be memory-unsafe code. That contradicts the project's first
  commitment for a core MVP feature, even though the code is a runtime
  dependency rather than first-party.
- **It depends on the host.** Hosts without OpenSSH installed, a different
  `libexec` path, and the host's own version drift would all decide whether
  the feature works. None of that is visible to `cargo deny`.

### Alternative 2: a Rust SFTP crate

`russh-sftp` (3.0.1 on crates.io) is described as an "SFTP subsystem
supported server and client for Russh". It was not chosen:

- It belongs to the russh ecosystem that RFC-0003 declined to build on.
- It would expand the trust base with a large dependency in the
  file-access path, which needs its own RFC-level justification.
- Like most Rust SFTP crates, it is async and meant to run in-process,
  which is the shape Alternative 3 rejects.

### Alternative 3: an SFTP server inside the server process

This would be an async handler on the runtime, with `tokio::fs` or the
blocking pool. It saves a process per session. It was not chosen:

- **Phase 3 needs per-user identity changes in an isolated, single-threaded
  context, never inside the Tokio process** (Phase-3 privsep scoping note,
  option C). File access in the server process would have to be torn out
  again then.
- **A parser bug would run in the process that holds the host key** and
  every other connection.

### Alternative 4: wait for Phase 3

SFTP could land directly with privilege separation and chroot. It was not
chosen: it would keep `scp` and `sftp` broken through `0.1.0`, and the
helper chosen here is already the Phase-3 shape, so nothing is thrown away.

### Why this design

The helper reuses the mechanism ADR-0038 just accepted: a re-exec mode, an
ordinary channel child, and the existing supervision and audit. It keeps
the file-access code out of the server process. And it is the
single-threaded point Phase 3 needs: the privilege drop and a chroot go in
the helper before it serves its first request.

## Prior art

- **OpenSSH** implements version 3 in `sftp-server.c`, as an external
  binary or as sshd's `internal-sftp` (`session.c:1613-1630`). Its
  extensions are documented in `PROTOCOL`. Its 256 KiB packet bound, read
  clamp and STATUS conventions are the de facto interoperability contract
  this RFC adopts.
- **`draft-ietf-secsh-filexfer-02`** (version 3) defines the protocol.
  Later drafts (versions 4–6) were never adopted by OpenSSH.
- **The PTY helper** (ADR-0038 §5) established the re-exec helper pattern
  in this codebase.

## Unresolved questions

1. **The extension set.** Should `statvfs@openssh.com` and
   `hardlink@openssh.com` join the initial four? Each is cheap to implement
   and makes a client command work, but each also adds surface.
2. **A switch.** Should `[sftp] enabled` and/or `read_only` exist in the
   configuration file (RFC-0010 v1 schema), or should SFTP stay
   unconditionally on, like the PTY? This RFC proposes no key, on
   YAGNI grounds.
3. **`bytes_received` and `bytes_sent` for every request type, or only for
   subsystems?** This RFC proposes every type, for one uniform `exec.finished`.
4. **The handle cap.** What value should it have? OpenSSH bounds it only by
   `RLIMIT_NOFILE`.

## Future possibilities

- **Phase 3:** the helper drops to the authenticated user's UID and
  optionally chroots before serving. The scoping note's option C maps onto
  it directly.
- **Per-file audit records**, such as "opened", "closed" and bytes read and
  written per path, through a dedicated pipe from the helper that the
  server validates and re-emits through `tracing`. Paths would be
  structured, escaped fields (ADR-0024).
- **A read-only mode**, like OpenSSH's `-R`, as a per-key restriction once
  per-key restrictions exist (ADR-0040).
- **The remaining `@openssh.com` extensions.**
