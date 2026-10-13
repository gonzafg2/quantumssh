# ADR 0041: SFTP v3 server in a re-exec helper — request handling, bounds and file operations

- **Status:** Accepted
- **Date:** 2026-10-26 (accepted with the implementing PR [#196](https://github.com/gonzafg2/quantumssh/pull/196), on RFC-0013's acceptance; drafted 2026-10-12)
- **Deciders:** Project lead
- **Related:** Implements [RFC-0013](../rfcs/0013-sftp-subsystem.md)
  (Accepted, [#194](https://github.com/gonzafg2/quantumssh/pull/194)), which
  decides the shape; this ADR locks the operative details and answers the
  RFC's unresolved questions 1, 2 and 4 (question 3 is
  [ADR-0042](0042-exec-finished-channel-byte-counts.md)). Extends
  [ADR-0038](0038-phase-2-interactive-pty-sessions.md) §1 (`subsystem` is
  no longer refused) and §5 (a second helper mode). Constrained by
  [ADR-0016](0016-phase-1-service-account-uid-model.md) (service account,
  sanitised environment), [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md)
  (`unsafe_code = "forbid"`), [ADR-0023](0023-phase-1-channel-layer-scope.md)
  (one channel per connection) and [ADR-0024](0024-phase-1-log-event-schema.md)
  (audit schema). Part of the Phase-2 milestone
  ([#109](https://github.com/gonzafg2/quantumssh/issues/109)).

## Context

RFC-0013 decides that QuantumSSH serves `subsystem "sftp"` with its own
SFTP version 3 server. That server runs in a single-threaded helper mode
of the `quantumssh` binary, which the channel layer starts as an ordinary
pipe child. The RFC sets the profile: version 3, OpenSSH's 256 KiB packet
bound, four `@openssh.com` extensions, file operations as the service
account, and a session-level audit record. It leaves the exact bounds,
the operation mapping and four open questions to implementing ADRs.

The interoperability contract is the stock OpenSSH 10.x client. Five of
its behaviours decide whether `sftp` and `scp` work at all
(openssh-portable `V_10_6_P1`):

- it kills the session on any packet over 256 KiB, or on DATA longer than
  requested (`sftp-client.c:195-199`, `:1768`);
- it parses STATUS's message and language strings unconditionally
  (`sftp-client.c:1068-1070`);
- if `limits@openssh.com` is advertised it must be answered, or
  `sftp_init` fails (`:553-556`);
- every plain `scp` upload truncates with FSETSTAT carrying SIZE
  (`:2248-2253`);
- SYMLINK takes its arguments in reversed order (`PROTOCOL` §4.1).

## Decision

We will implement the SFTP server as a `quantumssh-core` module, `sftp`,
run by a reserved helper mode of the binary, with the bounds, operation
mapping and extension set below.

### 1. Channel request

- **Parsing.** `subsystem` (RFC 4254 §6.5) carries one string, the name,
  bounded to 64 bytes. A truncated or oversized name is
  `SSH_DISCONNECT_PROTOCOL_ERROR`, as every channel-request parser does.
- **Honoured** when all of these hold:
  - the name is `sftp`;
  - the channel is `Idle`;
  - no PTY is pending (no `pty-req` was granted);
  - a helper executable is configured.
- **Refused** otherwise, with `SSH_MSG_CHANNEL_FAILURE` when `want_reply`
  is set, and no state is created.
- **Start.** The child is the helper executable with the argument
  `--quantumssh-internal-sftp-server`, on pipes. It gets the ordinary pipe
  child of ADR-0038 §6:
  - its own process group;
  - ADR-0016's sanitised environment;
  - reaping, kill guards and early close (ADR-0023, #191);
  - `exit-status` or `exit-signal` on the way out.
- **Audit.** `exec.started` and `exec.finished` carry
  `request_type = "subsystem"`, `command = "sftp"` and `pty = false`, plus
  ADR-0042's byte counts on `exec.finished`.

### 2. The helper and the library boundary

- **Dispatch.** `quantumssh_core::sftp::run_server_if_requested()` is
  called in `main` right after ADR-0038's `pty::run_helper_if_requested()`,
  before CLI parsing, configuration, logging or the runtime. It never
  returns when the argument selects it.
- **The executable is shared.** `server::Config::pty_helper` becomes
  `server::Config::helper`: the same binary hosts both helpers. `None`
  refuses both `pty-req` and `subsystem`.
- **Startup.** The helper changes to `$HOME`, or to `/` if that fails, as
  sshd's session child does (`session.c:1586`).
- **Serving.** It reads framed requests from fd 0 through a buffered
  reader. It writes each response to fd 1 and flushes it before reading
  the next request. It never writes to fd 2, which belongs to the client.
- **Exit status.** 0 at EOF on stdin at a packet boundary. 2 on a
  protocol violation, EOF inside a packet included, or when reading stdin
  or writing stdout fails. Open handles are closed on either
  path.

### 3. Framing and bounds

| Bound | Value | Source |
|---|---|---|
| Packet length (type + payload) | ≤ 262 144 bytes (256 KiB) | `sftp-common.h:29` |
| READ length served | clamped to 261 120 bytes (256 KiB − 1024) | `sftp-server.c:55`, `:808-811` |
| WRITE data | bounded by the packet | — |
| Names per READDIR reply | ≤ 100, and the reply ≤ the packet bound | `sftp-server.c:1160-1163` |
| Open handles (files + directories) | ≤ 256 | this ADR (RFC-0013 question 4) |
| Handle encoding | a 4-byte big-endian index | `sftp-server.c:362-384` |

**Malformed input ends the session.** The helper exits with 2 in each of
these cases:

- a length over the bound;
- a truncated field;
- a request read past its packet;
- any first packet other than `SSH_FXP_INIT`.

A handle that is not 4 bytes, or names no open handle, gets
`SSH_FX_FAILURE`, and the session continues. An OPEN or OPENDIR beyond the
cap also gets `SSH_FX_FAILURE`. The cap is checked before the open, so a
refused OPEN has not created or truncated a file.

**Every request gets exactly one response.** An unknown request type and
an unknown EXTENDED name get `SSH_FX_OP_UNSUPPORTED`. The server never
sends a packet over the bound, and never returns more DATA than was
requested.

**Handshake.** INIT's version and extension data are read and ignored.
The reply is VERSION 3 with these extension pairs, in this order, each
with version `"1"`: `posix-rename@openssh.com`, `fsync@openssh.com`,
`limits@openssh.com`, `expand-path@openssh.com`.

**ATTRS.**
- Parsing: unknown flag bits are ignored, as OpenSSH does
  (`sftp-common.c:103-151`). The extended-pair count is bounded by the
  packet.
- Sending: size, uid/gid, permissions (the full `st_mode`, file type
  included) and atime/mtime as 32-bit seconds, with values beyond `u32`
  clamped.

### 4. Operations

Operations use `std::fs`, `std::os::unix::fs` and `rustix` safe functions
only.

**Paths.** A path argument is the bytes as sent, resolved by the kernel
against the working directory (§2). An empty path is read as `.`, as
RFC-0013 §4 requires; OpenSSH's `sftp-server` does this only for
REALPATH and `expand-path` (`sftp-server.c:1243-1246`, `:1559-1562`).
SYMLINK's target is link content and is stored as sent.

| Request | Operation |
|---|---|
| OPEN | `rustix::fs::open` with the flags OpenSSH's `flags_from_portable` builds (`sftp-server.c:247-268`). READ and WRITE give `O_RDWR`, READ alone `O_RDONLY`, WRITE alone `O_WRONLY`. APPEND, CREAT, TRUNC and EXCL each add their own flag, so READ\|APPEND opens read-only and READ\|CREAT is valid. `O_CLOEXEC` is always set. `OpenOptions` cannot express this, because `append(true)` grants write access and `create(true)` requires it. The descriptor becomes a `File` through the safe `From<OwnedFd>`. The create mode is the ATTRS permissions `& 0o777`, or `0o666` if absent; the umask applies. |
| CLOSE | A handle on a **regular file** that was written since it was opened is first synced with `sync_data`; a failure is the reply's status (§4 mapping). A FIFO, socket or device is not synced, because `fdatasync` fails there with `EINVAL` (fsync(2)) while OpenSSH's plain `close()` succeeds. Then the handle is dropped. This is the only safe way to observe a deferred write error at CLOSE, as OpenSSH's `close()` does (`sftp-server.c:785-786`): `std::fs::File` ignores the close error in `Drop`, and `rustix::io::close` is `unsafe` and returns nothing (rustix 1.1.5, `src/io/close.rs:54`). A directory handle, or a file handle that was only read, is dropped. |
| READ | `read_at(offset)`: `SSH_FX_EOF` at end of file, otherwise DATA of ≤ min(len, 261 120) bytes. |
| WRITE | On a handle opened with APPEND, `write_all`: the kernel appends and the offset is ignored, as OpenSSH's `process_write` does by skipping `lseek` for `O_APPEND` (`sftp-server.c:865-872`). On any other handle, `write_all_at(offset)`. A positional write is never used with APPEND, because POSIX gives `O_APPEND` no effect on `pwrite`, and macOS follows POSIX: only Linux appends regardless (pwrite(2), BUGS). |
| STAT / LSTAT / FSTAT | `metadata` / `symlink_metadata` / `File::metadata`. |
| SETSTAT / FSETSTAT | Applied in this order, each only if its flag is set: size, `set_len` on a handle, or on a path a write-only, **non-blocking** open, then `ftruncate`. OpenSSH uses `truncate(2)`, and like it, a FIFO with no reader fails at once instead of blocking the single-threaded helper; uid/gid, `chown`/`fchown`; permissions, `set_permissions(perm & 0o7777)`; times, `File::set_times` on a handle, or `rustix::fs::utimensat` on a path. The first failure ends the request with its status. |
| OPENDIR / READDIR | `read_dir`. Each NAME carries the entry name, the longname (§5) and ATTRS from the entry's metadata. That metadata is read through the open directory, without following a symlink; an entry whose metadata cannot be read is skipped, as OpenSSH skips a failed `lstat`. A failed directory read is the reply's status, sent after any names already gathered. `SSH_FX_EOF` comes only once the directory is exhausted. |
| REMOVE / MKDIR / RMDIR | `remove_file` / `DirBuilder` with mode `perm & 0o777` (`0o777` if absent) / `remove_dir`. |
| REALPATH | OpenSSH's algorithm (`sftp-realpath.c:106-211`), not `canonicalize`. It resolves components left to right with `symlink_metadata` and follows every symlink, the last component's included, up to 32 links (`SYMLOOP_MAX`). Only a missing **last** component is accepted, and it is checked after any symlink before it was followed. A dangling final symlink therefore resolves to its target's path, not the link's. A relative path starts from the working directory, and an empty path means `.`. |
| RENAME | Refuses to overwrite, with OpenSSH's semantics (`sftp-server.c:1274-1314`). For a regular file (`symlink_metadata`): `hard_link(old, new)`, then `remove_file(old)`. If the link fails with `EOPNOTSUPP`, `ENOSYS` or `EXDEV` (a filesystem without hard links, or another device), or with `EPERM` on Linux, it falls back to an existence check of `new`, then `rename`. `EPERM` is OpenSSH's `LINK_OPNOTSUPP_ERRNO` for Linux (`configure.ac:974`), where a filesystem without hard links reports it. If the link succeeds but removing `old` fails, it removes the spare `new` link and replies with the removal's error. Anything else gets an existence check, then `rename`. Every existence check uses `symlink_metadata`, so it does not follow a symlink: an existing dangling symlink at `new` counts as existing and is never replaced. That is stricter than OpenSSH's `stat`, which would replace it. |
| READLINK | `read_link`. |
| SYMLINK | OpenSSH's order: the first string is the target, the second the link path (`PROTOCOL` §4.1). |
| `posix-rename@openssh.com` | `rename` (overwrites). |
| `fsync@openssh.com` | `File::sync_all` on the handle. |
| `limits@openssh.com` | EXTENDED_REPLY: 262 144, 261 120, 261 120, 256. |
| `expand-path@openssh.com` | `~` and `~/…` are taken relative to the helper's **working directory**, then resolved as REALPATH. That directory is `$HOME`, or `/` when `$HOME` is unusable (§2), as OpenSSH's `process_extended_expand` uses `getcwd` (`sftp-server.c:1553-1573`). Any other path is resolved directly. `~user` gets `SSH_FX_NO_SUCH_FILE`. |

**Status mapping.**
- `io::ErrorKind::NotFound` → `NO_SUCH_FILE` (2).
- `PermissionDenied` → `PERMISSION_DENIED` (3).
- Anything else → `FAILURE` (4).

The message is the fixed text of the code ("No such file", "Permission
denied", "Failure", "End of file", "Operation unsupported", "Success"), so
no OS error detail is sent. The language tag is empty. `NO_CONNECTION` and
`CONNECTION_LOST` are never sent.

### 5. Longname

The longname follows OpenSSH's `ls -l` layout: mode string, link count,
**numeric** uid and gid, size, date and name. Resolving names needs the
platform's account database, which `std` and `rustix` do not expose
without `unsafe`. The date is the mtime in **UTC**:
- `%b %e %H:%M` when the mtime is in the six months up to now;
- `%b %e  %Y` otherwise, a future mtime included.

This is OpenSSH's rule (`sftp-common.c:242-246`).

It is produced by a pure function, with no time-zone database. Clients
show it only when `users-groups-by-id` is absent, which it is
(`sftp.c:927-945`).

### 6. Answers to RFC-0013's open questions

1. **Extension set:** the four above. `statvfs`, `hardlink`, `lsetstat`,
   `copy-data` and `users-groups-by-id` are left for later. None is needed
   by `scp` or by `sftp`'s transfer and listing commands.
2. **Switch:** no configuration key. SFTP is on, like the PTY.
3. **Byte counts:** [ADR-0042](0042-exec-finished-channel-byte-counts.md).
4. **Handle cap:** 256.

### 7. Implementation and tests

- **Implementation PR contents.** It adds the `sftp` module, the helper
  dispatch, the `subsystem` request and the `Config::helper` rename. It
  flips this ADR and ADR-0042 to `Accepted` together with RFC-0013's
  acceptance. It also records two errata under ADR-0015: ADR-0038's
  Consequences said SFTP "brings multiplexing" (RFC-0013 §Motivation), and
  ADR-0024's `exec.finished` row omits the `command` field, which the code
  has emitted since Phase 1. ADR-0038's Status field also gains a pointer
  naming both partial supersessions: §1, where `subsystem` moves from
  "still refused" to honoured, and §9, whose `request_type` values gain
  `"subsystem"`. This follows the way ADR-0038 recorded its own on
  ADR-0024.
- **Unit tests:** framing (bounds, truncation, INIT first), each handler
  on a temporary directory, the RENAME semantics (including the
  link-failure fallback and the spare-link cleanup), APPEND writes ignoring
  the offset, CLOSE reporting a sync failure, REALPATH with a missing last
  component, the longname formatter, and the status mapping.
- **Integration tests:** they drive `subsystem sftp` through the shared
  SSH test client from the binary crate, re-executing the real binary
  (ADR-0038 §11).
- **Interop gate (ADR-0020):** `sftp -b` (put, get, ls, rename, rm, mkdir,
  rmdir) and `scp` in both directions, each checked byte for byte.
- **Threat model:** adds verbatim the §5.4.5 entry that RFC-0013 §6
  carries (a new attack vector goes through the RFC process, threat
  model "Maintenance"), and points §5.4.4's disposition at ADR-0042's
  byte counts, as a factual update.

## Consequences

### Positive

- `sftp` and `scp` from a stock OpenSSH 10.x client work, with no new
  dependency and no first-party `unsafe`.
- File access stays out of the server process, and the helper is the
  single-threaded point where Phase 3 drops privileges.
- Every attacker-controlled length has a fixed bound, and malformed input
  fails closed.

### Negative

- About as much new first-party parser and handler code as the transport
  layer, all post-authentication and attacker-reachable. It needs the
  Phase-3 fuzzing harness.
- `df`, `ln` without `-s`, `cp`, `chmod -h` and `~user` paths do not work.
  `ls -l` shows numeric owners and UTC dates.
- RENAME's no-overwrite check is check-then-act for non-regular files, and
  for regular files on filesystems without hard links, as in OpenSSH. A
  concurrent writer can race it, but only within the service account's own
  files.
- Each CLOSE of a written file costs one `fdatasync`, which OpenSSH's
  CLOSE does not do. In exchange, a deferred write failure reaches the
  client, and an upload is durable once CLOSE succeeds.

### Neutral

- `Config::pty_helper` is renamed `Config::helper`. `quantumssh-core` is
  unpublished (ADR-0017).
- `request_type` gains a third value, `"subsystem"`.

## Alternatives considered

### Alternative 1: `rustix` for every file operation

This would give one consistent API. It was not chosen: `std` already
covers READ, WRITE, STAT, DIR and the rest safely, and it is what the rest
of the codebase uses. `rustix` is used only where `std` cannot express the
semantics:
- OPEN with OpenSSH's flag mapping (READ|APPEND, READ|CREAT);
- SETSTAT's non-blocking size change on a path (`open` plus `ftruncate`);
- `utimensat` on a path.

### Alternative 2: `renameat2(RENAME_NOREPLACE)` for RENAME

This would be an atomic no-overwrite rename on Linux. It was not chosen
because it is Linux-only, and macOS would still need a fallback. OpenSSH's
`link` + `unlink` is portable and already what clients expect.

### Alternative 3: names in the longname, through a crate

A crate such as `uzers` could resolve the account database. It was not
chosen: it is a new dependency with `unsafe` NSS calls, for a cosmetic
column that only appears when `users-groups-by-id` is absent.

### Alternative 4: CLOSE by dropping the handle

This would avoid the `fdatasync`. It was not chosen: a deferred write
failure (NFS, quota, delayed write-back) would reach the client as
`SSH_FX_OK`, which `draft-ietf-secsh-filexfer-02` and OpenSSH's
error-mapped `close()` both rule out. No safe close that returns its error
exists.

### Alternative 5: a handle cap from `RLIMIT_NOFILE`

This is what OpenSSH does (`sftp-server.c:1521-1523`). It was not chosen:
a fixed, small cap makes the per-session bound explicit and independent of
the host's limits. OpenSSH's clients keep few handles open.

## Links

- RFC: [RFC-0013](../rfcs/0013-sftp-subsystem.md) ([#194](https://github.com/gonzafg2/quantumssh/pull/194)).
- Related ADRs: ADR-0016, ADR-0018, ADR-0020, ADR-0023, ADR-0024,
  ADR-0038, [ADR-0042](0042-exec-finished-channel-byte-counts.md).
- Code (implementation PR): `crates/quantumssh-core/src/sftp.rs` (new),
  `channel.rs`, `exec.rs`, `server.rs`, `crates/quantumssh/src/main.rs`,
  `crates/quantumssh/tests/`, `tests/interop/run_openssh_client.sh`.
- Prior art: openssh-portable `V_10_6_P1` (`sftp-server.c`,
  `sftp-client.c`, `scp.c`, `session.c`, `PROTOCOL` §4) and
  `draft-ietf-secsh-filexfer-02`.
