# ADR 0063: The launcher protocol: one `SOCK_SEQPACKET` socket pair, SSH wire encoding, explicit bounds and a fuzz target

- **Status:** Proposed
- **Date:** — (set on acceptance; drafted 2026-11-24)
- **Deciders:** Project lead
- **Related:**
  - Implements [RFC-0020](../rfcs/0020-privilege-separation-root-launcher-and-session-helper.md) §2. It is the first item of RFC-0020 §12: "the launcher protocol's encoding and bounds, and its fuzz target".
  - The rest of the protocol's meaning lives in three ADRs drafted with it:
    - [ADR-0064](0064-sessions-in-the-launcher-identifiers-pty-allocation-ending-and-reaping.md): what `start` and `end` do to a session;
    - [ADR-0065](0065-session-helper-identity-change-checks-and-environment.md): the helper a `start` runs;
    - [ADR-0066](0066-account-mode-start-readiness-and-stop.md): `listener` and `ready`.
  - Fuzzed under [ADR-0060](0060-continuous-fuzzing-cargo-fuzz-on-the-pinned-stable-toolchain.md). The PTY fields keep [ADR-0038](0038-phase-2-interactive-pty-sessions.md) §2's bounds and its modes parser.
  - Constrained by:
    - [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md): no first-party `unsafe`;
    - [ADR-0017](0017-phase-1-workspace-topology-two-crates-flat.md): two crates, no new one.

## Context

RFC-0020 runs account mode as two processes: a root launcher and the
unprivileged network server. They talk over one Unix socket pair.
RFC-0020 §2 fixes the content of that conversation:

- **Server to launcher:** start a session; signal a session.
- **Launcher to server:** started, with the session's descriptors;
  refused; exited.

It also fixes what the launcher refuses to trust:

- no descriptor flows from the server to the launcher;
- no path, program or environment variable comes from the server, except
  the command of `exec` (§2) and, on a PTY, `TERM` (RFC-0020 §5);
- every field has a bound;
- a malformed message ends the launcher's service;
- the parser gets a fuzz target.

The encoding, the bounds and the target are this ADR's to decide. The
launcher must hold if the server is compromised (RFC-0020 §2). So its
parser of server messages reads hostile bytes in a root process, and no
other root code does.

The platform gives everything without `unsafe` (rustix 1.1.6):

- **The socket pair:** `rustix::net::socketpair` (`src/net/socketpair.rs:29`).
- **Sending and receiving:** `sendmsg` and `recvmsg` (`src/net/send_recv/msg.rs:726`,
  `:803`).
- **Descriptors out:** `SendAncillaryBuffer::push(SendAncillaryMessage::ScmRights(&[BorrowedFd]))`.
- **Descriptors in:** `RecvAncillaryBuffer::drain` (`:482`) yields them
  as `OwnedFd`.
- **The one `unsafe` function,** `AncillaryDrain::parse` (`:529`), is not
  needed. RFC-0020's Prior art calls it `RecvAncillaryBuffer::parse`.

The kernel gives three guarantees (unix(7), Linux man-pages 6.19):

- `SOCK_SEQPACKET` "is connection-oriented, preserves message
  boundaries, and delivers messages in the order that they were sent".
- If the buffer for incoming descriptors "is too small (or is absent),
  then the ancillary data is truncated (or discarded) and the excess file
  descriptors are automatically closed in the receiving process".
- In that case `MSG_CTRUNC` is set in the flags `recvmsg` returns.

## Decision

### 1. The socket

- **`socketpair(AF_UNIX, SOCK_SEQPACKET, SOCK_CLOEXEC)`,** created by the
  launcher before it starts the server (ADR-0066).
  - The server's end becomes the server's stdin.
  - The launcher keeps the other end.
- **One message per record.** Each `sendmsg` carries one message, and
  each `recvmsg` returns one. There is no length framing, and no message
  spans two records. A message's descriptors arrive in the same record as
  its bytes.
- **A zero-length read.** It means the peer has closed its end, or that
  it sent an empty record. `SOCK_SEQPACKET` allows empty records, and no
  message is one. The launcher treats both cases alike:
  - it reads no more messages;
  - it waits for the server's exit, which ADR-0066 §5 handles.

  The launcher's exit status therefore comes from the server's wait
  status, never from the read. A running server that sends an empty
  record only stops itself from starting or ending sessions. It can
  already end its own service by exiting.
- **No version field.** The launcher starts the server from its own
  image, `/proc/self/exe` (ADR-0066), so both ends always run the same
  build.

### 2. Encoding

Byte 0 is the message type. The fields that follow use RFC 4251 §5's
`byte`, `boolean`, `uint32`, `uint64` and `string` encodings. They are
read and written with the `wire` module's `Reader` and `Writer`, which
every SSH message already goes through. Bytes left over after the last
field make the message malformed.

**Server to launcher:**

| Type | Name | Fields |
|---|---|---|
| 1 | `ready` | none (ADR-0066 §3) |
| 2 | `start` | `string` account; `byte` kind: 1 `exec`, 2 `shell`, 3 `sftp`; for `exec` only, `string` command; for `exec` and `shell`, `boolean` pty; when pty is true, `string` TERM, `uint32` columns, rows, width in pixels, height in pixels, and `string` modes |
| 3 | `end` | `uint64` session |

`end` is RFC-0020 §2's "signal a session". ADR-0064 §4 states what the
launcher does with it.

**Launcher to server:**

| Type | Name | Fields | Descriptors |
|---|---|---|---|
| 16 | `listener` | none | the listening socket (ADR-0066 §2) |
| 17 | `started` | `uint64` session; `uint32` UID | the session's stdin, stdout and stderr ends (three pipes), or the PTY master (one) |
| 18 | `refused` | `byte` reason | none |
| 19 | `exited` | `uint64` session; `byte` how: 1 exit code, 2 signal; `uint32` value; `boolean` core dumped, false for an exit code | none |

**Refusal reasons.** They name the cause in the server's diagnostic
record. The client sees the same answer for all of them (ADR-0064 §2).

| Reason | Meaning |
|---|---|
| 1 | the account is not listed |
| 2 | the account does not resolve now: no entry, UID 0, the service account's UID (ADR-0066 §1), or a file that fails RFC-0019 §8's check |
| 3 | the session limit is reached (ADR-0064 §1) |
| 4 | the PTY could not be allocated |
| 5 | the helper could not be started |

**Replies come in order.** The launcher answers every `start` with
exactly one `started` or `refused` before it reads the next message.
`listener` and `exited` arrive unprompted. The server therefore matches
a reply to its request by order, with no request identifier.

**On the server, one task owns the socket.**

- It sends every message.
- It keeps a FIFO of the connections that wait for an answer to
  `start`: one entry per `start` it sends.
- It hands each `started` or `refused` to the oldest entry.
- Connection tasks never touch the socket. They pass their requests to
  this task.

The launcher's order is therefore the order in which the server matches,
however many `start`s are in flight.

### 3. Bounds in the launcher's parser

| Item | Bound | Source |
|---|---|---|
| A record | 36,864 bytes (36 KiB) | the sum of the fields below, rounded up |
| account | 1 to 256 bytes | RFC-0019 §3 |
| command | at most 35,000 bytes | `wire::MAX_PACKET`, which bounds every SSH packet, so no `exec` request can carry more |
| TERM | at most 64 bytes, and empty or `[A-Za-z0-9._+-]+` | ADR-0038 §2 |
| modes | at most 1024 bytes, and accepted by `pty::Modes::parse` | ADR-0038 §2 |
| dimensions | any `uint32`, clamped to 65535 as ADR-0038 §2 does | ADR-0038 §2 |
| session in `end` | any `uint64`; ADR-0064 §4 ignores one it does not hold | ADR-0064 §4 |

**Malformed.** The launcher treats each of these as malformed:

- an unknown type, or a second `ready`;
- a field past its bound, or a truncated field;
- a field the kind does not allow: a command outside `exec`, or a PTY
  flag on `sftp`;
- trailing bytes;
- `MSG_TRUNC`, which means the record was longer than the buffer;
- `MSG_CTRUNC`.

The launcher receives with no ancillary buffer. A descriptor the server
sends anyway is therefore closed by the kernel, and sets `MSG_CTRUNC`.

**On a malformed message,** the launcher writes one diagnostic record
that names the rule broken, never the bytes. It then ends its service as
ADR-0066 §5 describes. A well-behaved server never sends one, so only a
fault or a compromise of the server reaches this path.

**A command with a NUL byte is not malformed.** A well-behaved server may
pass on what a client sent. No argument vector can carry a NUL byte, so
starting the helper fails, and the launcher answers `refused` with
reason 5. Today's server already fails such a spawn.

### 4. Descriptors

- **They flow one way only:** `listener` carries one, and `started`
  carries three or one.
- **The server receives** with `RecvFlags::CMSG_CLOEXEC` and a buffer
  sized for three descriptors (`cmsg_space!(ScmRights(3))`).
- **A `started` short of descriptors fails that one session.** That is a
  `started` with fewer descriptors than its session carries, or with
  `MSG_CTRUNC`.
  - The likely cause is the server's own descriptor table: descriptors
    beyond the receiver's `RLIMIT_NOFILE` "are automatically closed in
    the receiving process" (unix(7)).
  - The server closes the descriptors that did arrive, sends `end` for
    the session, and answers the client as it answers `refused`
    (ADR-0064 §2).
  - It keeps serving, as it keeps accepting when `accept` fails with
    `EMFILE` (`crates/quantumssh-core/tests/accept_resources.rs`).
- **A `listener` short of its descriptor fails the start.**
- **A launcher fault ends the server** (ADR-0066 §5). There are two
  kinds:
  - descriptors on a message that carries none, `refused` or `exited`;
  - more descriptors than the message carries, without `MSG_CTRUNC`:
    two or three on a PTY session's `started`, or two or more on
    `listener`.
- **`MSG_CTRUNC` on `started` always fails just that session,** whoever
  caused it. The server cannot tell its own descriptor limit from a
  sender that sent too many.
- **The launcher never runs a call on a descriptor the server chose,**
  because it never receives one (RFC-0020 §2).

### 5. Where the code lives

- **A new module, `launcher`, in `quantumssh-core`,** for Linux only.
  - It holds the message types, the encoder and the parser.
  - These are pure functions over byte slices, with no I/O.
  - The parser of server messages is `pub(crate)`. The `fuzzing` module
    reaches it, as ADR-0060 §3 provides.
- **The socket I/O wraps those functions.** Descriptors are `OwnedFd`
  and `BorrowedFd` throughout, and nothing needs `unsafe`.
- **Dependencies.** No new crate. The `rustix` pin gains the `net`
  feature, as RFC-0020 §11 states.

### 6. Fuzz target

- **A new target, `launcher_request`,** drives the launcher's parser of
  server messages.
- **Its seeds:**
  - `ready` and `end`;
  - `start` for `exec`, for `shell` with a PTY (TERM, dimensions and
    modes), and for `sftp`;
  - one `start` at every bound of §3;
  - an empty input. §1 handles an empty record before the parser runs,
    but the parser must still reject one.
- **When.** It lands in the PR that implements this ADR.
- **Why this one is fuzzed.** ADR-0060 §9's rule binds parsers that run
  before authentication. This parser runs after it, but it sits on a
  privilege boundary, so this ADR applies the same rule to it.
- **The server's parser of launcher messages is not fuzzed.** Its input
  comes from root.

## Consequences

### Positive

- **The only parser in the root process is small.** It reads three
  message types and five field kinds, all through readers that every
  SSH message already exercises.
- **The kernel keeps a message and its descriptors together.** No
  first-party framing is needed.
- **No new crate,** and no `unsafe`.

### Negative

- **A malformed message ends every session,** because the launcher ends
  its service (ADR-0066 §5). That trades availability for failing closed
  when the server misbehaves.
- **One more fuzz target** runs in the daily fuzzing job.
- **The protocol exists on Linux only,** like account mode (RFC-0019 §4).

### Neutral

- **The protocol is internal.** It is not an interface, has no version
  field, and can change in any release, because both ends are one image.

## Alternatives considered

### Alternative 1: `SOCK_STREAM` with length framing

OpenSSH's monitor talks over a stream socket pair with explicit lengths.
Rejected. It needs first-party framing. Ancillary data would also attach
to a byte range of the stream, not to a message, so matching descriptors
to messages would need extra rules.

### Alternative 2: a serialization crate

Examples are `serde` with `bincode` or `postcard`. Rejected. It would add
a dependency to the only parser in the root process, and RFC-0020 §11
adds no crate. The `wire` readers already exist and are already fuzzed.

### Alternative 3: a text protocol, such as JSON lines

Rejected. It would need escaping and a bounded text parser in the root
process. The fields are a few strings and integers, which binary
encodes with less code.

### Alternative 4: a request identifier on `start`

Rejected. The launcher is single-threaded and answers each `start`
before it reads the next message (§2), so order already pairs a reply
with its request.

## Links

- [RFC-0020](../rfcs/0020-privilege-separation-root-launcher-and-session-helper.md) §2, §11, §12.
- [ADR-0038](0038-phase-2-interactive-pty-sessions.md) §2, the `pty-req` bounds and the modes parser.
- [ADR-0060](0060-continuous-fuzzing-cargo-fuzz-on-the-pinned-stable-toolchain.md) §3, §9.
- unix(7), Linux man-pages 6.19: `SOCK_SEQPACKET`; `SCM_RIGHTS` and `MSG_CTRUNC`.
- RFC 4251 §5, the data type encodings.
- rustix 1.1.6: `src/net/socketpair.rs:29`; `src/net/send_recv/msg.rs:482`, `:529`, `:726`, `:803`.
