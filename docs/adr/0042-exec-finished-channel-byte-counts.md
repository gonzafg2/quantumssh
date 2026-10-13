# ADR 0042: `exec.finished` carries the channel byte counts of every child

- **Status:** Accepted
- **Date:** 2026-10-26 (accepted with the implementing PR [#196](https://github.com/gonzafg2/quantumssh/pull/196), on RFC-0013's acceptance; drafted 2026-10-12)
- **Deciders:** Project lead
- **Related:** Answers [RFC-0013](../rfcs/0013-sftp-subsystem.md)'s
  unresolved question 3 (Draft, [#194](https://github.com/gonzafg2/quantumssh/pull/194)).
  Realises threat model §5.4.4's record ("a session recorded as having
  opened an SFTP subsystem, transferred N bytes, and closed it"). Once
  accepted, it partially supersedes the field list of the `exec.finished`
  row of [ADR-0024](0024-phase-1-log-event-schema.md), as
  [ADR-0038](0038-phase-2-interactive-pty-sessions.md) §9 did. Implemented
  with [ADR-0041](0041-sftp-v3-server-in-a-re-exec-helper.md).

## Context

Threat model §5.4.4 scopes exfiltration over the session out of
QuantumSSH-side defence. It names the server's contribution as logging
fidelity: the record of an SFTP session should say that it transferred
N bytes. Today `exec.finished` says who ran what, under which UID, and how
it ended, but not how much data moved.

RFC-0013 asks whether byte counts belong only on SFTP sessions or on every
child. The audit schema freezes at `0.1.0` (Phase-2 scoping note, freeze
checklist), so the field set must be settled before then.

## Decision

`exec.finished` gains two fields for **every** request type (`exec`,
`shell`, `subsystem`), on every path that emits it:

| Field | Type | Meaning |
|---|---|---|
| `bytes_received` | u64 | `CHANNEL_DATA` payload bytes from the client that were handed to the child. |
| `bytes_sent` | u64 | `CHANNEL_DATA` and `CHANNEL_EXTENDED_DATA` payload bytes sent to the client from the child's output. |

- **What is counted:** channel payload bytes, not file bytes. For SFTP
  they include the protocol's framing and are an upper bound on the file
  content moved.
- **What is not counted:** data discarded after an early client close
  (#191), and input the child never received. The count is what crossed
  the channel to or from the child.
- **Where they are counted:** in the channel driver, where it already
  hands data to the child and frames its output. No new I/O path is added.
- **Drop-guard path:** an `exec.finished` emitted by the drop guard
  carries the counts up to that point.
- **Never logged:** the content of any stream, as before (ADR-0024,
  threat model §5.4.3).

## Consequences

### Positive

- §5.4.4's record exists for SFTP, and the same signal covers `exec` and
  `shell` (for example, a `cat` of a large file).
- One uniform `exec.finished`. Consumers need no per-type schema.

### Negative

- Two more fields in the schema that `0.1.0` freezes.
- The counts include protocol framing, so they are not exact file sizes.

### Neutral

- When this ADR is accepted, ADR-0024's Status field gains a pointer to
  it, as ADR-0038 §9's change did.

## Alternatives considered

### Alternative 1: counts on subsystem sessions only

This would keep `exec` and `shell` records unchanged. It was not chosen:
it would make the schema depend on the request type, and the same
exfiltration signal applies to `exec`.

### Alternative 2: file-level counts from the SFTP helper

These would be exact file bytes per path. It was not chosen for now: it
needs a validated side channel from the helper (RFC-0013 §Future
possibilities). Channel counts need no new mechanism and cover every
request type.

### Alternative 3: no counts

This would keep the schema smallest. It was not chosen because it leaves
§5.4.4's stated contribution unmet at the freeze.

## Links

- Code (implementation PR, with ADR-0041): `crates/quantumssh-core/src/channel.rs`
  (the counters and the event fields).
- Related: ADR-0024, ADR-0038 §9, ADR-0041, RFC-0013, threat model
  §5.4.4.
