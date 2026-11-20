# ADR 0062: Grow the OpenSSH interop gate into a conformance suite, with a catalogue of cases that the run enforces

- **Status:** Proposed
- **Date:** — (set on acceptance; drafted 2026-11-20)
- **Deciders:** Project lead
- **Related:**
  - Extends [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md), the interop gate, and keeps its hard subset.
  - Runs on the client of [ADR-0048](0048-openssh-interop-client-on-debian-forky.md), in the image of [ADR-0059](0059-gate-image-published-to-ghcr.md), as the required check of [ADR-0031](0031-required-status-checks-commit-lint-and-openssh-interop.md), and on the release artifacts as [ADR-0055](0055-interop-gate-on-published-artifacts.md) decided.
  - Borrows two rules: a test must be seen to run ([ADR-0061](0061-wipe-the-stack-below-the-transport-ciphers.md) §5), and a change brings its test in the same PR ([ADR-0060](0060-continuous-fuzzing-cargo-fuzz-on-the-pinned-stable-toolchain.md) §9).
  - The "Conformance tests" workstream of Phase 3, [#248](https://github.com/gonzafg2/quantumssh/issues/248).

## Context

The README's Phase 3 lists "Conformance tests against OpenSSH client", and
#248 gives that work an ADR that extends ADR-0020. This is that ADR.

### What exists

ADR-0020 put a real OpenSSH client in front of every PR. Its script,
`tests/interop/run_openssh_client.sh`, started with three checks and has
grown one at a time. Each later check was added by the ADR of a feature:
ADR-0023, ADR-0026, ADR-0038, ADR-0041, ADR-0047, ADR-0050, ADR-0055 and
ADR-0058. Today it makes 15 checks:

- an `exec` round trip and its exit status;
- the negotiated key exchange, host key algorithm and second cipher;
- two negotiations that must fail;
- a re-key that the client starts;
- a PTY;
- an SFTP batch and two `scp` copies;
- a user certificate, and three that must be refused;
- a host key written by `quantumssh keygen`.

It runs in two places:

- **On every PR**, as the required check `openssh-interop` (ADR-0031), in
  the gate image (ADR-0059) with OpenSSH 10.6p1 (ADR-0048). The step takes
  3 seconds.
- **On every release**, against the artifacts (ADR-0055): both Linux
  targets in the same image, and macOS arm64 with a client built from the
  pinned tarball, which has no AES-GCM.

### What is missing

- **No rule says which behaviours get a check.** Each ADR chose its own.
- **Nothing lists what is not checked.** The server does, and refuses, far
  more than 15 things that a stock client can reach. For the rest, the
  only tests are in-process: the project's own test client against the
  project's own server. ADR-0020 rejected that as the gate, because such a
  test "proves the implementation is consistent with itself, not with
  OpenSSH".
- **One check passes for any failure.** `negative_no_hybrid` asserts only
  that `ssh` exited non-zero. A server that was down would pass it. The
  check that ADR-0047 added next to it asserts the reason.

### What a probe showed

On 2026-11-20, 22 behaviours outside the gate were tried by hand with a
stock client against `main` at `04503b0`. The client was OpenSSH 10.6p2 on
macOS arm64, which is not the pinned client.

| Behaviour | What the client showed | Stated in |
|---|---|---|
| The server's whole offer | `ssh -vv` prints the server's lists as the documents give them | ADR-0021, ADR-0047 |
| `shell` without a PTY | Commands sent on stdin run, and `exit 7` reports 7 | ADR-0038 |
| stdin to the command | 4 MiB of random bytes through `cat` come back identical | ADR-0023 |
| stderr | Arrives on the client's stderr, apart from stdout | ADR-0023 |
| A command killed by a signal | `exit-signal` arrives and `ssh` exits 255 | ADR-0023 |
| Window size, then a resize | `stty size` reports the client's 30 by 100, then 43 by 132 | ADR-0038 |
| `env` (`SetEnv`) | The variable is not set, and the session goes on | ADR-0023 |
| Agent forwarding (`-A`) | No agent socket in the session, which goes on | ADR-0023 |
| Local forwarding (`-L`) | With a session open, "administratively prohibited: one channel only"; with `-N`, "unknown channel type" | ADR-0023, in part |
| Remote forwarding (`-R`) | "remote port forwarding failed"; with `ExitOnForwardFailure`, exit 255 | ADR-0023 |
| A second session (`ControlMaster`) | "Session open refused by peer" | ADR-0023 |
| An unknown subsystem | "subsystem request failed on channel 0", exit 255 | ADR-0041 |
| Password and keyboard-interactive | "Permission denied (publickey)." | `README.md`, zero legacy |
| A legacy cipher; a classical or `sntrup761` key exchange | "no matching cipher found" or "no matching key exchange method found", each with the server's offer | ADR-0021 |
| `Compression=yes` | `none` is negotiated and the command runs | ADR-0021 |
| RSA and ECDSA user keys | Permission denied, while the Ed25519 key still works | ADR-0050 |
| A key that is not authorized; then 14 of them | Permission denied; then disconnect 11, `too-many-auth-attempts` | RFC-0014, in part |
| Client keepalives | A 5-second command survives `ServerAliveInterval=1` with `ServerAliveCountMax=2` | ADR-0023 |
| The client killed mid-command | The remote process group is gone within 2.5 seconds | ADR-0016 |
| The server sends 1.2 GB | A re-key completes. Who started it is below | ADR-0026 |
| `sftp`: `chmod`, `ln -s`, `reget`; then `df`, `ln`, `cp` | The first three work. The last three get "Server does not support" for `statvfs`, `hardlink` and `copy-data` | ADR-0041 |
| `ssh-keyscan` | Refused: disconnect 3, `no-strict-kex` | Nowhere |

Nineteen behaved as their documents say. Three are stated in no
document, or not in full:

1. **`ssh-keyscan` cannot read the host key.** Its KEXINIT carries no
   `kex-strict-c-v00@openssh.com`, so the server disconnects it, as the
   fail-closed rule requires. No document says so. `docs/deployment.md`
   tells the operator to publish the fingerprint out of band, which is the
   path that works, and does not say that the usual tool fails.
2. **The size of the authentication budget is in the code only.** RFC-0014
   names the budget. The limit of 12 attempts, and the disconnect that
   ends the connection when it is spent, are in `auth.rs` and
   `transport.rs`.
3. **ADR-0023 does not say which failure a forwarding channel gets while a
   session is open.** It gives a non-`session` type "unknown channel
   type", and a second `session` "administratively prohibited". A
   `direct-tcpip` open that arrives while a session is open is both, and
   the server answers "administratively prohibited".

One of the nineteen shows how a case can mislead:

- **The obvious re-key case would have tested the client.** ADR-0026 has
  the server start a re-key after 1 GiB. Under ChaCha20 the client's own
  limit is also 1 GiB (`rekey out after 134217728 blocks`), and the audit
  log recorded `initiator: peer`. Under AES-GCM the client's limit is
  2^32 blocks, and the log recorded `initiator: server`, `trigger: bytes`.

Finding the first three is what a suite is for. The last is the mistake a
suite makes: a case that passes for a reason other than the one its name
gives.

### Constraints

- **The release gates run the same script with no toolchain.** ADR-0055 §1
  skips the toolchain and `cargo build` there, and §3 runs the script
  unchanged on macOS.
- **The gate image is part of what a release trusts** (ADR-0059). It holds
  bash, coreutils, util-linux, the OpenSSH client set, and what the build
  and the systemd test need. Anything added to it is added to the release
  path.
- **A local terminal is there already.** `script(1)` is in the image, from
  `bsdutils`, and on macOS. It gave a command a terminal on both, and on
  macOS it carried `ssh` through the resize in the table.
- **OpenSSH tests a foreign server the same way.** Its regress suite
  configures the server under test through an `sshd_config` that its
  driver writes, and QuantumSSH reads no `sshd_config` (RFC-0010). The
  exception is `regress/dropbear-server.sh`: a shell script written for
  one foreign server, which loops the `ssh` client over algorithms and
  compares the bytes it copied.

## Decision

We will grow ADR-0020's gate into the conformance suite: one script, one
case per behaviour, and a catalogue that the run enforces, against the
pinned client.

### 1. What conformance means here

A behaviour belongs in the suite when both of these hold:

- **A document of this project states it:** an ADR, an RFC, the threat
  model or `docs/deployment.md`. That includes what the server refuses.
- **A stock OpenSSH client tool reaches it** with its command line and
  options alone: `ssh`, `sftp`, `scp`, `ssh-keygen` or `ssh-keyscan`.

The claim the suite supports names its client: these documented behaviours
hold against the OpenSSH client of the pinned version. It is not a claim
of conformance with RFC 4253 at large.

- **Input that no stock client sends** stays with the fuzz targets
  (ADR-0060) and the in-process tests.
- **Other clients are out of scope.** The README names the OpenSSH client.
- **RFC-0003 wrote "OpenSSH client + server".** QuantumSSH has no client
  before Phase 4, so nothing here faces an OpenSSH server.

### 2. One case per behaviour, and the document comes first

- Each case has a name, drives the client and asserts one behaviour.
- Each case cites the document and section it checks.
- **When no document states the behaviour, the document gets its sentence
  first, in the same PR.** The suite is never the only record of what the
  server does. The probe found three such behaviours.
- **An accepted ADR is not edited for it** (ADR-0015). The sentence goes
  into a document that can take it.

### 3. The catalogue is a file, and the run enforces it

- **A catalogue in `tests/interop/` (planned)** holds one line per case:
  its name, the document it checks, and the legs on which it may skip.
- **The driver runs the cases the catalogue lists.**
  - Before the first case, it fails if a case has no line or a line has no
    case.
  - After the last, it fails unless every line reported `ok`, or a skip
    that its line allows.
- **Why.** A filter that matches nothing passes (ADR-0061 §5). A case that
  was dropped, renamed or never reached must fail the run.
- **What it is for.** The catalogue answers "what does the gate cover",
  and it is what a reviewer reads in a diff.

### 4. A case must fail for the right reason

- **A refusal case asserts the refusal:** the client's message, or the
  disconnect code and reason, and not only a non-zero exit.
  `negative_no_hybrid` is tightened to this.
- **A case about which side acted reads it from the server's audit log.**
  The case for a re-key that the server starts runs under AES-GCM and
  asserts `initiator`, for the reason the probe found.
- **A case that needs a terminal gets one from `script(1)`.**
- **Where a case matches the client's wording, that wording is the pinned
  client's.** It changes only with a client bump (§7).

### 5. One script, in bash, with nothing added to the image

- `tests/interop/run_openssh_client.sh` stays the entry point. It may
  source other files in `tests/interop/`.
- It needs only what the gate image and the macOS leg already have: bash,
  coreutils, `script(1)` and the OpenSSH client set.
- No package is added to the image, and no leg gains a toolchain.
- ADR-0055 §3's rule stands. The script runs unchanged on every leg, and a
  part that is not portable is fixed in the script, not forked.

### 6. Where it runs

- **Nothing new is wired.** The suite is the script that `openssh-interop`
  runs on every PR and that the release gates run on every artifact.
- **No tiers.** Every case runs on every leg, apart from declared skips.
- **Skips are declared twice.** The catalogue line says where a case may
  skip, and the workflow that calls a leg names the skips it allows. Any
  other skip fails the run.
  - Today there is one: the AES-GCM cases on the macOS leg, whose client
    has no AES-GCM (ADR-0055 §3).
  - On the PR gate and on both Linux release legs, nothing skips.
- **Time.** A script that tried the 22 behaviours took 21 seconds on the
  development machine, most of it fixed waits and a transfer of 1.2 GB.
  The implementing PR reports the step's time on the PR runner. If the
  suite outgrows a required check, splitting it is a new decision.

### 7. One client: the pin

- The suite runs against one client, the one ADR-0048 pins. There is no
  version matrix.
- **A client bump runs every case against the new client** before it
  becomes the pin (ADR-0034's procedure, in ADR-0059's image). A case
  whose result changes is what that PR's review is about.
- **The probe is not the pin.** It used 10.6p2 on macOS. The implementing
  PR runs every case on the pinned client and records any result that
  differs from the table above.

### 8. The rule for later PRs

- A PR that adds or changes a behaviour a stock client can reach adds or
  updates its case, and its catalogue line, in the same PR.
- A PR that removes a case changes the document that stated the behaviour.
- When this ADR is accepted, the rule goes into `CLAUDE.md` and
  `AGENTS.md`, next to ADR-0060 §9's rule for fuzz targets.

### 9. The first catalogue

The implementing PR's catalogue holds at least:

- **The 15 checks of today's gate.** What they assert does not change,
  except `negative_no_hybrid` (§4).
- **A case for each behaviour in the probe's table.**
- **The three behaviours that no document states in full, each with its
  sentence** (§2). The refusal of `ssh-keyscan` goes into
  `docs/deployment.md`. The implementing PR places the other two.

Three behaviours are left out, each for a stated reason:

- **X11 forwarding.** Without `xauth` the client's own setup failed in
  the probe, so it could not tell that failure from a refusal by the
  server. The gate image does not install `xauth`.
- **The one-hour re-key** (ADR-0026). No client option shortens the
  server's timer, so the case would run for an hour.
- **An interactive shell on a PTY.** The probe did not reach it. The
  implementing PR adds the case, or records why it cannot.

### 10. Scope

This decision covers how the gate is extended and enforced. It leaves
these alone:

- **What the server does.** `ssh-keyscan` stays refused, as the
  fail-closed rule requires, and the other two behaviours stay as they
  are. Only documents change.
- **A version matrix, other clients, and OSS-Fuzz.**

**Why an ADR, not an RFC.** No protocol, algorithm, public API or
dependency changes. The decision extends a CI gate that ADR-0020 decided.

## Consequences

### Positive

- Every documented behaviour a stock client can reach is checked against
  the real client, on every PR and on every release artifact, on three
  targets.
- The catalogue says what is covered. What is missing is a missing line.
- A client bump becomes a full run with a diff a reviewer can read.
- The documents get completed. The probe already found three behaviours
  that no document states in full.

### Negative

- **The required check does more.** The step takes 3 seconds today. The
  probe suggests tens of seconds. The implementing PR measures it.
- **The script grows several times over, in bash.** A large bash script is
  harder to keep right than the same suite in Rust would be. One function
  per case and the catalogue check are the mitigation.
- **Some cases match the client's wording**, such as "Their offer:". A
  client release can change it. The case then fails in the bump PR, where
  it is reviewed, and not on an unrelated PR. That is ADR-0020's reasoning
  for the pin.
- **`script(1)` has two syntaxes**, util-linux's and BSD's. The terminal
  cases need a small wrapper.
- **The claim covers one client version.** A behaviour that differs under
  another version shows only at the bump.
- **The suite says nothing about a peer that breaks the protocol.** That
  stays with fuzzing and the in-process tests.

### Neutral

- ADR-0020's hard subset stays, as cases in the catalogue.
- The in-process tests stay. They cover what the client cannot be made to
  do.
- The README's Phase 3 item is done when the implementing PR merges.

## Alternatives considered

### Alternative 1: keep adding checks feature by feature

The gate as it is. Rejected: there is no rule and no list. The first probe
found three behaviours that no document states in full, and a check that
passes for any failure.

### Alternative 2: a Rust harness that spawns `ssh`

Tests in `crates/quantumssh/tests/` that start the binary and run the
client. Rust is the better language for a suite. Rejected because the
release gates run with no toolchain (ADR-0055 §1). The bash script would
have to stay for them, and two harnesses drift apart.

### Alternative 3: OpenSSH's regress suite

Rejected. Its driver writes an `sshd_config` for the server under test,
and QuantumSSH reads TOML (RFC-0010). Its `dropbear-server.sh` is the
precedent for the shape chosen here.

### Alternative 4: compare each result with OpenSSH's `sshd`

Run every case against `sshd` too, and take its result as the expected
one. Rejected. QuantumSSH refuses by design what `sshd` accepts:
forwarding, passwords, a classical key exchange, a second channel. The
oracle would disagree where the suite matters most. It would also put
`openssh-server` in the gate image. Expected results come from this
project's documents.

### Alternative 5: a scanner for the algorithm offer

A tool that connects and reports the algorithms a server offers. Rejected:
it is a new package in the gate image, and it is not the reference client.
`ssh -vv` already prints the server's offer, and a case asserts it.

### Alternative 6: a matrix of client versions now

Rejected for now. Each extra client is an image to build, pin and attest
(ADR-0059), and another set of release legs. ADR-0020 named the matrix as
a later enhancement, and it stays one. The bump procedure covers moving to
a new client.

### Alternative 7: a fast required subset and a nightly full run

Rejected. At the measured times there is nothing to split. A nightly run
that is not required fails without blocking anything.

### Alternative 8: `expect`, or a Python harness

Rejected. Either is a new package in the gate image. bash and `script(1)`
reached every behaviour the probe tried with a terminal, including the
resize.

## Links

- Implementation (planned): `tests/interop/run_openssh_client.sh`, the
  catalogue beside it, the skips each leg allows in
  `.github/workflows/interop.yml` and `.github/workflows/release.yml`,
  the sentences of §9, and the rule of §8 in `CLAUDE.md` and `AGENTS.md`.
- The probe: 2026-11-20, `OpenSSH_10.6p2` on macOS arm64, against `main`
  at `04503b0`. Its scripts were throwaway and are not in the repository.
- The step's time today: the `OpenSSH interop gate` step of run
  [44672384663](https://github.com/gonzafg2/quantumssh/actions/runs/44672384663).
- `script(1)` in the gate image: `script from util-linux 2.42.4`, owned by
  `bsdutils`, in the image at digest `sha256:88a4c0e6…903b1e`.
- OpenSSH's regress suite, read on 2026-11-20 at `openssh-portable`
  `master`: `regress/README.regress`, `regress/Makefile`
  (`INTEROP_TESTS`) and `regress/dropbear-server.sh`.
- Related ADRs: [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md),
  [ADR-0023](0023-phase-1-channel-layer-scope.md),
  [ADR-0026](0026-phase-1-rekeying-policy.md),
  [ADR-0031](0031-required-status-checks-commit-lint-and-openssh-interop.md),
  [ADR-0034](0034-openssh-interop-client-pinned-to-image-build-snapshot.md),
  [ADR-0048](0048-openssh-interop-client-on-debian-forky.md),
  [ADR-0055](0055-interop-gate-on-published-artifacts.md),
  [ADR-0059](0059-gate-image-published-to-ghcr.md),
  [ADR-0060](0060-continuous-fuzzing-cargo-fuzz-on-the-pinned-stable-toolchain.md),
  [ADR-0061](0061-wipe-the-stack-below-the-transport-ciphers.md).
- Roadmap: Phase 3, [#248](https://github.com/gonzafg2/quantumssh/issues/248).
