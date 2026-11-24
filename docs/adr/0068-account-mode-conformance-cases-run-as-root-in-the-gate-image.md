# ADR 0068: Account-mode conformance cases, run as root in the gate image

- **Status:** Proposed
- **Date:** — (set on acceptance; drafted 2026-11-24)
- **Deciders:** Project lead
- **Related:**
  - It is the sixth item of [RFC-0020](../rfcs/0020-privilege-separation-root-launcher-and-session-helper.md) §12: "the conformance cases (ADR-0062 §8): the session's UID, groups, home and shell; file ownership over SFTP; and the refusals of RFC-0019".
  - It also covers the conformance item of [RFC-0019](../rfcs/0019-identity-model-ssh-user-name-to-os-account.md) §9.
  - Adds cases to the suite of [ADR-0062](0062-conformance-suite-driven-by-the-stock-openssh-client.md), under its §8 rule. They run in the gate image of [ADR-0059](0059-gate-image-published-to-ghcr.md).
  - Checks what [ADR-0064](0064-sessions-in-the-launcher-identifiers-pty-allocation-ending-and-reaping.md), [ADR-0065](0065-session-helper-identity-change-checks-and-environment.md) and [ADR-0066](0066-account-mode-start-readiness-and-stop.md) decide.

## Context

ADR-0062 §8 requires a conformance case for every behaviour that a stock
OpenSSH client can reach, a refusal included, in the PR that adds the
behaviour. Account mode adds several.

Account mode can only run under three conditions:

- **Linux,** because RFC-0019 §4 limits account mode to it.
- **Root,** because the launcher must start as root (ADR-0066 §1).
- **Real accounts,** with entries in `/etc/passwd` and `/etc/group`.
  Creating them on a developer's machine would leave real accounts
  behind.

Three things about the suite settle where these cases can run:

- **The Linux legs run in a container.** `openssh-interop`, on every PR,
  and the two Linux release legs (ADR-0055) both run
  `.github/workflows/interop.yml`, whose job runs in the gate image as a
  `container:`. The image sets no `USER`, so the job runs as root.
- **The systemd gate already does this kind of setup.** It creates
  accounts with `useradd` in the same image (ADR-0043 §7).
- **The macOS release leg cannot run them.** It runs the suite natively
  (ADR-0055 §3), where account mode does not exist.

The cases also need a file layout that RFC-0019 §8 accepts:

- root-owned files;
- root-owned ancestor directories that are not group- or world-writable;
- no symlinks.

The suite's work directory sits under `/tmp`, which is world-writable,
so it fails that check.

## Decision

### 1. Where the account cases run

- **Three conditions.** An account case runs only on Linux, as UID 0,
  with `INTEROP_ACCOUNT_MODE=1` in the environment.
  - The variable is the run's statement that it is inside a disposable
    container. The cases create accounts and groups, and write under
    `/etc`.
  - When any condition fails, the case reports a skip.
- **On the Linux legs nothing skips.** `interop.yml` sets the variable on
  its container job, which covers the PR gate and both Linux release
  legs. It lists no account case in `INTEROP_ALLOW_SKIP`.
- **On the macOS leg every account case may skip.** Its
  `INTEROP_ALLOW_SKIP` lists each of them. Each case's "May skip" cell in
  `CASES.md` reads "where account mode cannot run (ADR-0068 §1)".
- **Locally,** a developer runs them through the gate image, as
  `tests/systemd/run_in_docker.sh` runs the systemd gate.

### 2. Setup

Before the first account case, the driver creates everything once per
run:

- **The service account `quantumssh`:** a system account, with
  `/usr/sbin/nologin` as its shell.
- **The group `qssh-team`.**
- **The test accounts:**

  | Account | Login shell | Listed | Other |
  |---|---|---|---|
  | `qssh-alice` | `/bin/bash` | yes | member of `qssh-team` |
  | `qssh-deploy` | `/bin/sh` | yes | |
  | `qssh-nologin` | `/usr/sbin/nologin` | yes | |
  | `qssh-unlisted` | | no | |

- **A directory for the run's files, `/etc/quantumssh-interop`,** owned
  by root with mode `0755`.
  - It holds the configuration, the CA file and every account's key
    file, all owned by root, so they pass RFC-0019 §8.
  - The host key sits there too, owned by `quantumssh` with mode `0600`,
    as the operator guide installs it (ADR-0067 §4).

The configuration uses the grammar of RFC-0019's implementing ADR. The
cases start their servers as the other cases do, here as root, so each
one gets a launcher.

### 3. The cases

Each line names its document first, as ADR-0062 §2 requires.

| Case | Checks |
|---|---|
| `account_session_identity` | RFC-0020 §4, §5: `id -u`, `id -g`, `id -G`, `pwd -P`, `HOME`, `USER`, `LOGNAME`, `SHELL` and `PATH` match `qssh-alice`'s record, its groups with `qssh-team`, and ADR-0065 §3's `PATH` |
| `account_login_shell` | RFC-0020 §4: `shell` on a PTY runs the account's login shell as a login shell, so `$0` is `-bash` |
| `account_pty_owner` | RFC-0020 §4, ADR-0064 §2: the session's terminal is owned by the account, with mode `0600` |
| `account_session_privileges` | RFC-0020 §8, ADR-0065 §2: in a session, `NoNewPrivs` is 0, and `CapPrm`, `CapEff` and `CapInh` are 0 |
| `account_audit_records` | RFC-0019 §6: `server.started` carries `identity_mode` `account`; `exec.started` carries `account` and the account's UID in `executing_uid` |
| `account_exit_status` | ADR-0064 §3, ADR-0038 §8: `exit 3` reports 3, and `kill -TERM $$` reports `exit-signal`, through the launcher |
| `account_client_gone_kills` | ADR-0064 §4: when the client goes away, the session's process group is killed |
| `account_sftp_ownership` | RFC-0020's Guide: a file put over SFTP belongs to the account and its primary group |
| `account_nologin` | RFC-0020 §5: for `qssh-nologin`, `exec` fails as `nologin` makes it fail, and an `sftp` batch works |
| `account_unlisted_refused` | RFC-0019 §3: `root`, `qssh-unlisted` and a name with no entry each get `Permission denied (publickey).`, as a wrong key does |
| `account_key_bound_to_account` | RFC-0019 §5: `qssh-alice`'s key does not log in to `qssh-deploy` |
| `account_certificate_principal` | RFC-0019 §5: a certificate with the principal `qssh-alice` logs in to `qssh-alice` and not to `qssh-deploy` |

**What a stock client cannot reach is tested elsewhere,** in unit and
integration tests:

- RFC-0019 §2's change of user name mid-authentication, which the
  client never sends;
- the startup refusals: a listed UID 0, a start other than as root, a
  listed service account, a writable executable, and
  `--require-account-mode` with no account (ADR-0066 §1);
- the launcher's protocol faults, which ADR-0063 also fuzzes.

### 4. When the cases land

- **With the code.** Each case lands in the PR that implements the
  behaviour it checks, under ADR-0062 §8.
- **The setup of §2 lands with the first of them.**
- **Time is measured, not estimated.** The implementing PR measures what
  the cases add to the suite's time, as ADR-0062 §6 measured the suite.

## Consequences

### Positive

- **Every account-mode behaviour a client can see is checked on every
  PR,** against the pinned stock client.
- **The refusals are checked too.** An unlisted account or a key bound
  elsewhere answers as a wrong key does, which is the property that
  keeps the list from being an enumeration oracle.

### Negative

- **The macOS release leg never runs account mode.** That matches where
  account mode exists, but the macOS artifact is never checked as root.
- **The driver gains a setup step** that only makes sense in a
  container.

### Neutral

- **No new workflow, image or required check.** The cases run in the
  existing `openssh-interop` job.

## Alternatives considered

### Alternative 1: run the account cases in the systemd gate

The systemd gate already creates accounts as root. Rejected. That gate
checks the unit, and ADR-0062 makes the interop suite the single
catalogue of what a client sees. ADR-0067 §5 adds an account-mode run to
the systemd gate for the unit's own behaviour.

### Alternative 2: detect a container instead of using a variable

Examples are `/.dockerenv` or the cgroup path. Rejected. The heuristics
differ between engines, and a wrong guess on a developer's machine
creates real accounts. An explicit variable cannot be guessed wrong.

### Alternative 3: create the test accounts in the gate image

Rejected. The image would then carry state that only one script needs,
and building it would have to change for a test detail (ADR-0059).

## Links

- [ADR-0062](0062-conformance-suite-driven-by-the-stock-openssh-client.md) §2, §6, §8.
- [RFC-0019](../rfcs/0019-identity-model-ssh-user-name-to-os-account.md) §2, §3, §5, §6, §8, §9; [RFC-0020](../rfcs/0020-privilege-separation-root-launcher-and-session-helper.md) §4, §5, §8, §12.
- `.github/workflows/interop.yml`, the container job; `tests/systemd/run_reference_unit.sh`.
