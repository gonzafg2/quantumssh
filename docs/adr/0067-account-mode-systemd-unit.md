# ADR 0067: The account-mode systemd unit

- **Status:** Proposed
- **Date:** — (set on acceptance; drafted 2026-11-24)
- **Deciders:** Project lead
- **Related:**
  - Implements [RFC-0020](../rfcs/0020-privilege-separation-root-launcher-and-session-helper.md) §8, and answers its unresolved question 3, the launcher's capability bounding set. It is the fifth item of RFC-0020 §12: "the account-mode unit".
  - Runs the processes of [ADR-0066](0066-account-mode-start-readiness-and-stop.md).
  - Keeps [ADR-0043](0043-systemd-notify-service-and-reference-unit.md)'s unit as the service-account-mode unit (RFC-0020 §10). Its directives, and its reasons for leaving sandboxing out (§4), carry over except where this ADR says otherwise.

## Context

ADR-0043's unit starts the server as `User=quantumssh`, with
`NoNewPrivileges=yes`. RFC-0020 §8 says that account mode needs a
different unit:

- **no `User=`,** so that systemd starts the launcher as root;
- **no `NoNewPrivileges=`,** because the flag would bind every session,
  and a real account's session may rely on `sudo`. The network server
  sets `no_new_privs` on itself instead (ADR-0066 §2);
- **the launcher is the main process** for `Type=notify` and
  `NotifyAccess=main`.

RFC-0020's unresolved question 3 leaves the bounding set to this ADR,
which must say what it costs sessions. capabilities(7) gives two facts
that decide it:

- **The bounding set is inherited, unchanged, across `execve`.**
  capabilities(7) gives the rule as `P'(bounding) = P(bounding)`, so
  every session inherits the launcher's set.
- **It caps what a program can gain.** At `execve`, "the capability
  bounding set is ANDed with the file permitted capability set, and the
  result of this operation is assigned to the thread's permitted
  capability set". A set-user-ID-root program such as `sudo` therefore
  gets only the capabilities in the bounding set.

## Decision

### 1. The unit: `contrib/systemd/quantumssh-account-mode.service`

```ini
[Unit]
Description=QuantumSSH server (account mode)
Documentation=https://github.com/gonzafg2/quantumssh/blob/main/docs/deployment.md
After=network.target

[Service]
Type=notify
NotifyAccess=main
ExecStart=/usr/local/bin/quantumssh --config /etc/quantumssh/config.toml --require-account-mode
KillMode=mixed
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

**How an operator installs it.** It goes in as
`/etc/systemd/system/quantumssh.service`, in place of ADR-0043's unit.
An operator installs the unit that matches the configuration's mode.
Both mistakes fail the start, and the error names the reason:

- **An account-mode configuration under ADR-0043's unit** is not running
  as root (ADR-0066 §1).
- **A service-account configuration under this unit** meets
  `--require-account-mode`, which refuses a configuration that lists no
  account (ADR-0066 §1). Without the flag it would serve the network as
  root.

What differs from ADR-0043 §3, and why:

- **No `User=` or `Group=`.** systemd starts the launcher as root, and
  the launcher starts the server as `quantumssh` (ADR-0066 §2).
- **`--require-account-mode` on `ExecStart=`.** A unit that starts as
  root must never run the network server as root, so it refuses a
  configuration without accounts (ADR-0066 §1).
- **No `NoNewPrivileges=`.** RFC-0020 §8 gives the reason above.
- **`Type=notify` and `NotifyAccess=main`.** The launcher is the main
  process and the only process that notifies (ADR-0066 §3). The
  directive stays load-bearing: neither the server nor a session can
  drive the service manager.
- **`KillMode=mixed`.** `SIGTERM` goes to the launcher alone, which
  forwards it to the server (ADR-0066 §4). When the launcher exits,
  systemd sends `SIGKILL` to whatever is left in the cgroup, as under
  ADR-0043.
- **`Restart=on-failure`.** The launcher exits with 1 when the server
  crashes (ADR-0066 §5), so a crash restarts both.
- **Nothing for port 22.** The launcher binds as root (ADR-0066 §2), so
  the unit needs no capability and the guide needs no firewall redirect.
  ADR-0043 §4 still applies to service-account mode.

`ExecReload=`, `TimeoutStopSec=` and `WorkingDirectory=` stay absent,
for ADR-0043's reasons.

### 2. The capability bounding set

**The unit sets no `CapabilityBoundingSet=`.**

- **What setting one would cost sessions.** Sessions inherit the set,
  so `sudo` in a session would run as UID 0 with only the capabilities
  the set keeps. A set narrow enough to confine the launcher would take,
  for example, `CAP_DAC_OVERRIDE` from root in every session. An
  account's `sudo` would then fail in ways its sudoers file does not
  explain.
- **What leaving it unset costs.** The launcher keeps root's full set.
  What it exposes is its parser of server messages (ADR-0063) and the
  startup it runs before the network server exists.
- **An operator who wants no session to gain privilege** sets
  `NoNewPrivileges=yes`, as RFC-0020 §8 allows, and loses `sudo` in
  every session. A session's `execve` then gains no privilege at all,
  so a bounding set would change nothing for sessions. The operator
  guide states both options and their costs.

### 3. Sandboxing

ADR-0043 §4 holds here too. `ProtectSystem=`, `ProtectHome=`,
`PrivateDevices=` and the rest would confine every session along with
the launcher. Under this unit they also bind a root process that needs
`/dev/ptmx` and `/dev/pts`, `/etc/passwd` and `/etc/group`. They stay
the operator's choice (threat model §8.8).

### 4. Operator guide, `docs/deployment.md`

An account-mode section covers:

- **which unit to install,** and the start failure that each wrong
  combination gives (§1);
- **the service account,** still required and still named `quantumssh`
  (ADR-0066 §1);
- **file ownership:**
  - the configuration, the CA file and every account key file are owned
    by root, with root-owned ancestors and no symlinks (RFC-0019 §8);
  - the host key is owned by `quantumssh` with mode `0600`, because the
    server reads it;
- **RFC-0020 §8's warning, as it stands.** List only accounts whose
  whole privilege you accept exposing to a compromise of the network
  server. That includes their ways to become root, such as `sudo` or the
  `docker` group.

### 5. Verification: the systemd gate

`tests/systemd/run_reference_unit.sh` (ADR-0043 §7) gains an
account-mode run in the same disposable container. It creates the
service account and two test accounts, and installs this unit. It then
checks:

- **The unit runs.** `systemctl start` leaves the unit active.
- **The session's identity.** A session runs as its account, `id -un`,
  in its home, `pwd -P`.
- **The three processes' identities.**
  - The main process runs as UID 0.
  - The server runs as `quantumssh`, with `NoNewPrivs` 1.
  - A session has `NoNewPrivs` 0.
- **Reload.** `systemctl reload` is refused.
- **The wrong configuration.** A configuration that lists no account
  fails the start under this unit, and the journal names
  `--require-account-mode`.
- **The stop.** It runs under `TimeoutStopSec=2`, shorter than a 4 s
  drain, while a session runs and a `setsid` process has escaped.
  - It ends with `Result=success` after the drain.
  - No process of the test accounts is left.
  - The journal holds as many `exec.finished` records as
    `exec.started`.

## Consequences

### Positive

- **Sessions run as their accounts under systemd,** with `sudo`
  available to accounts that have it.
- **Port 22 needs no capability grant and no redirect.**
- **Only the launcher can talk to systemd.**

### Negative

- **Two reference units, one per mode.** Installing the wrong one fails
  the start, with an error that names the reason (§1).
- **One more command-line flag,** `--require-account-mode`, which only
  this unit needs.
- **The launcher keeps root's full capability set** (§2).
- **No sandboxing by default,** as under ADR-0043.

### Neutral

- **The service-account-mode unit is unchanged.**

## Alternatives considered

### Alternative 1: one unit for both modes

Both modes would start without `User=`, and the binary would drop to the
service account itself in service-account mode. Rejected. Service-account
mode would start as root for no gain, and RFC-0020 keeps that mode as it
is.

### Alternative 2: a drop-in over ADR-0043's unit

The drop-in would undo `User=`, `Group=` and `NoNewPrivileges=`.
Rejected. The effective unit would then depend on two files, and on how
each directive treats an override. A complete file is easier to read and
to check.

### Alternative 3: a bounding set limited to what the launcher needs

Rejected for the reference unit. It would limit `sudo` in every session
(§2). An operator who accepts that can add one through a drop-in.

### Alternative 4: `NoNewPrivileges=yes` in the reference unit

Rejected. RFC-0020 §8 leaves it out so that sessions can use `sudo`.
Operators who want it can set it (§2).

### Alternative 5: refuse root in service-account mode

That would close the same mistake without a flag. Rejected:

- It changes service-account mode, which RFC-0020 leaves as it is.
  ADR-0016 names a non-root account, but the binary has never refused
  root.
- The interop gate runs that mode as root in its container (ADR-0068),
  and so can anyone who runs the server in a container. Each of them
  would break.

The flag puts the check only where the mistake can happen: in the unit
that starts as root.

## Links

- [RFC-0020](../rfcs/0020-privilege-separation-root-launcher-and-session-helper.md) §8, §10, §12, unresolved question 3.
- [ADR-0043](0043-systemd-notify-service-and-reference-unit.md) §3, §4, §7.
- capabilities(7), Linux man-pages 6.19: "Capability bounding set"; "Transformation of capabilities during execve()".
- systemd.exec(5): `NoNewPrivileges=`, `CapabilityBoundingSet=`. systemd.kill(5): `KillMode=`.
