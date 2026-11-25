# ADR 0073: The release tarball ships the account-mode unit

- **Status:** Proposed
- **Date:** — (set on acceptance; drafted 2026-11-25)
- **Deciders:** Project lead
- **Related:**
  - Refines [RFC-0017](../rfcs/0017-alpha-distribution.md) §3, which lists what each release tarball holds, `contrib/systemd/quantumssh.service` among them.
  - Ships the unit of [ADR-0067](0067-account-mode-systemd-unit.md) §1, and extends to it the systemd gate on the artifact of [ADR-0055](0055-interop-gate-on-published-artifacts.md) §2.

## Context

RFC-0017 §3 lists the contents of each tarball. It holds one unit, the
service-account-mode unit of ADR-0043.

ADR-0067 adds a second unit, for account mode, and its §5 adds an
account-mode run to the systemd gate. ADR-0055 §2 runs that gate on the
released artifact, with the unit the tarball ships rather than the
checkout's copy. That way the gate checks the bytes an operator installs.

If the tarball does not ship the second unit:

- **An operator who installs from a release** has to fetch the
  account-mode unit from the repository. The commit they fetch it from
  may not match the binary.
- **The release gate cannot check** the unit an operator installs for
  account mode.

## Decision

### 1. What the tarball holds

Each tarball also ships `contrib/systemd/quantumssh-account-mode.service`,
next to `contrib/systemd/quantumssh.service`:

- `scripts/release/package.sh` installs it with mode `0644`, as it
  installs the other unit.
- It ships in every target's tarball. The service-account unit already
  does the same.
- Nothing else in RFC-0017 §3 changes.

### 2. The release gate

ADR-0055 §2's run on the `x86_64` artifact installs both units from the
tarball. Its account-mode run (ADR-0067 §5) installs the shipped
`quantumssh-account-mode.service`, not the checkout's copy.

### 3. The operator guide

`docs/deployment.md` installs the account-mode unit from the extracted
tarball or from a checkout, as it already does the other unit.

## Consequences

### Positive

- **An operator gets the unit that matches the binary.**
- **The release gate checks the unit an operator installs,** in both
  modes.

### Negative

- **The tarball grows by one small text file.**
- **The macOS tarballs carry a unit for a mode macOS does not have.**
  They already carry a systemd unit that macOS cannot use.

### Neutral

- **No new dependency, workflow or required check.**

## Alternatives considered

### Alternative 1: leave the tarball as RFC-0017 §3 lists it

The release gate would then install the checkout's copy of the
account-mode unit. Rejected. The gate would check a unit that no release
ships, and an operator would take the unit from a commit that may not
match the binary.

### Alternative 2: run the account-mode run in CI only

Rejected. The release gate would not check account mode's unit at all.

### Alternative 3: ship the account-mode unit in the Linux tarballs only

Rejected. The service-account unit ships in every tarball. One list for
every target keeps `package.sh` a single path.

## Links

- [RFC-0017](../rfcs/0017-alpha-distribution.md) §3; [ADR-0055](0055-interop-gate-on-published-artifacts.md) §2; [ADR-0067](0067-account-mode-systemd-unit.md) §1, §5.
- `scripts/release/package.sh`; `tests/systemd/run_reference_unit.sh`.
