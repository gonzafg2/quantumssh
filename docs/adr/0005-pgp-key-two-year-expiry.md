# ADR 0005: Project PGP key expires after two years

- **Status:** Accepted
- **Date:** 2026-05-10
- **Deciders:** Project lead
- **Related:** `SECURITY.md`, `docs/infrastructure.md` § "Project PGP key", `keys/security.asc`

## Context

The project publishes a PGP key for encrypted security disclosures
(`SECURITY.md`). Every PGP key has an expiry date, which can be
"never". The trade-off:

- A shorter expiry forces rotation discipline. A compromised or lost
  key has a bounded window during which it remains trusted by
  reporters who fetched it before the compromise was detected.
- A longer expiry reduces operational overhead. Rotation involves
  generating a new key, updating `SECURITY.md` and `keys/security.asc`,
  notifying the keys.openpgp.org keyserver, and absorbing the brief
  window in which old and new keys coexist for reporters who pre-cached
  the old fingerprint.

For a personal key, two years is widely recommended. For a project key
used for security disclosure, the same window is workable.

## Decision

We will issue the project security PGP key with a two-year expiry.
Rotation is reminded 60 and 30 days before expiry via the local
operational calendar.

## Consequences

### Positive

- A compromised or lost key has a bounded blast radius of at most two
  years before it stops being trusted by clients that re-fetch.
- Forces a deliberate revisit of the key's parameters (algorithm,
  subkey configuration, UID list, keyserver publication) every two
  years.
- Aligns with the rotation cadence published by comparable
  security-conscious OSS projects.

### Negative

- The maintainer must remember to rotate. Mitigation: the rotation
  events are on a calendar with multiple reminders.
- The brief window when the new key is published but reporters have
  not yet refetched leaves a small UX gap. Mitigation: announce
  rotation in `CHANGELOG.md` and via the `security` GitHub label.

### Neutral

- Key signatures and certifications from third parties (e.g., the
  Web of Trust) need to be reattached to the new key, but the project
  does not currently rely on third-party certifications.

## Alternatives considered

### Alternative 1: One-year expiry

Would tighten the blast-radius window. Rejected because the rotation
overhead would dominate the project's release cadence, and the
marginal security benefit over two years is small given that key
revocation is also available out-of-band.

### Alternative 2: Five-year expiry

Would reduce overhead. Rejected because a five-year window is too long
to tolerate for a key used as a trust anchor for embargoed-disclosure
encryption. If an attacker silently exfiltrates the private key and
the maintainer does not notice for years, the project loses
confidentiality on every disclosure submitted during that window.

### Alternative 3: No expiry

Rejected outright. Keys without expiry require all-or-nothing
revocation as the only invalidation mechanism, and an attacker who
controls the revocation certificate (or who is in a position to
suppress its publication) can keep the key trusted indefinitely.

## Links

- Public key: `keys/security.asc` (this repository)
- Fingerprint: `66DB 5100 B070 0E4A E051  971F 9A8D FF06 AFD2 5B24`
- Cross-published at: https://keys.openpgp.org/vks/v1/by-email/security%40quantumssh.org
- Rotation procedure: see the project's local operational notes
