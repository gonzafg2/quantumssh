# ADR 0013: Tighten DMARC policy to `p=reject`

- **Status:** Accepted
- **Date:** 2026-05-11
- **Deciders:** Project lead
- **Related:** Supersedes [ADR-0004](0004-dmarc-p-none-monitoring.md). See also [`docs/infrastructure.md` § "Authentication posture"](../infrastructure.md#authentication-posture) and GitHub issue #11.

## Context

[ADR-0004](0004-dmarc-p-none-monitoring.md) set DMARC to `p=none`
during a 30-day observation window. The rationale was that a sudden
move to a stricter policy could silently drop legitimate mail from
relays the project did not yet know about, and that 30 days of
aggregate reports would surface any such senders before tightening.

Reviewing the situation a day after the observation window opened:
the project does not send outbound mail under `quantumssh.org`. It
only receives via Cloudflare Email Routing. The full sender profile
is therefore known to be empty by construction, not by observation.

When the legitimate-sender set is empty, the entire purpose of the
observation window — surfacing senders before they get dropped —
disappears. There is no one to false-positive against. Skipping
directly to `p=reject` is safe today.

## Decision

We will publish DMARC as:

```
v=DMARC1; p=reject; rua=mailto:<Cloudflare aggregate-report endpoint>
```

This skips the intermediate `p=quarantine` step that ADR-0004
contemplated. Receivers will outright **reject** mail that fails
alignment under `quantumssh.org`, rather than routing it to spam.

## Consequences

### Positive

- Any unauthorized sender attempting to spoof `@quantumssh.org` is
  rejected by compliant receivers immediately, not merely flagged
  as suspicious.
- The abuse window during which an attacker could use this domain
  for phishing or impersonation closes the moment caches refresh
  (well under 24h).
- Aggregate reports continue to flow in via the `rua` endpoint, so
  any future configuration drift surfaces as a report.

### Negative

- **Any future legitimate sender** under `@quantumssh.org` — a
  third-party newsletter platform, a transactional-mail service, an
  alerting integration, a CI bot that emails the project — must be
  perfectly aligned with SPF + DKIM before it sends. Misalignment
  results in outright rejection at the receiver, not in a spam-folder
  fallback. Operational mitigation: any plan to add outbound mail in
  the future must include the SPF/DKIM configuration as part of the
  same change. This is documented as a follow-up consideration in
  `CHANGELOG.md`.
- The recovery path from a misconfiguration is slightly more visible
  (bounces) than under `p=quarantine` (silent spam-folder routing).
  This is arguably a positive trait (failures are loud rather than
  quiet) but should be acknowledged.

### Neutral

- Inbound forwarding via Cloudflare Email Routing is entirely
  unaffected — DMARC policies govern outbound, not inbound.

## Alternatives considered

### Alternative 1: Stay at `p=none` for the full 30-day window

The plan ADR-0004 originally laid out. Rejected because the
30-day window was a safety check against an unknown sender profile.
The sender profile is now known to be empty by construction, so the
window has no protective value to add.

### Alternative 2: Move to `p=quarantine` first, then to `p=reject` after a further 30 days

The two-step path ADR-0004 contemplated. Rejected for the same
reason as Alternative 1 — the intermediate step adds no risk
reduction when there are no legitimate senders to validate.

### Alternative 3: Stay at `p=none` indefinitely

Some operators prefer monitoring without enforcement as a long-term
posture. Rejected because the project has a non-trivial brand and
maintainer-identity surface tied to this domain; an attacker who
can send mail under `@quantumssh.org` can impersonate the project
in ways that harm vulnerability reporters and the broader community.
`p=reject` is the appropriate posture for an SSH project's identity
domain.

## Links

- Verify the served policy:
  `dig +short TXT _dmarc.quantumssh.org @1.1.1.1`
- Parent ADR (superseded): [ADR-0004](0004-dmarc-p-none-monitoring.md)
- GitHub issue tracking the tightening (now resolved by this ADR): #11
