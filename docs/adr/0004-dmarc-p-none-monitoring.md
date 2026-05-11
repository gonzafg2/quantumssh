# ADR 0004: Publish DMARC with `p=none` during the observation window

- **Status:** Accepted
- **Date:** 2026-05-10
- **Deciders:** Project lead
- **Related:** `docs/infrastructure.md` § "Authentication posture", GitHub issue tracking the policy tightening

## Context

DMARC ties SPF and DKIM together with an alignment check and instructs
receivers what to do with messages that fail alignment. The policy
parameter `p` has three meaningful values:

- `none` — record alignment failures via aggregate reports; take no
  receiver-side action.
- `quarantine` — treat aligning-but-failing messages as suspicious
  (typically: route to spam).
- `reject` — refuse aligning-but-failing messages.

Tightening from `none` toward `reject` increases protection against
abuse of the domain in mail headers, but at the cost of risking
legitimate sources being silently dropped if SPF/DKIM are not yet
correctly configured everywhere.

The project does not currently send outbound mail under
`quantumssh.org` — it only receives via Cloudflare Email Routing —
so the surface for legitimate-source confusion is small but not zero.

## Decision

We will publish DMARC as
`v=DMARC1; p=none; rua=mailto:<Cloudflare aggregate-report endpoint>`
during a 30-day observation window. After 30 days of report data, the
policy will be reconsidered and likely tightened to `p=quarantine`,
and from there to `p=reject` after a further observation period.

## Consequences

### Positive

- Aggregate reports flow in from major receivers (Google, Microsoft,
  Yahoo) immediately, with no risk of dropping legitimate mail.
- Operational confidence in the SPF/DKIM configuration is built from
  real receiver feedback before tightening.

### Negative

- An attacker can currently send mail spoofing `@quantumssh.org` and
  have it merely reported, not rejected. The window during which this
  matters is bounded by the 30-day observation; after tightening the
  exposure shrinks materially.

### Neutral

- Cloudflare Email Routing auto-manages the SPF and DKIM records on
  the receiving side; the DMARC TXT record is the only one we
  manage explicitly for this decision.

## Alternatives considered

### Alternative 1: Start at `p=quarantine` immediately

Would shorten the abuse window. Rejected because the project has no
historical sending pattern under this domain, no observation of which
relays might be in use, and tightening prematurely risks silently
dropping legitimate mail that nobody is paying attention to (the
project is single-maintainer in Phase 0).

### Alternative 2: Start at `p=reject` immediately

Strongest policy. Rejected for the same reason as quarantine, plus
the additional risk that any future legitimate sender (e.g., a
mailing-list relay set up later) would be silently broken without
warning.

### Alternative 3: Skip DMARC entirely

Would leave the domain with no abuse signal. Rejected because DMARC
costs nothing to publish and starts producing data from day one.

## Links

- Current record: verify with `dig +short TXT _dmarc.quantumssh.org @1.1.1.1`
- Cloudflare Email Routing settings panel
