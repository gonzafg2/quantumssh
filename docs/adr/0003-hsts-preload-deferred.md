# ADR 0003: Set the HSTS preload directive but defer list submission

- **Status:** Fully superseded on 2026-05-11. The `max-age` value chosen here (6 months) was superseded by [ADR-0012](0012-hsts-max-age-bumped-to-one-year.md) (1 year). The preload-list submission deferral was superseded by [ADR-0014](0014-hsts-preload-submitted.md) when the domain was submitted to the browser preload list ahead of the original 60-day observation target.
- **Date:** 2026-05-10
- **Deciders:** Project lead
- **Related:** `docs/infrastructure.md` § "TLS posture", GitHub issue tracking the submission decision

## Context

HSTS protects against active downgrade attacks on first-visit traffic
by instructing browsers to refuse non-HTTPS connections to the host.
The browser-side enforcement only kicks in after the first successful
HTTPS visit — unless the host is on the browser's built-in HSTS
preload list, which is shipped with Chromium, Firefox, Safari, and
Edge.

To be eligible for the preload list, the host must serve an HSTS
response with `max-age` of at least one year, `includeSubDomains`,
and the `preload` directive. Eligibility is necessary but not
sufficient: the host owner must then submit the domain at
`hstspreload.org`. Inclusion is processed and shipped in browser
updates, then can take **months** of waiting to remove once accepted.

The trade-off is between protection (preload list is the strongest
form of HSTS) and reversibility (removal is slow).

## Decision

We will configure HSTS with `max-age=15552000; includeSubDomains; preload`
on the project's apex and `www` endpoints, but we will **not** submit
the domain to `hstspreload.org` during Phase 0.

A decision to submit (or to skip) will be revisited approximately 60
days after the directive was set, when the project has accumulated
enough operational evidence that its HTTPS surface is stable.

## Consequences

### Positive

- Returning visitors get full HSTS enforcement (`max-age` is six
  months).
- The `preload` directive is set in the header, signaling intent.
  Actual preload-list submission will additionally require bumping
  `max-age` to at least 31536000 (one year) per hstspreload.org
  requirements; that bump is one configuration change at submission
  time, not a re-architecting.
- Deferral avoids irreversibly committing to a long removal window
  before the project has observed its own HTTPS behaviour.

### Negative

- First-time visitors are not protected by browser preload until
  submission is completed and the new browser versions ship.
- The `includeSubDomains` directive will block any future subdomain
  that is not HTTPS — currently the project has no such subdomains,
  but a future need (e.g., a development environment on HTTP) would
  conflict.

### Neutral

- The `preload` directive in the header without a matching submission
  is a no-op from a browser-enforcement standpoint, but it signals
  intent to crawlers and scanners.

## Alternatives considered

### Alternative 1: Submit to the preload list now

Would maximise protection for first-time visitors. Rejected because
removal is months-long, and the project is too new to be confident
that no HTTPS regression will surface. A six-week observation window
is a cheap insurance policy.

### Alternative 2: Skip the `preload` directive entirely

Would leave the protection at the `max-age` baseline and remove any
implicit commitment. Rejected because the `preload` directive is one
of several preload-list eligibility requirements (alongside
`max-age` ≥ 31536000, `includeSubDomains`, and HTTP → HTTPS
redirection); including it now costs nothing, signals intent, and
keeps a clean configuration for the submission decision. Only the
explicit submission locks anything in.

### Alternative 3: Shorter `max-age`

Would reduce the recovery cost of an HTTPS regression. Rejected
because the preload-eligibility floor is one year (we are at six
months currently, which is below preload floor anyway; tightening to
align with preload floor will be part of the submission decision).

## Links

- Header as currently served: verify with
  `curl -sI https://www.quantumssh.org | grep -i strict-transport-security`
- Cloudflare HSTS configuration: SSL/TLS → Edge Certificates → HSTS
- Preload list status check:
  https://hstspreload.org/?domain=quantumssh.org
