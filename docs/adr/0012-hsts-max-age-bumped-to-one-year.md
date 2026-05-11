# ADR 0012: Bump HSTS `max-age` to one year

- **Status:** Accepted
- **Date:** 2026-05-11
- **Deciders:** Project lead
- **Related:** Partially supersedes [ADR-0003](0003-hsts-preload-deferred.md) (the `max-age` value; the preload-list submission deferral established in that ADR remains in effect). See also [`docs/infrastructure.md` § "TLS posture"](../infrastructure.md#tls-posture) and GitHub issue #10.

## Context

[ADR-0003](0003-hsts-preload-deferred.md) set `max-age=15552000`
(six months) as a conservative starting point during the project's
HTTPS observation window. The same ADR documented that this value is
below the one-year (`31536000`) floor required by `hstspreload.org`
for preload-list submission eligibility, and that a future bump to
the floor was part of the eventual submission decision.

In practice, the project has run on the six-month value without
HTTPS regressions. The maintainer is comfortable making a multi-year
commitment to HTTPS-only on the apex and on all subdomains (which is
what `includeSubDomains` with a longer `max-age` implies), and
bumping `max-age` now keeps the option of submitting to the preload
list later (per ADR-0003's deferral) open without any further
configuration change at submission time.

## Decision

We will increase the HSTS `max-age` directive to `31536000` seconds
(one year), keeping `includeSubDomains` and the `preload` directive
set. The header now reads:

```
strict-transport-security: max-age=31536000; includeSubDomains; preload
```

We do **not** submit the domain to the `hstspreload.org` preload list
in this decision. The deferral from ADR-0003 remains in effect; a
separate decision and ADR will close that decision when the time
comes.

## Consequences

### Positive

- Repeat visitors get HTTPS enforcement for 12 months after their
  last visit, up from 6 months.
- The header now meets the `max-age` floor required by
  hstspreload.org. One of the multiple preload-list eligibility
  conditions is satisfied; the others (notably the HTTP→HTTPS
  same-host first-hop redirect) remain unresolved by design.

### Negative

- A 12-month commitment to HTTPS-only on `quantumssh.org` and all
  subdomains. If a future subdomain (e.g., a dev environment) is
  configured to serve plain HTTP, browsers that have already
  received this header will refuse to load it for the duration of
  the cache window.
- An HTTPS regression now has a 12-month tail of browser-side
  enforcement to recover from, rather than 6 months. The "tail of
  regret" doubles.

### Neutral

- The Cloudflare panel UI lists the option as "12 months" rather
  than a raw second count; the underlying header value is the same
  31536000 seconds.

## Alternatives considered

### Alternative 1: Keep `max-age` at six months

The cautious baseline ADR-0003 established. Rejected because the
observation window has passed without incident and the project is
ready to make a longer commitment.

### Alternative 2: Bump and submit to the preload list in the same decision

Would satisfy the strongest form of HSTS in one step. Rejected
because the preload-list submission has additional irreversibility
cost (months to remove) that is independent of the `max-age` choice,
and additional eligibility blockers (the redirect chain requires
HTTP→HTTPS on the same host before going to GitHub) that have not
been addressed. ADR-0003's separation of these decisions remains
valuable.

### Alternative 3: Bump to two years

Some preload-eligible sites use longer cache windows. Rejected
because one year is the floor required by hstspreload.org; going
above the floor doubles the recovery tail without a corresponding
protection benefit at this stage of the project.

## Links

- Verify the served header:
  `curl -sI https://www.quantumssh.org | grep -i strict-transport-security`
- Verify preload eligibility status:
  `curl -sS 'https://hstspreload.org/api/v2/preloadable?domain=quantumssh.org'`
- Parent ADR (partially superseded): [ADR-0003](0003-hsts-preload-deferred.md)
- GitHub issue tracking the remaining preload-submission decision: #10
