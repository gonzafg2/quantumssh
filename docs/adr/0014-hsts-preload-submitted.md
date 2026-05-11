# ADR 0014: Achieve HSTS preload-list eligibility and submit

- **Status:** Accepted
- **Date:** 2026-05-11
- **Deciders:** Project lead
- **Related:** Fully completes the path that [ADR-0003](0003-hsts-preload-deferred.md) deferred. Builds on [ADR-0012](0012-hsts-max-age-bumped-to-one-year.md) (which removed the `max-age` blocker). See also [`docs/infrastructure.md` § "TLS posture"](../infrastructure.md#tls-posture) and the now-closed GitHub issue #10.

## Context

[ADR-0003](0003-hsts-preload-deferred.md) deliberately deferred
submission of `quantumssh.org` to the browser HSTS preload list while
the project observed its own HTTPS behaviour. The original target was
roughly 60 days post-activation.

Since then, two of the four `hstspreload.org` eligibility requirements
were already met by the Phase 0 configuration (the `preload` directive
in the header and `includeSubDomains`). The remaining two:

1. **`max-age` ≥ 31536000.** Addressed by
   [ADR-0012](0012-hsts-max-age-bumped-to-one-year.md), which bumped
   `max-age` from six months to one year.
2. **First HTTP-to-HTTPS hop must be to the same host.** Still failing
   at the time ADR-0012 landed, because the project's Cloudflare
   Redirect Rule matched on hostname only (no protocol filter), so an
   HTTP request to `http://quantumssh.org` triggered the redirect
   straight to `https://github.com/...` in a single hop, bypassing
   Cloudflare's "Always Use HTTPS" setting that would otherwise have
   upgraded HTTP to HTTPS on the same host first.

Cloudflare evaluates Redirect Rules before SSL-level settings such as
"Always Use HTTPS". Without scoping the rule, the rule always wins
against the HTTPS-upgrade step.

The maintainer also reconsidered the original observation-window
rationale. The project's `README.md` makes a "no compatibility with
old clients" and "open and staying open" commitment posture that
implies HTTPS-only as a structural commitment, not as a configuration
choice that could be unwound. Staying eligible-but-not-submitted on
the preload list is consistent with that posture only as a transient
state; long-term eligibility-without-submission would be a contradiction
the project does not need to maintain.

## Decision

We will close out both remaining items in a single change:

1. **Scope the Cloudflare Redirect Rule to HTTPS-only.** The rule's
   filter expression becomes:

   ```
   (http.host eq "quantumssh.org" and ssl)
     or (http.host eq "www.quantumssh.org" and ssl)
   ```

   This makes the rule a no-op for HTTP requests. Cloudflare's
   "Always Use HTTPS" setting then handles the HTTP-to-HTTPS upgrade
   on the same host first, after which the (now applicable) Redirect
   Rule sends the HTTPS request to the GitHub repository. The
   resulting redirect chain for an HTTP request is two hops, with the
   first hop staying on `quantumssh.org`.

2. **Submit `quantumssh.org` to the browser HSTS preload list** at
   `hstspreload.org/?domain=quantumssh.org`, acknowledging the
   irreversibility of the submission.

The maintainer performed both changes on 2026-05-11. The
`hstspreload.org` API now reports `status: "pending"` (in queue for
inclusion in the next Chromium release; other browsers follow on their
own cadence) and `preloadable` returns `errors: []`.

## Consequences

### Positive

- First-time visitors typing `quantumssh.org` in a browser address bar
  are protected from active downgrade attacks on their initial request
  once the domain ships in browser preload lists, without needing a
  prior successful HTTPS visit to learn the HSTS header.
- The project's "no escape from HTTPS" posture is now hardcoded into
  browser binaries themselves, not merely served as a response header.
- The redirect chain is observable end-to-end (two clean 301 hops for
  HTTP traffic; one for HTTPS direct). Future drift surfaces under
  `curl -sIL`.

### Negative

- **Removal from the preload list is slow.** Per Chrome's own
  documentation it takes six to twelve weeks of waiting for a
  preload-list-removal release to ship, and other browsers may take
  longer. If the project ever needs to serve plain HTTP on
  `quantumssh.org` or any subdomain — for example, a temporary dev
  environment that does not have a valid certificate — that traffic
  is unreachable from any browser that received a preload list
  containing this domain. The project accepts this trade-off because
  no realistic future use case requires plain HTTP on this domain.
- The Redirect Rule now has a slightly more complex filter expression.
  A future contributor editing it must remember the `ssl` clause, or
  the rule will go back to overriding "Always Use HTTPS" for HTTP
  traffic. The clause's role is documented in this ADR and inline in
  the rule expression.

### Neutral

- Behaviour for direct HTTPS requests (`https://quantumssh.org/...`)
  is unchanged: the Redirect Rule fires once, 301 to GitHub.
- Inclusion in the actual browser preload list takes four to eight
  weeks (one or two Chromium release cycles), so the runtime effect
  for first-time visitors lags this decision by that window. The
  decision itself is effective immediately.

## Alternatives considered

### Alternative 1: Stay eligible but not submitted

The deferred state ADR-0003 originally established. Rejected because
the project's commitment posture toward HTTPS is structural, not
provisional. Maintaining eligibility-without-submission as a long-term
state would contradict the manifesto's framing of openness and
permanence; the project would be saying "we are committed to
HTTPS-only, except we have left ourselves a quiet escape hatch in case
we change our minds". The submission closes that gap.

### Alternative 2: Wait until the original 2026-07-10 target

The observation window ADR-0003 contemplated. Rejected because the
observation window's purpose was to surface HTTPS regressions during
the project's first operational weeks, and none have occurred.
Continuing to wait offers diminishing information returns against the
fixed cost of staying off the preload list during that period.

### Alternative 3: Skip the redirect-chain fix and submit anyway

Submission would have failed eligibility check at `hstspreload.org`,
rejecting the form. The fix is structurally required.

### Alternative 4: Achieve the redirect-chain fix differently (e.g., remove the Redirect Rule entirely and rely on a static `Always Use HTTPS` plus a different mechanism)

Considered. Rejected because the Redirect Rule still does useful work
(translating apex/`www` HTTPS into the GitHub repository URL with
path preservation). Scoping it to `ssl` is the minimal change that
restores correct interaction with "Always Use HTTPS".

## Links

- Submission confirmation:
  `curl -sS https://hstspreload.org/api/v2/status?domain=quantumssh.org`
  → `{"name": "quantumssh.org", "status": "pending", ...}`
- Eligibility confirmation:
  `curl -sS https://hstspreload.org/api/v2/preloadable?domain=quantumssh.org`
  → `{"errors": [], "warnings": []}`
- Observed redirect chain (HTTP apex):
  `curl -sIL http://quantumssh.org` → two 301 hops, first to
  `https://quantumssh.org/`, second to `https://github.com/gonzafg2/quantumssh`.
- Parent ADRs (now fully resolved): [ADR-0003](0003-hsts-preload-deferred.md), [ADR-0012](0012-hsts-max-age-bumped-to-one-year.md)
- Closes GitHub issue #10.
