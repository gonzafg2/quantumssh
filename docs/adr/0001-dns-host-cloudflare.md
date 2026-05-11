# ADR 0001: Use Cloudflare as the authoritative DNS host

- **Status:** Accepted
- **Date:** 2026-05-10
- **Deciders:** Project lead
- **Related:** [ADR-0002](0002-registrar-namecheap.md) (registrar), [ADR-0007](0007-caa-whitelist-includes-cloudflare-pool.md) (CAA), `docs/infrastructure.md` § "DNS host — Cloudflare"

## Context

The project domain `quantumssh.org` needs an authoritative DNS host
that supports:

- DNSSEC signing with current algorithms
- Inbound email forwarding (the project does not run its own MTA)
- HTTPS redirection (the project does not run an origin web server in
  Phase 0)
- CAA management
- A free or near-free tier (the project has no operational budget)

The decision affects long-term operational dependency: switching DNS
hosts later is non-trivial (re-issuing DNSSEC, migrating Email Routing
records, reconfiguring redirect rules).

## Decision

We will host the authoritative DNS zone for `quantumssh.org` at
Cloudflare under the free plan.

## Consequences

### Positive

- DNSSEC enabled at zero cost with ECDSA P-256 keys.
- Email Routing replaces a self-operated MTA, with verified destination
  forwarding and no monthly cost.
- Redirect Rules handle apex + `www` 301 to the GitHub repository
  without requiring an origin server.
- Universal SSL provides edge-terminated TLS automatically across
  multiple CAs.
- Anycast resolution across hundreds of POPs gives global latency
  characteristics out of the box.

### Negative

- Operational dependency on a single commercial provider with
  significant power to deplatform. The project accepts this in
  exchange for operational simplicity.
- The free plan locks the two assigned nameservers; we cannot select
  them.
- Some auto-managed records (e.g., the auto-injected CAA entries
  documented in [ADR-0007](0007-caa-whitelist-includes-cloudflare-pool.md))
  are outside the project's direct control.

### Neutral

- The `192.0.2.1` / `100::` addresses used at the apex are RFC 5737 /
  RFC 6666 dummies; Cloudflare's proxy serves the actual traffic from
  its anycast pool.

## Alternatives considered

### Alternative 1: Self-hosted DNS (e.g., PowerDNS or NSD on a small VM)

Would give full control and no third-party dependency. Rejected
because it is operationally disproportionate for a project that
currently has no traffic, would require us to also run an MTA and a
web server for the redirect, and would not pay for itself before there
is a real service to host.

### Alternative 2: NS1 or Amazon Route 53

Both are mature and feature-rich. Rejected because they are not free
at the relevant scale and the additional features over Cloudflare's
free plan are not yet needed.

### Alternative 3: DigitalOcean DNS or similar free DNS hosts

Free, but lacks the integrated Redirect Rules and Email Routing that
Cloudflare provides. Would require a separate provider for the redirect
and for inbound mail, increasing the operational dependency count.

## Links

- Records as deployed: see `docs/infrastructure.md` § "Records reference"
- Verification commands: `docs/operations.md` § "DNS chain of trust"
- Recovery procedure if Cloudflare is unreachable: see the project's
  local operational notes (not in the public repository)
