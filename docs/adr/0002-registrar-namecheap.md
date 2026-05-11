# ADR 0002: Use Namecheap as the domain registrar

- **Status:** Accepted
- **Date:** 2026-05-10
- **Deciders:** Project lead
- **Related:** [ADR-0001](0001-dns-host-cloudflare.md) (DNS host), `docs/infrastructure.md` § "Registrar — Namecheap"

## Context

The registrar's responsibilities for this project are deliberately
narrow:

- Hold the `.org` delegation and keep it renewed.
- Publish the DNSSEC DS record to the parent zone so the chain of
  trust descending from IANA into `quantumssh.org` is unbroken.

The registrar is decoupled from the DNS host: nameservers point at
Cloudflare (per [ADR-0001](0001-dns-host-cloudflare.md)), and the
registrar's only further obligation is the DS submission. The choice
is therefore optimised for renewal price, DS support, and absence of
privacy strip-mining rather than for DNS features.

## Decision

We will register `quantumssh.org` at Namecheap.

## Consequences

### Positive

- Self-service DNSSEC DS submission via the Namecheap UI; no support
  ticket required.
- Renewal pricing at or near the `.org` wholesale floor.
- No privacy strip-mining requirements for non-commercial domains.
- Auto-renew is supported and is configured for this domain.

### Negative

- The registrar relationship is now a separate operational dependency
  from the DNS host, requiring annual attention (renewal) and reactive
  attention if DNSSEC keys ever rotate at Cloudflare and a new DS must
  be published.
- A registrar lapse breaks the redirect, invalidates the inbound email
  aliases, and silently takes the DNSSEC chain out of trust because
  the DS record in `.org` references this zone's KSK.

### Neutral

- The registrar does not host the zone (Cloudflare does); a future
  migration to a different registrar would not affect resolution.

## Alternatives considered

### Alternative 1: Cloudflare Registrar

Preferred for the wholesale-price reason and for the seamless DS
handling within a single account. Rejected because at the time of the
decision the project lead already held a Namecheap account suitable
for `.org`, and onboarding to Cloudflare Registrar would have added
friction without operational benefit. A future migration to Cloudflare
Registrar remains an option, recorded for revisiting.

### Alternative 2: NIC Chile (`.cl` instead of `.org`)

Considered as a Latin-American alternative consistent with the
project's geographic origin. Rejected because constraining the
project's identity to a country-code TLD would have set an
unnecessarily geographic expectation for a piece of infrastructure
that is meant to be used worldwide.

### Alternative 3: Other generic registrars (GoDaddy, Gandi, Porkbun)

Considered briefly. Rejected on price, on questionable historical
practices around WHOIS privacy and pricing surprises, or simply
because Namecheap was already a known quantity.

## Links

- DS record currently published: see `docs/operations.md` § "DNS chain of trust"
- Recovery procedure on domain expiry: see the project's local
  operational notes (not in the public repository)
