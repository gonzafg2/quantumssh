# ADR 0007: Keep Cloudflare's auto-injected CAs in the CAA whitelist

- **Status:** Accepted
- **Date:** 2026-05-10
- **Deciders:** Project lead
- **Related:** [ADR-0001](0001-dns-host-cloudflare.md) (Cloudflare as DNS host), `docs/infrastructure.md` § "Certificate Authority Authorization"

## Context

CAA records (Certification Authority Authorization, RFC 8659) instruct
CAs which authorities are allowed to issue certificates for a domain.
A CA that receives a CSR for a domain is required to check the CAA
records and refuse if the issuance would violate them. The default —
no CAA records — admits every public CA in the world.

The project explicitly authorises:

- Let's Encrypt (`letsencrypt.org`), for any cert the project might
  request directly in the future.
- Google Trust Services (`pki.goog`), one of the CAs Cloudflare uses
  for Universal SSL.

Cloudflare, when it detects manual CAA records on a zone it serves
Universal SSL for, **auto-injects** records covering the rest of its
issuing pool: Sectigo (`comodoca.com`), DigiCert (`digicert.com`),
and SSL.com (`ssl.com`), each for both `issue` and `issuewild`.

This means the project did not author all of the records that appear
on the zone. The choice is whether to accept the auto-injection or
fight it.

## Decision

We will accept Cloudflare's auto-injected CAA entries. The effective
policy is a whitelist of five CAs: Let's Encrypt, Google Trust
Services, Sectigo, DigiCert, and SSL.com. An IODEF entry
(`mailto:security@quantumssh.org`) is published alongside, instructing
CAs to notify us of attempted issuance that violates these CAA records.

## Consequences

### Positive

- Universal SSL renewals continue to work transparently regardless of
  which CA Cloudflare's edge picks for a given renewal cycle.
- The effective policy ("any of these five CAs") is a meaningful
  narrowing relative to the no-CAA default ("any CA on Earth").
- IODEF gives a notification channel for CAA-violating issuance
  attempts, providing a detection path for some classes of mis-issuance.

### Negative

- The project does not directly control the full list. If Cloudflare
  changes its Universal SSL CA pool, the CAA records will silently
  follow. Mitigation: this is a property of relying on Cloudflare for
  edge SSL ([ADR-0001](0001-dns-host-cloudflare.md)); we accept it.
- The whitelist is wider than strictly necessary. A genuinely-strict
  policy would authorise only LE and GTS. Mitigation discussed below.

### Neutral

- The mix of authorised CAs is rotated by Cloudflare, not by the
  project. From the project's perspective, this is no different from
  rotating among Let's Encrypt subordinate CAs.

## Alternatives considered

### Alternative 1: Fight Cloudflare's auto-injection — declare only LE and GTS

Would yield the strictest policy and the smallest CA attack surface.
Rejected because Cloudflare auto-injection is not user-controllable
in the free plan, and removing the injected entries by automation
would create a silent failure mode: the next Universal SSL renewal
that landed on a CA not in the project-managed list would fail, and
the project's HTTPS would break at certificate expiry. The cost of
that silent failure outweighs the marginal security gain of the
tighter whitelist.

### Alternative 2: Remove CAA entirely

Would eliminate the operational concern about auto-injection.
Rejected because going from a five-CA whitelist back to "every CA on
Earth" is a meaningful weakening, even with Cloudflare's pool being
a known set in practice.

### Alternative 3: Pin to a single CA (e.g., Let's Encrypt only) and self-host the cert

Would let us set CAA to LE only with no auto-injection. Rejected
because self-hosting the cert means abandoning Cloudflare Universal
SSL, which goes against [ADR-0001](0001-dns-host-cloudflare.md). A
future ADR could revisit this if the project leaves Cloudflare.

## Links

- Records as currently observed: `dig +short CAA quantumssh.org @1.1.1.1`
- Cloudflare's documentation on auto-managed CAA records
- RFC 8659 — DNS Certification Authority Authorization
