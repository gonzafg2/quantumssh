# Security Policy

QuantumSSH is cryptographic infrastructure. Security is the project's
primary product. This document explains how to report vulnerabilities,
what you can expect from us in return, and the boundaries of the
embargoed-disclosure process.

## Reporting a vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Send a private report to:

```
security@quantumssh.org
```

> The DNS records for `quantumssh.org` are not yet provisioned at the time
> of writing. Until they are, please send reports to the project lead
> directly (see the maintainer's contact in `GOVERNANCE.md`) and reference
> this file. This notice will be removed once the alias is live.

If you wish to encrypt your report, use the project's PGP key:

```
Primary key fingerprint:    66DB 5100 B070 0E4A E051  971F 9A8D FF06 AFD2 5B24
Encryption subkey:          12A8 BCF0 3709 5A50 06E9  E6F6 4CFE 72E9 E72F A113
UID:                        QuantumSSH Security <security@quantumssh.org>
Algorithm:                  Ed25519 (sign, cert) + Curve25519 (encrypt)
Created:                    2026-05-10
Expires:                    2028-05-09
```

The full ASCII-armored public key is published in this repository at
[`keys/security.asc`](./keys/security.asc). To import it locally and
**verify the fingerprint before trusting it** — never skip this step
on a security-sensitive key:

```sh
# 1. Download (do NOT pipe directly to gpg --import without inspecting).
curl -fsSL -o quantumssh-security.asc \
  https://raw.githubusercontent.com/gonzafg2/quantumssh/main/keys/security.asc

# 2. Verify the fingerprint OFFLINE against the value printed above.
#    Expected primary fingerprint:
#      66DB 5100 B070 0E4A E051  971F 9A8D FF06 AFD2 5B24
gpg --show-keys quantumssh-security.asc

# 3. Only after the fingerprint matches, import.
gpg --import quantumssh-security.asc
```

For extra assurance, cross-check the fingerprint against this README on
`quantumssh.org` (served from a different origin) and against the
project's signed git tags once the first release ships.

If you cannot encrypt your report, plain email is acceptable; do not
delay disclosure waiting on PGP setup.

A useful report typically includes:

- A clear description of the vulnerability and its impact.
- Affected versions, commits, or configurations.
- Steps to reproduce, ideally with a minimal proof of concept.
- Any suggested mitigation or fix, if you have one.
- Whether you intend to publish independently, and your preferred
  attribution (real name, handle, or anonymous).

## What you can expect from us

We commit publicly to the following response targets:

| Milestone                                          | Target                  |
|----------------------------------------------------|-------------------------|
| Acknowledgement of receipt                         | Within 72 business hours |
| Initial assessment and severity triage             | Within 7 days            |
| First patch, mitigation, or substantive update     | Within 14 days           |
| Coordinated disclosure (default embargo period)    | 90 days                  |
| Maximum embargo extension for complex coordination | Up to 120 days           |

If a report falls outside our scope, we will say so explicitly and
quickly, rather than leaving you waiting.

## Coordinated disclosure

The default embargo period is **90 days** from the date of
acknowledgement. The embargo may be extended to up to **120 days** when
coordination with downstream packagers, distributions, or interoperating
projects justifies it. Any extension beyond 90 days will be discussed
with the reporter.

For vulnerabilities that warrant a CVE identifier, we will request one
through MITRE's CVE Numbering Authority program.

We will credit reporters by name (or pseudonym, or anonymously) in the
release notes, the advisory, and the project changelog, unless they
request otherwise.

## Scope

In scope:

- The QuantumSSH server and any first-party crates published from this
  repository.
- Cryptographic protocol logic, key handling, authentication, and
  session management code authored in this repository.
- Configuration parsing, command-line handling, and any exposed control
  surfaces shipped with the server.

Out of scope (please report to the upstream project instead):

- Vulnerabilities in `russh`, `tokio`, `liboqs`, or other third-party
  dependencies. We will of course react to upstream advisories, but
  primary disclosure should be coordinated with the upstream maintainers.
- Issues in operating system kernels, system libraries, or container
  runtimes that QuantumSSH happens to run on.
- Social-engineering, phishing, or physical-access attack scenarios that
  do not exploit a defect in QuantumSSH itself.

## What we do not offer (yet)

- **No bug bounty program.** We do not currently offer monetary rewards
  for vulnerability reports. We hope to introduce one as the project
  matures and funding allows; until then, we will be honest that we
  cannot pay you, and will credit your work generously.
- **No safe-harbor legal commitments beyond good faith.** Fleming Science
  and Technologies SpA will not pursue legal action against researchers
  acting in good faith and in accordance with this policy. We cannot
  speak for third parties whose systems may be involved in your testing.

## Hardening reports and non-vulnerability findings

Reports of weak defaults, configuration footguns, or hardening
opportunities that are not exploitable vulnerabilities are very welcome
as ordinary issues or pull requests. The same goes for documentation
improvements that reduce the chance of users misconfiguring the server.

## Thank you

The people who report vulnerabilities responsibly are doing the project,
and its users, a substantial favour. We take that seriously.
