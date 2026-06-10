# QuantumSSH Threat Model

> **Status:** Substantive. This document supersedes the skeleton committed
> in the initial scaffold. It establishes the project's defensive posture
> as of acceptance and is the authoritative reference for what
> QuantumSSH defends, against whom, under what assumptions, and where
> the boundaries of those defences sit.
>
> **Maintenance:** Substantive changes to this document — additions to or
> removals from the asset list, threat-actor tiers, trust boundaries, in-
> scope attack vectors, or non-goals — go through the RFC process
> ([`docs/rfcs/`](rfcs/README.md)). Typographical and factual corrections may land
> as ordinary documentation pull requests. The intent is the same as the
> ADR errata mechanism in [ADR-0015](adr/0015-permit-annotated-errata-in-adrs.md):
> revisions are visible in git history; structural changes are deliberate.

This document is meant to be read by:

- **Implementers** writing or reviewing protocol, cryptographic, or
  process-isolation code, who need to know which adversaries the code
  must withstand and which it explicitly does not.
- **Auditors** assessing whether QuantumSSH's claims are matched by its
  design and its code.
- **Operators** deciding whether QuantumSSH is appropriate for a given
  deployment, and which complementary controls they need to add.

**Contents.** §1 Scope and posture · §2 Assets · §3 Threat actors · §4 Trust boundaries · §5 Attack vectors · §6 Mitigations · §7 Residual risk · §8 Out of scope · §9 References.

The model is deliberately concrete. Attack vectors are described at a
level of detail that an implementer can use to design tests; mitigations
cross-reference the architectural and operational decisions recorded in
[`docs/adr/`](adr/) and the (forthcoming) RFCs that govern the protocol
and cryptographic layers.

---

## 1. Scope and posture

### 1.1 What this document is

A threat model — an enumeration of the security-relevant things
QuantumSSH protects, the adversaries it expects, the trust boundaries
inside the system, the classes of attack that cross those boundaries,
and the design choices that respond to them. It is not a risk assessment
(no likelihoods or impact ratings are assigned), not a security policy
(no operational controls are mandated), and not a verification claim
(no proof of correctness is asserted).

### 1.2 What QuantumSSH is, for this model

QuantumSSH is a memory-safe, post-quantum-first SSH server, written in
Rust, intended for production use as the listening side of an SSH
session. The default profile (Phase 1–2 target; no Rust code has
landed yet — see the [README roadmap](../README.md#roadmap) for the
current phase) is designed to support:

- Hybrid post-quantum key exchange (`mlkem768x25519-sha256`) — Phase 1.
- Ed25519 host keys (RFC 8709) — Phase 1.
- Public-key user authentication only — Phase 1.
- Single-command execution — Phase 1. Interactive PTY and SFTP — Phase 2.

Port forwarding, X11 forwarding, agent forwarding, and other features
are opt-in, gated behind explicit configuration. The threat model
covers the default profile as the primary subject and notes where opt-
in features extend the attack surface.

This model does **not** cover the QuantumSSH client. A client-side
threat model will be added before any client code lands.

### 1.3 Defensive posture, in one sentence

QuantumSSH defends session confidentiality, integrity, and host
authenticity against adversaries up to and including Very High
capability (NIST SP 800-30 Rev.1, Appendix D), under the
assumption that the host operating system and its administrators are
not themselves the adversary. It does not defend against adversaries
who have already compromised the host kernel, the operator account,
or the user's private key material.

---

## 2. Assets

The assets QuantumSSH protects are organised by what is being protected
about them. Each asset entry names the asset, gives its locations
inside the system, and states which of confidentiality (C), integrity
(I), authenticity (A), and availability (V) are within the protection
goal — and at what strength. Strength is qualified rather than
numerical: *long-term* means "must remain protected for decades against
harvest-now-decrypt-later", *session* means "must remain protected for
the lifetime of an SSH session against an in-line attacker", *channel*
means "must remain protected against tampering between endpoints" (this
document uses *channel* in two senses; SSH-protocol channels in §2.5
onward are always qualified by context).

### 2.1 Session plaintext

**What.** The plaintext of every byte carried inside an SSH session:
command strings, shell input and output, SFTP file content, terminal
escape sequences, and the structure of channel messages.

**Where.** Inside the encrypted SSH transport once a session is
established (RFC 4253); inside server memory while in flight to or from
the channel layer.

**Goal.** Confidentiality (long-term), integrity (channel),
authenticity (channel). Long-term confidentiality is the project's
motivating threat: any session plaintext recorded today must remain
confidential against an adversary holding the ciphertext for decades.

### 2.2 User authentication material

**What.** The fact that a particular user authenticated, the
public-key fingerprints presented during authentication, and any
authentication-protocol metadata that could be used to mount targeted
follow-up attacks. Private keys themselves are *not* QuantumSSH-side
assets — they live with the user — but their public counterparts and
the linkage to a user identity are.

**Where.** The `authorized_keys` configuration source (file or other
backend), the authentication code path (RFC 4252), and the audit
record.

**Goal.** Integrity (long-term — `authorized_keys` integrity is what
authentication is built on), authenticity (channel — clients must be
able to prove key possession; the server must be able to verify it
without learning the private key), confidentiality (modest — the
fact-of-authentication is exposed to the operator by design).

### 2.3 Host key material

**What.** The host's long-term private signing key (Ed25519 by
default), which the server uses to authenticate itself to clients
during the SSH transport handshake.

**Where.** On-disk under operator control, and in process memory while
the server is running.

**Goal.** Confidentiality (long-term — disclosure ends host
authenticity until rotation), integrity (long-term — substitution
enables impersonation), availability (best-effort — loss requires
operator-led rotation but does not directly expose past sessions
provided forward secrecy holds in the key-exchange layer).

### 2.4 Symmetric session keys and KEM secrets

**What.** The ephemeral shared secrets derived from the hybrid key
exchange (`mlkem768x25519-sha256`), the symmetric encryption and
integrity keys derived from them, and the ephemeral KEM private key
material that participates in the exchange.

**Where.** Process memory during the handshake and the active session;
never persisted to disk.

**Goal.** Confidentiality (session, plus a stronger goal: must not be
recoverable after the session ends — forward secrecy), integrity
(session). The combination is what makes harvest-now-decrypt-later
defence work: an adversary who later breaks one of the asymmetric
primitives still must break the other to recover the session key, and
the ephemeral KEM material is gone.

### 2.5 Command execution authority

**What.** The bounded ability to run programs and access files on the
host as the authenticated user, with the privileges that user holds in
the operating system.

**Where.** The session's connection to the host OS — process creation,
PTY allocation, file system access — established after authentication.

**Goal.** Integrity (channel — execution requests must match the
authenticated user's intent, not an attacker's substitution),
authenticity (the user the host believes is executing the command is
the user who authenticated). Confinement *beyond* what the host OS
provides for that user is **not** a QuantumSSH-side goal; see §8.

**Phase-bounded reality.** The authority described above is the
Phase-3 target. During Phase 1 the server runs commands as the OS
identity of the QuantumSSH service account itself, not as the
authenticated user. The Phase-1 posture is documented as a temporary
non-goal in §8.12; per-user UID isolation is part of the
privilege-separation work scheduled for Phase 3 and gated by its own
RFC.

### 2.6 Configuration and policy

**What.** The server's configuration file (TOML), the host key paths,
the authentication backend pointer, listener address and port, feature-
flag settings, and any other operator-controlled policy.

**Where.** Configuration files on disk, environment, command-line
arguments at startup.

**Goal.** Integrity (long-term — configuration tampering is policy
tampering), authenticity (the configuration the server loads must be
the configuration the operator wrote). Confidentiality of
configuration is **not** a primary goal: the operator is trusted, and
configuration secrets (if any) must be referenced rather than
embedded.

### 2.7 Audit record

**What.** The structured log records produced via `tracing`: connection
acceptance, authentication outcomes (success and failure), session
lifecycle events, command-execution boundaries, configuration load,
and protocol errors significant enough to indicate attack. Each
command-execution boundary record includes the *authenticated identity*
(`authenticated_identity` field — the key fingerprint that
authenticated) and the *executing UID* (`executing_uid` field — the
OS-level numeric UID under which the command actually runs) as separate
fields, so that the gap documented in §8.12 is visible to anyone
reviewing server logs.

**Where.** Standard logging sinks under operator control (stderr,
journald, files, log shippers).

**Goal.** Integrity at emission (records emitted by the server must
reflect what actually happened) plus a one-way emission path to a sink
the attacker cannot reach from inside the server process; long-term
integrity belongs to the sink and is not the server's goal.
Authenticity (records must be attributable to the server, not
forgeable from inside the session). Availability (modest — the system
continues to function if the log sink fails, with operator-visible
degradation).

### 2.8 Service availability

**What.** The server's ability to accept and serve well-formed
sessions for the operator's intended user population.

**Where.** The listener socket, the connection-accept loop, the
session machinery.

**Goal.** Availability (best-effort, *not* DoS-resistant). QuantumSSH
applies basic resource discipline (handshake budgets, per-connection
limits) but is explicitly **not** a DoS-defence layer; that
responsibility belongs to the operating environment. See §8.

---

## 3. Threat actors

### 3.1 Framework

Threat-actor capability is described using the qualitative scale of
NIST SP 800-30 Rev.1, Appendix D, Table D-3. The scale's five levels
are, verbatim:

| Level | Capability |
|---|---|
| Very High | Very sophisticated expertise, well-resourced, generates opportunities for multiple successful, continuous, and coordinated attacks. |
| High | Sophisticated expertise, significant resources, multiple successful coordinated attacks. |
| Moderate | Moderate resources, expertise, and opportunities for multiple successful attacks. |
| Low | Limited resources, expertise, and opportunities for a successful attack. |
| Very Low | Very limited resources, expertise, and opportunities for a successful attack. |

> **Terminology note.** NIST SP 800-30 Rev.1 does **not** use the
> "Tier I–V" labels that some secondary literature applies to this
> scale; the "Tier" terminology in Appendix D refers to the
> *organisational* tiers (Tier 1 / 2 / 3) defined in SP 800-39, which
> are unrelated to adversary capability. This document uses NIST's
> own qualitative labels (Very Low → Very High) to avoid the
> confusion.

The companion scales for intent (Table D-4) and targeting (Table D-5)
are referenced where they materially distinguish one actor from
another.

Where a particular technique aligns with a MITRE ATT&CK Enterprise
technique, the technique ID is cited (e.g. `T1190`). ATT&CK IDs are
informative cross-references, not normative classification.

### 3.2 In-scope actors

The actors below define the **upper bound** of capability QuantumSSH's
design responds to. The most consequential one for the project's
architecture is the Very-High harvest-now-decrypt-later adversary;
everything else inherits the protections built for that case.

#### 3.2.1 Opportunistic remote attacker (Very Low – Low)

**Capability.** Limited resources and expertise; uses publicly
available tooling; opportunistic scanning of internet-reachable
addresses.

**Intent.** Disrupt or deface without concern for detection
(Table D-4, Very Low). Credential harvesting at scale.

**Targeting.** "May or may not target any specific organisations"
(Table D-5, Very Low). Targets are the population of reachable
sshd-style listeners.

**Typical techniques.** Internet-wide port scanning;
password-guessing and credential-stuffing against any
authentication backend that accepts passwords (`T1110.001`,
`T1110.004`); attempting known-vulnerable CVE chains against
fingerprinted server versions (`T1190`).

**Implication for design.** Defaults must close these vectors
without operator action: no password authentication, no exposure of
detailed server-version banners, no debug verbosity to the wire.

#### 3.2.2 Authenticated peer (Low – Moderate)

**Capability.** Holds a valid public-key credential for the host.
May be a benign user with an accident or a malicious tenant in a
shared environment.

**Intent.** Range from accidental misuse to deliberate lateral
movement; in the malicious case, "obtain critical or sensitive
information … by establishing a foothold" (Table D-4, Moderate).

**Targeting.** Knows specifics of the host they have access to
(Table D-5, Moderate or higher).

**Typical techniques.** Session-channel abuse and protocol
misbehaviour after auth; misuse of forwarding features if enabled
(`T1572` protocol tunneling, `T1090` SOCKS proxy via `ssh -D`);
ssh-agent hijacking against forwarded agents (`T1563.001`);
attempting privilege escalation through interaction with the host
shell.

**Implication for design.** Authentication grants access to the
authenticated user's authority on the host and nothing more.
Forwarding features must be opt-in, off by default, and bounded
when on.

#### 3.2.3 Network-positioned adversary (Moderate – High)

**Capability.** Can observe or modify packets between the client
and the server. May hold a position on the path (ISP, transit
network, on-premises switch), may have transient access through
ARP or DHCP manipulation (`T1557.002`, `T1557.003`) or evil-twin
wireless (`T1557.004`), may operate a TLS-terminating middlebox the
operator did not consent to.

**Intent.** Capture sessions for analysis (Table D-4, Moderate or
High), or impersonate the server to compromise clients.

**Targeting.** Persistent against high-value targets
(Table D-5, High).

**Typical techniques.** Passive sniffing (`T1040`) — defeated by
the transport encryption; active KEX downgrade attempts — defeated
by the algorithm-negotiation MAC binding; substitution of the host
key during the handshake — defeated by client-side host-key
verification when correctly used; transport replay — defeated by
sequence-number authentication; traffic analysis (timing,
keystroke-length leakage) — partially defeated, see §6.

**Implication for design.** The transport must assume a hostile
channel. Algorithm negotiation must be authenticated, host
identity must be cryptographically demonstrated by the server, and
no in-band fallback to weaker primitives may exist.

#### 3.2.4 Targeted intruder (High)

**Capability.** "Sophisticated level of expertise, significant
resources" (Table D-3, High). A funded criminal group, a red team
operating against a defined target, or a state-affiliated actor
operating below the threshold of supply-chain or implant
operations.

**Intent.** Establish a foothold while "very concerned about
minimising detection" (Table D-4, High).

**Targeting.** Persistent against a specific organisation, focuses
on "high-value resources and specific employees" (Table D-5, High).

**Typical techniques.** Pre-authentication parser exploitation
against complex protocol fields (`T1190`), credential abuse of
exposed `~/.ssh` private keys recovered from compromised user
endpoints (`T1552.004`, `T1078`), `authorized_keys` injection on
hosts where another path to the file system already exists
(`T1098.004`), session hijack via ssh-agent socket replay if
forwarding is enabled (`T1563.001`, `T1550`), tampering with the
audit channel to obscure the intrusion (`T1685.004`, `T1685.006`).

**Implication for design.** The pre-authentication parser must be
the smallest possible attack surface, with no `unsafe` Rust in the
default profile. Logging must be a one-way path to a sink the
attacker cannot reach from inside the server process. Every
post-authentication action must be attributable to the
authenticated user.

#### 3.2.5 Nation-state with HNDL capability (Very High)

**Capability.** "Very sophisticated level of expertise,
well-resourced" (Table D-3, Very High). Can operate signals
intelligence collection at internet scale, fund original
cryptanalysis, mount supply-chain operations against open-source
infrastructure, and hold ciphertext for decades pending future
decryption capability.

**Intent.** "Undermine, severely impede, or destroy a core
mission or business function … by exploiting a presence in the
organisation's information systems" (Table D-4, Very High).

**Targeting.** Persistent, multi-vector, multi-year against
specific targets including supply chains and supporting personnel
(Table D-5, Very High).

**Typical techniques.** Bulk recording of encrypted SSH sessions
(`T1040`-class, at scale) for later cryptanalysis; original work
on quantum cryptanalysis or implementation cryptanalysis; supply-
chain compromise of dependencies in the build pipeline
(`T1195.002` — illustrated by the 2024 `xz-utils` operation, which
targeted OpenSSH's authentication path through a compression
dependency); attempts to influence standards, defaults, or
upstream maintainers; targeted parser exploitation
pre-authentication (`T1190`); long-lived implants in the
maintainer's development environment.

**Implication for design.** The post-quantum-by-default key
exchange is precisely the response to the harvest-now-decrypt-
later component of this threat. Supply-chain risk is addressed by
the project's signed-commits and signed-tags posture (see
ADR-0006) and by dependency-discipline controls (`deny.toml`
enforced in CI; see §5.5.2 and §6.4); reproducibility and
bill-of-materials are on the Phase 3 roadmap.

The HNDL adversary is "Very High" with respect to capability, but
*nothing* about QuantumSSH's defence requires the adversary to be a
nation-state in practice. Bulk passive recording of ciphertext is
cheap; the cryptanalytic capability that decrypts it later is the
expensive part. The asymmetry is what motivates the project's
default.

### 3.3 Non-adversarial threat sources

NIST SP 800-30 Rev.1 distinguishes adversarial threat sources from
three non-adversarial categories (Table D-6, Range of Effects). They
are noted here for completeness:

- **Accidental.** Operator misconfiguration, fat-finger errors,
  inadvertent exposure. Mitigated by configuration validation and
  defaults that fail closed.
- **Structural.** Bugs in QuantumSSH itself, in `russh`, or in any
  upstream cryptographic library. Mitigated by Rust's memory-safety
  guarantees, by minimising the surface, by the Phase 3 audit, and
  by continuous fuzzing.
- **Environmental.** Host kernel failures, hardware faults, power
  loss, RNG corruption. Mitigated by relying on OS-provided
  randomness with no fallback, and by accepting that hardware-level
  defences are out of scope.

---

## 4. Trust boundaries

A trust boundary is a place where data, code, or authority crosses
between regions of differing trust. The boundaries below are where
QuantumSSH's security argument changes hands. They are described in
terms of what crosses, what is trusted on each side, and what the
boundary enforces.

### 4.1 Network boundary — wire ↔ process

**Where.** The TCP socket between the listening server and a
remote endpoint, in particular the bytes received before any
authentication has occurred.

**Trusted on the wire side.** Nothing. The peer is anonymous,
potentially adversarial, potentially in-line on the network path.

**Trusted on the process side.** That the protocol parser, the
algorithm negotiator, and the key-exchange code reject malformed
or hostile input without state corruption, without memory unsafety,
and without escalating the peer's authority.

**What the boundary enforces.** That bytes from the wire never
reach a privileged code path or a destination file system before
authentication completes; that algorithm negotiation produces a
hybrid post-quantum KEX or fails closed; that no degradation to a
weaker primitive is possible by attacker choice.

### 4.2 Process boundary — server ↔ host OS

**Where.** Every system call, every file descriptor obtained, every
process spawned, every PTY allocated.

**Trusted on the server side.** That the server's process owner is
the user the operator intended. That the file system permissions
on host key material, on `authorized_keys`, and on configuration
files are correct.

**Trusted on the host side.** That the kernel enforces process
isolation, file permissions, and PTY ownership; that the network
stack delivers packets to the configured listener and only to it.

**What the boundary enforces.** That the QuantumSSH process
operates entirely within the privilege envelope the OS has granted
it; that no QuantumSSH-side mechanism *expands* that envelope.
Confinement of *the authenticated user* is the OS's job; QuantumSSH
will not implement its own sandboxing layer over what the OS
provides.

### 4.3 Key-material boundary — disk ↔ memory

**Where.** The point at which the host private key is read from
disk into process memory, and the point at which session-derived
symmetric keys come into existence inside process memory.

**Trusted on the disk side.** That file permissions are correct
and the operator did not store the key in a location the
filesystem cannot protect.

**Trusted on the memory side.** That key material is kept in
memory only for as long as it is needed, and is zeroised on a
best-effort basis via the `zeroize` crate after use (the guarantee
is bounded by what the compiler does not reorder). Operators who
require memory-confidentiality against an attacker with paging-
file access must additionally configure `mlockall`/equivalent or
disable swap at the host; the server itself cannot unilaterally
prevent paging on every supported OS. Key material is not exposed
through error messages or panic output.

**What the boundary enforces.** That host private keys never leave
the process by any path other than the cryptographic operations
that legitimately use them; that session keys never persist beyond
the session.

### 4.4 Configuration boundary — operator ↔ runtime

**Where.** The TOML configuration file loaded at startup, the
command-line arguments, and the environment.

**Trusted on the operator side.** That the operator-authored
configuration expresses the operator's intent. That the
configuration file's filesystem permissions exclude unauthorised
writers.

**Trusted on the runtime side.** That the parsed configuration is
the configuration the operator wrote; that defaults applied to
unspecified options are the documented defaults; that no
configuration option weakens the cryptographic profile of the
default below what the project's design admits.

**What the boundary enforces.** That an operator who follows the
documentation gets the secure default. That any configuration
that would lower the security floor is either impossible to
express or is required to be explicit, named, and warned about in
the audit record at startup.

### 4.5 Operator ↔ user boundary — administrative vs interactive authority

**Where.** The conceptual line between the operator (the human or
automation that owns the host and runs QuantumSSH) and the
authenticated user (the human or automation that connects through
QuantumSSH to do work on the host).

**Trusted on the operator side.** That the operator has chosen
the user population, the authentication policy, the audit
disposition, and the feature flag set. The operator is not the
adversary; if they were, QuantumSSH is moot.

**Trusted on the user side.** Only what their authentication
demonstrates: that they hold the private key corresponding to a
public key the operator has listed. Nothing more.

**What the boundary enforces.** That the operator's
configurational authority does not flow into the user's
interactive authority, and vice versa: the user cannot reconfigure
the server through the session, and the operator's configuration
choices do not silently raise the user's privileges beyond what
their OS account holds.

---

## 5. Attack vectors

This section enumerates the classes of attack the design considers in
scope and describes, for each, the mechanism, the assets it targets,
the actors who realise it, the ATT&CK reference where one applies, and
a concrete handle an implementer can use to design a test.

The grouping follows the conceptual phases of an SSH session
(connection, key exchange, authentication, session, lifecycle) rather
than the MITRE ATT&CK tactic structure, because the design questions
QuantumSSH must answer are phase-shaped. Cross-references to ATT&CK
tactics are noted in each subsection header.

### 5.1 Pre-handshake (transport-layer reachability)

ATT&CK tactic alignment: Reconnaissance, Resource Development,
Initial Access.

#### 5.1.1 Banner and version fingerprinting

**Mechanism.** An attacker opens a TCP connection and reads the
SSH protocol version exchange banner (RFC 4253 §4.2). Detailed
version strings let the attacker target known-vulnerable releases.

**Assets at risk.** Session plaintext (via downstream exploitation),
service availability (via targeted CVE chains).

**Actors.** Opportunistic remote attacker, targeted intruder.

**ATT&CK reference.** `T1190` (Exploit Public-Facing Application)
in its preparation phase.

**Test handle.** Banner emitted to anonymous peer must convey only
what RFC 4253 §4.2 requires: protocol version, comma-separated
software-version string. The software-version string must not
include a build-system minor-release identifier or operator-
provided metadata in the default configuration.

#### 5.1.2 Pre-authentication parser exploitation

**Mechanism.** An attacker sends malformed or boundary-stretching
binary packets — oversized lengths, recursive structures, malformed
multiple-precision integers, malformed name-lists — aimed at
triggering memory unsafety, integer overflow, or panic-induced
denial of service in the parser.

**Assets at risk.** Process-level confidentiality and integrity
(memory disclosure or arbitrary code execution); service
availability (panic loop).

**Actors.** Targeted intruder, nation-state.

**ATT&CK reference.** `T1190` (Exploit Public-Facing Application).

**Test handle.** Pre-authentication parsing must be exercised by a
fuzzer (`cargo-fuzz`, OSS-Fuzz) with corpora derived from the
RFC 4253 binary packet grammar. No path that observes attacker-
chosen length fields may allocate without an explicit bound. No
`unsafe` Rust is permitted in the pre-authentication path; any
exception requires an RFC.

#### 5.1.3 Connection exhaustion and slowloris

**Mechanism.** An attacker holds open many TCP connections without
completing the handshake, exhausting per-process file descriptor
limits or per-connection memory.

**Assets at risk.** Service availability.

**Actors.** Opportunistic remote attacker upward.

**ATT&CK reference.** No specific ATT&CK technique; addressed at
the network layer in defender taxonomies.

**Test handle.** Per-source connection rate limits, total
concurrent half-open connection caps, and handshake-completion
deadlines must be configurable; the defaults must be documented
and the test suite must include a slow-handshake scenario. See §8
on the explicit limits of QuantumSSH's DoS posture.

### 5.2 Key exchange

ATT&CK tactic alignment: Credential Access, Adversary-in-the-Middle.

#### 5.2.1 Passive recording for future cryptanalysis (HNDL)

**Mechanism.** A network-positioned adversary records the full
encrypted SSH transport, stores it, and later applies improved
classical cryptanalysis or a cryptographically relevant quantum
computer (CRQC) to recover the session key from the recorded
asymmetric key-exchange material, then decrypts the session.

**Assets at risk.** Session plaintext (long-term confidentiality),
user-typed authentication material visible inside the session.

**Actors.** Nation-state (Very High) is the canonical realiser;
the *recording* part of the attack is cheap and within reach of
lower tiers.

**ATT&CK reference.** `T1040` (Network Sniffing) covers the
recording side; the cryptanalytic side has no specific ATT&CK
technique because ATT&CK assumes a defender-relevant time horizon.

**Test handle.** The default key exchange must be
`mlkem768x25519-sha256` (per `draft-ietf-sshm-mlkem-hybrid-kex`).
Algorithm negotiation must not permit any non-hybrid post-quantum
or non-post-quantum-only exchange in the default profile. Both
halves of the hybrid must contribute to the derived key; failure
of either half must abort the connection, not silently fall back
to the surviving half.

#### 5.2.2 Algorithm downgrade

**Mechanism.** An on-path attacker rewrites the algorithm-
negotiation `SSH_MSG_KEXINIT` to remove the post-quantum exchange
from the offer, forcing both sides to a weaker primitive both
nominally support.

**Assets at risk.** Session plaintext (collapsed to classical
strength against future CRQC).

**Actors.** Network-positioned adversary and upward.

**ATT&CK reference.** `T1557` (Adversary-in-the-Middle), generic
form.

**Test handle.** The negotiation MAC must bind the agreed
algorithm list to the derived session key. A test must verify
that mutating the `KEXINIT` of either party causes the handshake
to abort. Algorithm-name binding alone is insufficient
post-CVE-2023-48795 (Terrapin): a prefix-truncation attack on the
binary packet protocol manipulates sequence numbers across the
NEWKEYS boundary despite a correct KEXINIT MAC. The hardening is
the strict-kex extension (`kex-strict-c-v00@openssh.com` /
`kex-strict-s-v00@openssh.com`), which the server must offer and
require by default in the in-scope profile; test cases must
verify that a peer omitting strict-kex is rejected when the
operator has not opted into legacy-client mode. The server must
refuse offers that do not include the default hybrid PQ method.

#### 5.2.3 Host-key substitution

**Mechanism.** An on-path attacker presents a host key of their
choosing to a connecting client, hoping the client's
known-hosts state is empty or that the user dismisses the
warning.

**Assets at risk.** Session plaintext, user authentication
material exchanged inside the session.

**Actors.** Network-positioned adversary and upward.

**ATT&CK reference.** `T1557`.

**Test handle.** This vector is fundamentally client-side.
QuantumSSH's server-side responsibility is to make
authentication-by-host-key cleanly anchorable: expose the
host-key fingerprint in operationally usable forms so the
operator can publish it. SSHFP records under a DNSSEC-signed
zone are one such form; the publication itself and the DNSSEC
operation are the operator's responsibility, not the server's.
The default must use Ed25519, whose fingerprint is compact
enough for out-of-band verification.

#### 5.2.4 Key-derivation flaw

**Mechanism.** Implementation bugs in the KDF (typo, wrong
context string, missing input, byte-order error) cause derived
session keys to be predictable, reused, or correlated across
sessions.

**Assets at risk.** Session plaintext.

**Actors.** Any actor able to observe the resulting weakness.

**ATT&CK reference.** No specific ATT&CK technique; this is an
implementation-cryptanalysis vector.

**Test handle.** The current `draft-ietf-sshm-mlkem-hybrid-kex`
(version -10, 26 February 2026) does not itself publish
hybrid-combiner test vectors; the substitute is layered.
Component-level vectors must be reproduced byte-for-byte: NIST
ACVP-Server vectors for the ML-KEM-768 half
(`gen-val/json-files/ML-KEM-keyGen-FIPS203` and
`ML-KEM-encapDecap-FIPS203`) and RFC 7748 §6.1 vectors for the
X25519 half. Hybrid-combiner output (`K = HASH(K_PQ || K_CL)`)
and the SSH-level exchange hash `H` must be testable against
fixed inputs; internally-captured golden vectors against an
OpenSSH 10.x peer using a fixed-RNG test profile (analogous
to OpenSSH's `TEST_SSH_FIXED_KEX_SEED`) close the gap until the
IETF draft adopts an appendix of canonical vectors.

### 5.3 Authentication

ATT&CK tactic alignment: Credential Access, Initial Access.

#### 5.3.1 Online credential guessing

**Mechanism.** An attacker attempts authentication repeatedly,
either against a single user or sprayed across many.

**Assets at risk.** Command execution authority (and through it,
the assets the user has on the host).

**Actors.** Opportunistic remote attacker upward.

**ATT&CK reference.** `T1110.001` (Password Guessing),
`T1110.004` (Credential Stuffing); not applicable to public-key
auth in the cryptographic sense, but applicable as a denial
mechanism.

**Test handle.** Password authentication is **not** offered in
the default profile. Public-key authentication does not benefit
the attacker from repetition: either the attacker holds the
private key or they do not. Authentication-failure events must be
rate-limited per source. The per-target-user dimension is
deliberately omitted: on a public-key-only server, per-user
counters create a user-enumeration oracle, where the attacker
would learn which usernames exist by observing whether their
counter advances. Failures are recorded in the audit channel
with deduplication metadata.

#### 5.3.2 Stolen private key (off-host compromise)

**Mechanism.** An attacker compromises a user's endpoint and
exfiltrates their SSH private key (`~/.ssh/id_*`), then uses it
to authenticate against the host.

**Assets at risk.** Command execution authority on every host
that trusts the stolen key.

**Actors.** Targeted intruder upward.

**ATT&CK reference.** `T1552.004` (Unsecured Credentials: Private
Keys), `T1078` (Valid Accounts).

**Test handle.** This is *not* defeatable from inside QuantumSSH
once the key is in the attacker's hands: from the server's
viewpoint, the attacker is the legitimate user. QuantumSSH's
contribution is to make compensating controls discoverable —
short-lived certificates (a Phase 2 feature behind RFC), audit-
record fidelity, and configurable per-key restrictions
(`from=`, `command=`, `no-port-forwarding`, equivalents in
QuantumSSH's own syntax) — but the primary defence lives in the
user's endpoint hygiene.

#### 5.3.3 `authorized_keys` injection

**Mechanism.** An attacker who has acquired write access to the
`authorized_keys` source (file or backend) adds a key they
control. From then on, the attacker authenticates as the user
whose `authorized_keys` was tampered with.

**Assets at risk.** Persistence on the host.

**Actors.** Targeted intruder, nation-state.

**ATT&CK reference.** `T1098.004` (Account Manipulation: SSH
Authorized Keys).

**Test handle.** QuantumSSH does not write to the
`authorized_keys` source under any circumstance — it only reads.
The configuration must permit operators to choose backends that
make injection visible (file with audit-logged
opens, signed-key authorities, certificate-based authentication
with revocation). Authentication events must record the *key
fingerprint* that authenticated, not just the username, to
support post-hoc detection of unfamiliar keys.

#### 5.3.4 Authentication-process tampering

**Mechanism.** An attacker who has reached the host file system
modifies QuantumSSH's binary, replaces its configuration, or
modifies its authentication backend (e.g., PAM module if PAM is
ever integrated) to admit themselves.

**Assets at risk.** All assets on the host.

**Actors.** Targeted intruder upward.

**ATT&CK reference.** `T1556` (Modify Authentication Process),
sub-techniques as applicable; `T1554` (Compromise Host Software
Binary).

**Disposition.** This vector is **out of scope** for QuantumSSH-
side defence — by the time it applies, the attacker already has
the privileges the defence would need to act on. The project's
contribution is upstream: signed releases, reproducible builds
(Phase 3), and ADRs (ADR-0006) that document the signing posture
the operator's verification can rely on.

### 5.4 Session and channel layer

ATT&CK tactic alignment: Execution, Persistence, Lateral Movement,
Collection, Command and Control.

#### 5.4.1 Session hijacking via ssh-agent forwarding

**Mechanism.** A user enables agent forwarding when connecting to
a host. A malicious user (or compromised root) on that host
connects to the user's forwarded `SSH_AUTH_SOCK` and uses it to
authenticate to third hosts.

**Assets at risk.** Command execution authority on every host the
user's key opens.

**Actors.** Authenticated peer (Moderate) upward.

**ATT&CK reference.** `T1563.001` (SSH Hijacking via agent
socket), `T1550` (Use Alternate Authentication Material).

**Test handle.** Agent forwarding is **off by default** and
behind an explicit feature flag. When enabled, sessions must be
loggable as having opted in; per-key configuration must allow
operators to forbid agent forwarding for keys that should never
have it.

#### 5.4.2 Command injection across forwarding

**Mechanism.** Port forwarding (local or remote) carries TCP
streams that the client picked. An authenticated user with
forwarding enabled can reach internal services from the server's
network perspective; an adversary who has compromised an
authenticated account inherits the same reach.

**Assets at risk.** Network confidentiality of services adjacent
to the host.

**Actors.** Authenticated peer upward.

**ATT&CK reference.** `T1572` (Protocol Tunneling), `T1090`
(Proxy).

**Test handle.** Port forwarding (local, remote, dynamic) is
**off by default** and behind explicit feature flags. Per-user
and per-key restrictions must be supported. Allowed-destination
lists must be expressible without an external policy engine.

#### 5.4.3 PTY misuse and terminal-escape injection

**Mechanism.** A user with a PTY can write bytes whose terminal-
escape semantics affect the operator-side terminal of any tool
that consumes the audit log naively (e.g., a `cat` of a log file
that included raw session output).

**Assets at risk.** Operator-side trust in the audit channel.

**Actors.** Authenticated peer upward.

**ATT&CK reference.** No specific ATT&CK technique; addressed in
defender taxonomies as log-injection.

**Test handle.** Session content is **not** recorded in the
audit channel by QuantumSSH; only event metadata is recorded. If
session recording is ever added as an opt-in (post-Phase 2 RFC),
escape-sequence-safe encoding is a precondition for the RFC's
acceptance.

#### 5.4.4 Exfiltration over the SSH channel

**Mechanism.** An authenticated attacker uses the SSH session
itself — through interactive output, SFTP, or forwarded streams —
to exfiltrate data they have legitimate read access to.

**Assets at risk.** None that QuantumSSH was protecting; the user
already had legitimate read access by hypothesis.

**Actors.** Authenticated peer upward.

**ATT&CK reference.** `T1041` (Exfil over C2 channel), `T1071`
(Application Layer Protocol), `T1573` (Encrypted Channel).

**Disposition.** This is **out of scope** for QuantumSSH-side
defence; access control to data the user can read is the host's
job. The QuantumSSH contribution is logging fidelity — a session
recorded as having opened an SFTP subsystem, transferred N
bytes, and closed it, even if the *content* of the transfer is
not recorded.

### 5.5 Server lifecycle and operations

ATT&CK tactic alignment: Persistence, Defense Evasion.

#### 5.5.1 Audit-log tampering on the host

**Mechanism.** An attacker who has reached the host's audit sink
(file, journald, log shipper) edits records to remove their
intrusion.

**Assets at risk.** Audit record integrity.

**Actors.** Targeted intruder upward.

**ATT&CK reference.** `T1685.004` (Disable or Modify Linux Audit
System Log), `T1685.006` (Clear Linux or Mac System Logs). These
identifiers reflect the v19 (April 2026) reorganisation of
ATT&CK's defence-evasion mappings; older mappings (`T1070.002`,
`T1562.006`) are now consolidated under `T1685`.

**Test handle.** QuantumSSH must support emitting structured
records (JSON) suitable for one-way shipment to an external sink
the attacker cannot reach from inside the server's process or
host. Format stability of the log schema is part of the public
interface from Phase 2 onward, so log-shipping configurations do
not silently break.

#### 5.5.2 Supply-chain compromise of dependencies

**Mechanism.** A dependency in QuantumSSH's build pipeline is
backdoored upstream — by maintainer compromise, by registry
attack, or by social-engineering as in the 2024 `xz-utils`
operation (CVE-2024-3094), which targeted OpenSSH's authentication
path through a compression dependency.

**Assets at risk.** Every asset, because the attacker now runs
inside the server process.

**Actors.** Nation-state (Very High) is the realistic actor at
the maintainer-compromise scale; lower tiers realise registry-
attack variants.

**ATT&CK reference.** `T1195.002` (Supply Chain Compromise:
Compromise Software Supply Chain). The 2024 `xz-utils` incident
is not at present documented as a procedure example under
`T1195.002`; the primary public references are Red Hat
RHSB-2024-001 and the NIST NVD entry for CVE-2024-3094.

**Test handle.** Dependency discipline is recorded in
`deny.toml`; the `cargo deny` invocation runs in CI; the
project's signed-tag posture is recorded in ADR-0006. Phase 3
introduces reproducible builds and a published software bill of
materials, both of which are RFC-gated.

#### 5.5.3 Host private key compromise

**Mechanism.** The host's private key is read off disk by an
attacker who has reached the host file system, or extracted from
process memory by an attacker who has reached the running
process.

**Assets at risk.** Host authenticity for every client that has
ever cached this key.

**Actors.** Targeted intruder upward.

**ATT&CK reference.** No specific ATT&CK technique; addressed as
a credential-access pattern with host-key semantics.

**Test handle.** Forward secrecy in the key-exchange layer
ensures that compromise of the host private key does **not**
expose past session plaintexts. This guarantee depends on the
ephemeral KEM material having been destroyed after the session
(see §2.4) and on the host key not being used in the key
exchange in a way that leaks the ephemeral. Operators must have
a documented rotation procedure (Phase 2). The server must
refuse to start if host-key file permissions are world-readable
in the default configuration.

#### 5.5.4 Operator-account compromise

**Mechanism.** The operator's account on the host (the account
under which QuantumSSH runs or whose authority configures it) is
compromised. The attacker rewrites configuration, replaces host
keys, modifies `authorized_keys`, edits logs, or starts a
replacement binary.

**Assets at risk.** All host assets.

**Actors.** Targeted intruder upward.

**ATT&CK reference.** `T1078` (Valid Accounts).

**Disposition.** **Out of scope.** The operator is, by the
project's posture, not the adversary. Operators concerned about
self-defence against operator-account compromise must look to
host-level controls (privileged-access workstations, MFA on
operator login, immutable infrastructure, log shipping to
external systems) — none of which QuantumSSH attempts to
replace.

---

## 6. Mitigations

This section summarises, by category, the design choices that respond
to the attack vectors above. Each item cross-references the
authoritative record — the ADR or the (future) RFC — rather than
repeating it.

### 6.1 Cryptographic posture

- **Hybrid post-quantum key exchange by default.**
  `mlkem768x25519-sha256` from `draft-ietf-sshm-mlkem-hybrid-kex` is
  the only key exchange offered in the default profile. Failure of
  either half aborts the handshake; there is no silent fallback.
  Defends §5.2.1, §5.2.2.
- **Ed25519 host keys.** RFC 8709. Compact fingerprints, modern
  curve, no parameter-choice attack surface. Defends §5.2.3.
- **Forward secrecy.** Ephemeral KEM secrets are not persisted and
  are zeroised after derivation. Defends §5.5.3.
- **Negotiation MAC binding.** The agreed algorithm list is bound
  into the derived session key (RFC 4253 §7), preventing
  silent downgrade. Defends §5.2.2.
- **Strict KEX (Terrapin defence).**
  `kex-strict-{c,s}-v00@openssh.com` is advertised and required
  by default; peers that fail to negotiate strict-kex are
  rejected in the default profile. Sequence numbers are reset on
  the strict-kex boundary, closing the CVE-2023-48795
  prefix-truncation vector that algorithm-name binding alone does
  not address. Defends §5.2.2.
- **No legacy primitives.** No SSH-1, no RSA-1024, no DSA, no CBC
  modes, no `diffie-hellman-group1-sha1`, no
  `diffie-hellman-group14-sha1`, no `ssh-rsa` (SHA-1-signed RSA
  host keys per RFC 9142 §4). Aligned with RFC 9142's MUST-NOT
  and SHOULD-NOT lists for new deployments.

### 6.2 Implementation posture

- **Memory safety as a primary defence.** Rust with the borrow
  checker, no `unsafe` in the pre-authentication code path in the
  default profile. Defends §5.1.2.
- **Smallest plausible attack surface.** The MVP target is pubkey
  auth (Phase 1), command execution (Phase 1), PTY and SFTP
  (Phase 2). Everything else is opt-in behind a feature flag.
  Defends §5.4 generally.
- **Fuzzing as a Phase-3 deliverable.** `cargo-fuzz` and OSS-Fuzz
  integration are committed in the roadmap; corpora derived from the
  RFC 4253 binary packet grammar are the starting target. Defends
  §5.1.2.
- **Audit log shape stable from Phase 2.** Structured records via
  `tracing`, JSON-emittable, schema-versioned. Defends §5.5.1.

### 6.3 Authentication posture

- **Public-key only in the default profile.** Defends §5.3.1.
- **Authentication-event records include key fingerprint.** Defends
  §5.3.3 post-hoc detection.
- **No `authorized_keys` writes from the server.** Defends §5.3.3
  in-band.
- **Per-key restrictions.** `from=`, `command=`, forwarding
  restrictions expressible in configuration. Defends §5.4.1, §5.4.2
  selectively.

### 6.4 Operational posture (project-side)

- **Signed releases and signed commits on `main`.** Recorded in
  ADR-0006. Defends §5.5.2 partially.
- **Dependency discipline.** `deny.toml` enforced in CI; reviewed in
  PRs. Defends §5.5.2 partially.
- **Reproducible builds and SBOM** are Phase-3 RFC-gated
  deliverables. Will defend §5.5.2 fully.
- **Branch protection on `main`.** Recorded in ADR-0008. Defends the
  authoritative source against single-actor compromise of the
  repository.

### 6.5 Documentation as defence

A protocol implementation that no operator understands cannot be
operated safely. QuantumSSH treats the threat model, the ADR catalog,
the operations runbook ([`docs/operations.md`](operations.md)), and the
infrastructure overview ([`docs/infrastructure.md`](infrastructure.md))
as load-bearing artifacts, not afterthoughts. The verification recipes
in `operations.md` exist so that an operator can confirm the security
claims against the running system, not against this document.

---

## 7. Residual risk

Even with the mitigations above, QuantumSSH leaves residual risk that
operators must account for. The principal items, by category, are:

- **Compromise of the user's endpoint or private key** (§5.3.2)
  remains the dominant lateral-movement risk and is not addressable
  server-side; certificate-based authentication and short-lived
  credentials, both Phase-2 RFC items, narrow the window but do not
  close it.
- **Compromise of the host or operator account** (§5.5.4, §8.1)
  defeats QuantumSSH by hypothesis; host-level controls are the
  operator's responsibility.
- **Cryptographic primitives might be broken** (ML-KEM, X25519,
  Ed25519, AES-GCM, ChaCha20-Poly1305, SHA-2 family). The hybrid
  posture means *both* asymmetric primitives must fall for the
  asymmetric handshake to fail; the symmetric primitives are
  conservative and well-studied. The project commits to following
  NIST and IETF guidance on primitive deprecation and to surfacing
  upgrades as RFCs.
- **Implementation flaws not caught by review, tests, or fuzzing.**
  The Phase-3 security audit is the principal compensating control;
  the project's posture is that bugs will exist and the goal is to
  find them before adversaries do.
- **Traffic analysis** (packet timing, packet sizes, keystroke
  cadence). Padding and timing defences are an active research area;
  QuantumSSH inherits whatever the underlying transport library
  offers and does not at this stage promise resistance to a
  sophisticated traffic-analysis adversary.

The intent of listing residual risk explicitly is the same intent
behind §8: an operator who deploys QuantumSSH should know what they
are still on the hook for.

---

## 8. Out of scope

The threats below are explicitly **not** what QuantumSSH attempts to
defend against. Each is listed with a short rationale, so that an
operator can recognise the gap and choose a complementary control.
Being explicit here is as important as being explicit about goals:
silence implies a coverage that does not exist.

### 8.1 Compromise of the host kernel or operator account

If the OS kernel is malicious, or if the operator's privileged
account is in adversary hands, QuantumSSH is downstream of the
compromise. The host owns the file system the host key lives on,
the process memory the session key lives in, and the system calls
the server uses. Defending an SSH server against its own host is
not a tractable goal and not one this project pursues.

### 8.2 Compromise of the user's client endpoint or private key

When the attacker holds the user's private key, the server cannot
distinguish them from the user. Compensating controls
(certificate-based authentication with short lifetimes, per-key
restrictions, hardware-bound credentials) narrow the window; the
primary defence is the user's endpoint hygiene, which is outside
this project.

### 8.3 Denial of service as a primary objective

QuantumSSH applies basic resource discipline (handshake budgets,
per-connection limits, configurable rate limits) but is not a DoS-
defence layer. Volumetric attacks, distributed exhaustion, and
amplification are addressed at the network layer and by upstream
operational tooling.

### 8.4 Covert channels

RFC 4251 §9 already states that the SSH protocol "was not designed
to eliminate covert channels". QuantumSSH inherits that posture: a
user with a legitimate session can encode information in timing,
packet sizes, output patterns, or PTY content. Defending against
that is a domain-specific problem (data-loss prevention, behavioural
analytics) outside QuantumSSH's scope.

### 8.5 Traffic-analysis resistance beyond what the transport provides

Packet-length and packet-timing analysis can reveal information
about session content (notably keystroke timing in interactive
sessions). The protocol does some shaping (block padding); strong
resistance to traffic analysis is a research-grade problem and not
a Phase-1 or Phase-2 deliverable.

### 8.6 Backward compatibility with pre-modern SSH clients

If a client cannot speak the hybrid post-quantum key exchange, it
does not connect. This is a stated non-goal in the README and the
manifesto. Operators with legacy clients should either upgrade them
or continue using OpenSSH on those endpoints during the transition.

### 8.7 Compliance with National Security System (NSS) requirements

NSA CNSA 2.0 mandates **ML-KEM-1024** and **ML-DSA-87** for U.S.
National Security Systems. QuantumSSH's default,
`mlkem768x25519-sha256`, uses ML-KEM-**768** — consistent with the
IETF hybrid PQ KEX draft and with the OpenSSH 10.0 default, but
*below* CNSA 2.0's NSS requirement. QuantumSSH is not targeting
NSS deployments; operators in that space should consult the
controlling authority and the current CNSA 2.0 advisory before
relying on any open-source SSH implementation.

### 8.8 Replacement for host-level hardening

QuantumSSH does not implement its own sandboxing, its own
mandatory-access-control layer, its own audit subsystem, or its own
key-management daemon. It uses the operating system's facilities
for those concerns and assumes the operator has chosen and
configured them appropriately.

### 8.9 Hardware-level adversaries

Side-channel attacks against the host CPU (cache timing, power
analysis, electromagnetic emanation), fault injection, and physical
attacks on the host's storage are outside this project's scope.
Operators deploying on shared, multi-tenant, or physically
accessible hardware must add hardware-level controls.

### 8.10 Indefinite forward secrecy against unknown future capability

The post-quantum-by-default posture defends against the
harvest-now-decrypt-later adversary modelled on currently anticipated
cryptanalytic capability (classical advances on lattice problems,
quantum advances per Shor's algorithm and successors). It cannot
defend against unknown future cryptanalytic breakthroughs that
target the chosen primitives directly. The project's commitment is
to track NIST and IETF guidance and to migrate before deprecation
deadlines, not to anticipate breakthroughs that have not yet
occurred.

### 8.11 Hardening of the maintainer's personal endpoint

*(Reserved by [RFC-0001](rfcs/0001-threat-model-actor-project-maintainer-compromise.md)
§"Proposed amendments — §8". Content provided in the RFC-0001
Implementation PR.)*

### 8.12 Per-user UID isolation until Phase 3

Until the privilege-separation work scheduled for Phase 3 lands,
QuantumSSH executes the authenticated user's command under the
operating system identity of the QuantumSSH service account (the same
account that owns the listening process), **not** under the OS
identity of the authenticated user. Two consequences follow.

First, operators must deploy Phase 1 with the assumption that any key
in `authorized_keys` is operationally equivalent to a key for the
service account; multi-tenant deployments are not in scope for Phase 1.
The supported posture is single-user: one operator, one set of keys,
one account.

Second, file system and process accesses performed by commands run
through QuantumSSH inherit the service account's authority, not the
authenticated user's. Auditors reading server logs must read
`executing_uid = <service account UID>` on every command-execution
record rather than a per-user UID; the §2.7 audit record includes
`executing_uid` as a first-class field precisely so this gap is
visible to anyone reviewing logs.

The closure condition for this non-goal is Phase 3 privilege-separation
being implemented and a follow-up RFC superseding this entry and
removing §8.12. Until both happen, this remains a deliberate temporary
non-goal. See [RFC-0002](rfcs/0002-threat-model-phase1-uid-model-and-non-goal.md)
and [ADR-0016](adr/0016-phase-1-service-account-uid-model.md) for the
full rationale and operational counterpart.

---

## 9. References

### Standards and primary documents

- IETF RFC 4251, *The Secure Shell (SSH) Protocol Architecture*,
  January 2006. <https://datatracker.ietf.org/doc/html/rfc4251>
- IETF RFC 4252, *The Secure Shell (SSH) Authentication Protocol*,
  January 2006. <https://datatracker.ietf.org/doc/html/rfc4252>
- IETF RFC 4253, *The Secure Shell (SSH) Transport Layer Protocol*,
  January 2006. <https://datatracker.ietf.org/doc/html/rfc4253>
- IETF RFC 4254, *The Secure Shell (SSH) Connection Protocol*,
  January 2006. <https://datatracker.ietf.org/doc/html/rfc4254>
- IETF RFC 8709, *Ed25519 and Ed448 Public Key Algorithms for the
  Secure Shell (SSH) Protocol*, February 2020.
  <https://datatracker.ietf.org/doc/html/rfc8709>
- IETF RFC 9142, *Key Exchange (KEX) Method Updates and
  Recommendations for Secure Shell (SSH)*, January 2022.
  <https://datatracker.ietf.org/doc/html/rfc9142>
- IETF Internet-Draft, *PQ/T Hybrid Key Exchange with ML-KEM in SSH*,
  `draft-ietf-sshm-mlkem-hybrid-kex` (version -10, 26 February
  2026). Active draft as of acceptance of this document.
  <https://datatracker.ietf.org/doc/draft-ietf-sshm-mlkem-hybrid-kex/>
- NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism
  Standard*, 13 August 2024.
  <https://csrc.nist.gov/pubs/fips/203/final>
- NIST FIPS 204, *Module-Lattice-Based Digital Signature Standard*,
  13 August 2024.
  <https://csrc.nist.gov/pubs/fips/204/final>
- NIST FIPS 205, *Stateless Hash-Based Digital Signature Standard*,
  13 August 2024.
  <https://csrc.nist.gov/pubs/fips/205/final>
- NIST SP 800-227, *Recommendations for Key-Encapsulation Mechanisms*,
  September 2025 (final).
  <https://csrc.nist.gov/pubs/sp/800/227/final>

### Risk-assessment framework

- NIST SP 800-30 Rev.1, *Guide for Conducting Risk Assessments*,
  September 2012, in particular Appendix D, "Threat Sources",
  Tables D-2 (threat sources), D-3 (adversary capability), D-4
  (adversary intent), D-5 (adversary targeting), and D-6 (range of
  effects for non-adversarial sources).
  <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf>
- NIST SP 800-39, *Managing Information Security Risk*, March 2011
  (source of the organisational Tier 1 / 2 / 3 model referenced in
  the terminology note in §3.1).
  <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-39.pdf>

### Attack taxonomy

- MITRE ATT&CK Enterprise Matrix, v19 (April 2026). Technique IDs
  cited inline in §5.
  <https://attack.mitre.org/>

### Post-quantum transition guidance

- NSA Cybersecurity Advisory, *Announcing the Commercial National
  Security Algorithm Suite 2.0* (U/OO/194427-22), reissued 30 May
  2025. Original advisory 7 September 2022.
  <https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF>
- NSA CNSA 2.0 FAQ (U/OO/194427-22), Ver. 2.1, December 2024.
  <https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF>
- CISA, NSA, NIST joint Cybersecurity Information Sheet,
  *Quantum-Readiness: Migration to Post-Quantum Cryptography*,
  21 August 2023.
  <https://www.cisa.gov/sites/default/files/2023-08/Quantum-Readiness_Final_CLEAR_508c%20(3).pdf>
- NIST IR 8547 (Initial Public Draft), *Transition to Post-Quantum
  Cryptography Standards*, November 2024 — establishes deprecation
  of quantum-vulnerable algorithms by 2030 and disallowance after
  2035 as NIST's policy proxy for the CRQC timeline.
  <https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf>
- Michele Mosca, *Cybersecurity in an era with quantum computers:
  will we be ready?*, Cryptology ePrint Archive Paper 2015/1075,
  5 November 2015 (canonical reference for the *x + y > z*
  inequality used to size HNDL exposure).
  <https://eprint.iacr.org/2015/1075>

### Project-internal references

- [`README.md`](../README.md) — project introduction, vision, and
  open-source posture.
- [`MANIFIESTO.es.md`](../MANIFIESTO.es.md) — Spanish-language
  manifesto.
- [`docs/infrastructure.md`](infrastructure.md) — operational
  topology referenced from §6.5.
- [`docs/operations.md`](operations.md) — verification recipes
  referenced from §6.5.
- [`docs/adr/`](adr/) — architecture decision records; ADR-0006
  (commit signing), ADR-0008 (branch protection), and ADR-0015
  (errata mechanism) are cited inline.
- [`SECURITY.md`](../SECURITY.md) — coordinated disclosure process.
