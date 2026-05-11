# ADR 0006: Sign commits with SSH keys rather than GPG

- **Status:** Accepted
- **Date:** 2026-05-10
- **Deciders:** Project lead
- **Related:** [ADR-0005](0005-pgp-key-two-year-expiry.md) (PGP is still used for embargoed disclosure), `docs/infrastructure.md` § "Commit signing", `docs/operations.md` § "Signed-commit verification"

## Context

Git supports two signing back-ends: GPG (the historical default) and
SSH (introduced in git 2.34 and natively supported on GitHub since
2022). Branch protection on `main` requires signed commits regardless
of mechanism.

The trade-off centres on where the trust root lives and what
contributors must do to verify signatures.

- **GPG signing** requires a separate keypair, separate key
  management, a separate trust web, and a separate keyserver
  ecosystem. Verifying signatures requires the verifier to install
  GnuPG and fetch the maintainer's GPG public key.
- **SSH signing** reuses the SSH key the maintainer already uses for
  authentication. The verifier fetches the public key from a known
  public source — GitHub exposes it at
  `api.github.com/users/<user>/ssh_signing_keys` — and constructs a
  one-line `allowed_signers` file. No GnuPG keyring required.

Both produce equivalently strong signatures (Ed25519 → Ed25519).

## Decision

We will use SSH keys (Ed25519) for git commit signing. The PGP key
is retained, separately, for the embargoed-disclosure path described
in `SECURITY.md`.

## Consequences

### Positive

- One fewer private key for the maintainer to secure. The same key
  authenticates to GitHub and signs commits.
- The signing-key trust root is a public artefact at
  `api.github.com/users/<user>/ssh_signing_keys`, queryable by anyone
  without auth.
- Contributor and auditor setup for signature verification is a
  one-line file (`allowed_signers`) instead of a GnuPG keyring import.
- Branch-protection-required signatures are validated server-side by
  GitHub against the same upload, so a divergence between local and
  server state surfaces immediately.

### Negative

- Reusing the auth key for signing means a single compromise affects
  both surfaces. Mitigation: the SSH private key is held under the
  same protections as before (passphrase, FileVault, no key forwarding
  to untrusted hosts), and the compromise is detectable through GitHub
  audit logs.
- Tooling for SSH-signature verification in non-git contexts is less
  mature than for GPG. The project's verification recipes in
  `docs/operations.md` document the working approach.

### Neutral

- The PGP key keeps its role for embargoed-disclosure encryption.
  The two systems are intentionally separated by tool: one keypair per
  purpose.

## Alternatives considered

### Alternative 1: GPG signing only

The historical default. Rejected because it duplicates key management
without a corresponding benefit, and because the verification UX
(install GnuPG, import key, manage trustdb) is a friction wall for
casual contributors.

### Alternative 2: Both SSH and GPG signing in parallel

Would maximise compatibility. Rejected because git signs with exactly
one back-end per commit; "parallel" signing would require dual-commit
workflows or external counter-signatures, neither of which adds value
for a project at this stage.

### Alternative 3: No commit signing

Would have removed the branch-protection requirement and lowered the
contribution barrier. Rejected because cryptographic infrastructure
projects that do not sign their own commits cannot credibly ask users
to trust those commits.

## Links

- Verification recipe: `docs/operations.md` § "Signed-commit verification"
- GitHub signing key endpoint:
  `https://api.github.com/users/gonzafg2/ssh_signing_keys`
- Branch protection enforcing signatures: see [ADR-0008](0008-branch-protection-zero-required-reviews.md)
