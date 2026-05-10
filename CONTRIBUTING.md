# Contributing to QuantumSSH

Thank you for considering a contribution. QuantumSSH aims to be
infrastructure that anyone can audit, fork, and improve, without asking
permission and without signing anything. That principle applies to the
contribution process too: we want it to be straightforward, free of
ceremony, and friendly to first-time contributors.

This document describes the few rules we do have, and the conventions
that keep the project navigable as it grows.

## Languages

**Spanish and English are both first-class languages of this project.**

You are welcome to file issues, open pull requests, write commit
messages, and start discussions in either. Maintainers will respond in
the language of the original message when possible. Documentation may
exist in either or both languages depending on its audience.

We are explicit about this because Latin America has been a consumer of
systems software for a long time, and we want this project to be a place
where Spanish-speaking contributors do not have to switch languages to
participate seriously.

## Developer Certificate of Origin (DCO)

Every commit to this repository must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/).
The DCO is a lightweight statement that you wrote the code (or have the
right to contribute it) and agree to license it under the project's
license.

To sign off a commit, add the `-s` flag to `git commit`:

```sh
git commit -s -m "feat: add hybrid key exchange handler"
```

This appends a line of the form `Signed-off-by: Your Name <you@example.com>`
to the commit message. The CI will reject pull requests containing
commits without sign-off.

**We do not require a Contributor License Agreement (CLA).** The DCO is
sufficient. Your contributions remain licensed under Apache 2.0 (the
project's license), and we will not relicense them out from under you.
See `GOVERNANCE.md` for the formal commitment.

## Workflow at a glance

1. **Open an issue first** for anything non-trivial, so we can agree on
   the shape of the change before you spend time on it. For typo fixes,
   small documentation changes, and obvious bug fixes, you can skip
   straight to a pull request.
2. **For substantial design changes**, open an RFC under `docs/rfcs/`
   first. See `docs/rfcs/README.md` for the (lightweight) process.
3. **Branch from `main`**, do your work, sign off your commits, and open
   a pull request against `main`.
4. **CI must be green** before review. The pre-merge checks are the
   same ones described below; you can run them all locally.
5. **At least one maintainer review** is required to merge. Reviewers
   will engage in substance, not nitpicks; if you disagree with feedback,
   please push back.

## Local development

The project pins its toolchain via `rust-toolchain.toml`, so `rustup`
will install the right channel for you automatically when you enter the
directory.

Common commands:

```sh
# Format check (must pass in CI)
cargo fmt --all -- --check

# Lint (must pass with -D warnings in CI)
cargo clippy --workspace --all-targets -- -D warnings

# Tests
cargo test --workspace

# Build, release profile (sanity check)
cargo build --workspace --release

# Dependency / license audit (requires cargo-deny installed)
cargo deny check

# Vulnerability audit (requires cargo-audit installed)
cargo audit
```

Please run `cargo fmt` and `cargo clippy` before pushing. The CI will
otherwise reject the PR and you will spend a round trip you did not need.

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/).
The first line of the message follows the pattern:

```
<type>(<optional scope>): <short summary>
```

Common types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`,
`perf`, `ci`, `build`, `security`.

Examples:

```
feat(kex): add ML-KEM-768 + X25519 hybrid key exchange
fix(auth): reject Ed25519 keys with malformed prefix
docs(threat-model): describe harvest-now-decrypt-later assumptions
```

The body of the commit (after a blank line) should explain *why* the
change is needed when it is not obvious from the summary. Cross-reference
the issue or RFC the change is associated with.

## Code style

- Format with `rustfmt`. The project's `rustfmt.toml` is the source of
  truth.
- Lint clean with `clippy` at the project's configured level. If you
  need to silence a lint, comment why next to the `#[allow]`.
- No `unsafe` in the protocol or crypto layers without an accompanying
  justification, review, and tests. The workspace lints set
  `unsafe_code = "deny"` by default; opting out is a deliberate act.
- Keep functions small and named after what they do. Prefer boring code
  that obviously works over clever code that probably works.

## Tests

- Unit tests live next to the code they test, in the conventional Rust
  `#[cfg(test)] mod tests` blocks.
- Integration and protocol tests live under each crate's `tests/`
  directory.
- Cryptographic and protocol code should have property-based tests where
  reasonable. We will adopt fuzzing under `cargo-fuzz` and OSS-Fuzz once
  the surface area justifies it.

## Documentation

Public APIs should have rustdoc comments. The workspace lints set
`missing_docs = "warn"` so you will be reminded if you forget. For
end-user documentation, prefer adding to or extending files under
`docs/` rather than scattering Markdown across the repo.

## Reporting a security issue

**Do not open public issues for security vulnerabilities.** See
`SECURITY.md` for the embargoed-disclosure process.

## Code of Conduct

Participation in this project is governed by the
[Contributor Covenant 2.1](./CODE_OF_CONDUCT.md). Reports go to
`conduct@quantumssh.org`.

## Questions

If something here is unclear, please open a discussion or an issue
asking. Friction in a contribution process is a bug, and we would like
to hear about it.
