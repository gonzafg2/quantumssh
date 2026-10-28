# ADR 0044: Parse the config file with `toml`, replacing the unmaintained `basic-toml`

- **Status:** Proposed
- **Date:** — (set on acceptance; drafted 2026-10-28)
- **Deciders:** Project lead
- **Related:** Supersedes the "Parser crate" bullet of [ADR-0029](0029-phase-2-config-file-v1-schema-parser-strictmodes.md) §Decision; every other bullet of ADR-0029 stands. [RFC-0010](../rfcs/0010-configuration-file.md) §"The parser and its dependency" leaves the crate to an implementing ADR, chosen against `cargo deny` at the time. Triggered by [RUSTSEC-2026-0374](https://rustsec.org/advisories/RUSTSEC-2026-0374.html); the stopgap ignore is [#212](https://github.com/gonzafg2/quantumssh/pull/212). Constrained by [ADR-0010](0010-toolchain-pinning-resolver-3-edition-2024-msrv-1-92.md) (MSRV 1.92).

## Context

ADR-0029 chose `basic-toml` as the config parser: "a maintained,
serde-only fork of `toml` 0.5" with no further dependencies, so the
lockfile delta was one crate. The config structs derive `Deserialize`
with `deny_unknown_fields` on the root and on every section, and the
`schema_error` message carries line and column.

On 2026-09-26 RustSec published RUSTSEC-2026-0374: `basic-toml` is
unmaintained. Its repository is archived, and its last release (0.1.10,
the locked version) is from 2025-03-03. The advisory is informational:
no vulnerability is known, there is no patched version, and it names
`toml` as the alternative.

`deny.toml` treats an unmaintained crate as an error, so `cargo deny`,
a required check, has failed on `main` since the 2026-10-28 push. #212
ignores the advisory, with its reason, to unblock merges until this
decision lands.

ADR-0029's premise ("maintained") was true when it was accepted and is
false now. That is a changed fact, not a factual error, so ADR-0015's
errata do not apply. The parser choice is superseded instead.

The config surface is part of the `0.1.0` freeze ([#109](https://github.com/gonzafg2/quantumssh/issues/109)).
Shipping the frozen release on an archived parser means no upstream fix
for any defect found later.

What the parser must keep doing, unchanged from ADR-0029:

- serde derive, with `deny_unknown_fields` on the root document struct
  and every section struct, so that the RFC-0010 fail-closed rule comes
  from the deserializer and not from hand-written key checks;
- a `schema_error` that names the line and column;
- no allocation or recursion that the file's contents can grow without
  bound.

## Decision

1. **The parser is `toml` 1.1.8.** The workspace declares
   `toml = { version = "1.1", default-features = false, features = ["std", "serde", "parse"] }`,
   and `Cargo.lock` resolves 1.1.8. The features left out:
   - `display`: the binary never writes TOML.
   - `preserve_order` and `fast_hash`: key order does not matter to a
     struct deserializer.
   - `debug`: it pulls `anstream` and `anstyle`.
   - `unbounded`: it adds a method that disables the parser's recursion
     limit. Without it, the limit stays in force, so nesting depth in the
     file is bounded.
2. **The lockfile delta is five crates, net four.** `toml` 1.1.8,
   `toml_parser` 1.1.5, `toml_datetime` 1.1.2, `serde_spanned` 1.1.2 and
   `winnow` 1.0.4 enter, `basic-toml` 0.1.10 leaves, and `serde_core`
   1.0.229 is already locked. Checked on 2026-10-28:
   - **Licences:** `MIT OR Apache-2.0`, and `MIT` for `winnow`. `deny.toml`
     allows both.
   - **MSRV:** 1.85, and 1.65 for `winnow`. Both are within ADR-0010's
     1.92.
   - **Advisories:** RustSec has none for any of the five.
3. **`schema_error` stays one line, with no file contents.** The
   message is `{origin}: {message} at line {L} column {C}`. `message`
   comes from `toml::de::Error::message()`, and the line and column are
   computed from the start of `Error::span()` over the input. The
   crate's `Display` adds a multi-line excerpt of the file, and that
   excerpt is not used, so no config text reaches stderr or the log. An
   error without a span carries the message alone.
4. **Everything else in ADR-0029 is unchanged:** the keys and value
   grammars, `deny_unknown_fields` placement, `schema_version`
   handling, zero rejection, StrictModes, and the retained flags. The
   message text inside a `schema_error` changes wording, since it comes
   from a different crate. The class, `schema_error`, does not change,
   and neither do the other RFC-0010 classes.
5. **The implementing PR** swaps the dependency, adapts the error
   mapping in `crates/quantumssh/src/config.rs`, keeps the existing
   config tests green, and adds one test for the single-line message.
   It also removes RUSTSEC-2026-0374 from `deny.toml`, flips this ADR to
   Accepted, and points ADR-0029's Status field at it, as ADR-0010's
   points at ADR-0039. It runs `cargo deny check`.

## Consequences

### Positive

- The config parser is maintained again, and the `0.1.0` freeze does not
  ship an archived crate.
- `cargo deny` passes without an ignore, so the advisory gate is back
  to its default.
- The recursion limit stays in force by construction: the feature that
  lifts it is not enabled.
- The error message no longer depends on a crate's `Display` layout,
  because the binary builds it from the message and the span.

### Negative

- **Four more crates in the trust base.** `winnow` is a general parser
  combinator library, larger than `basic-toml`'s hand-written parser.
  The parsed input is the operator's own file, read after the
  StrictModes checks, never peer input, and off the pre-authentication
  path (threat model §4.1).
- **A wider grammar.** `toml` 1.1.8 implements TOML 1.1.0, which adds
  syntax over 1.0: newlines and trailing commas in inline tables, the
  `\e` and `\xHH` escapes, and times without seconds. A schema-v1 file
  that is valid TOML 1.0 stays valid. A file that uses the new syntax is
  now accepted, and the schema's keys and types are still enforced.
- **Different wording in `schema_error` messages.** v0.0.1 shipped
  `basic-toml`'s wording. Only the text after the class changes: the
  classes are RFC-0010's stable contract, and the text is not.

### Neutral

- `cargo deny check` runs in the implementing PR. This ADR checked its
  inputs by hand: licences against `deny.toml`, MSRV against ADR-0010,
  and advisories against RustSec.

## Alternatives considered

- **Keep `basic-toml` with a permanent ignore.** The parser reads a
  trusted file, so the risk is small. Rejected: the frozen `0.1.0` would
  carry a crate that cannot receive fixes, and the ignore would hide any
  later advisory on the same crate.
- **`toml-span`.** It is small, but it deserializes through its own
  trait, not serde derive. Rejected: `deny_unknown_fields` would become
  hand-written key checks, which ADR-0029 rejected.
- **`toml_edit`.** It preserves formatting for editing, which the binary
  never does. With parsing and serde enabled it needs the same crates as
  `toml`, plus `indexmap`, which is required. Rejected.
- **A first-party parser for a TOML subset.** Rejected: it adds
  first-party parser surface for a solved problem, and RFC-0010 fixes
  TOML, not a subset of it.

## Links

- Advisory: [RUSTSEC-2026-0374](https://rustsec.org/advisories/RUSTSEC-2026-0374.html)
  (2026-09-26); stopgap [#212](https://github.com/gonzafg2/quantumssh/pull/212).
- Crate: [`toml` 1.1.8](https://crates.io/crates/toml/1.1.8), whose
  `unbounded` feature is described in [`crates/toml/Cargo.toml`](https://github.com/toml-rs/toml/blob/main/crates/toml/Cargo.toml);
  [`toml::de::Error`](https://docs.rs/toml/1.1.8/toml/de/struct.Error.html)
  (`message`, `span`).
- Superseded choice: [ADR-0029](0029-phase-2-config-file-v1-schema-parser-strictmodes.md)
  §Decision, "Parser crate".
- Roadmap: Phase 2 — [#109](https://github.com/gonzafg2/quantumssh/issues/109).
