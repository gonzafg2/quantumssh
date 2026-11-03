# RFC 0018: Host-key generation in the binary — `quantumssh keygen`

- **Status:** Accepted (2026-11-03)
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-11-03
- **Roadmap issue:** [#248](https://github.com/gonzafg2/quantumssh/issues/248) (Phase 3)
- **Implementation PR:** TBD

## Summary

Add one subcommand, `quantumssh keygen <PATH>`. It writes a new
`ssh-mldsa44-ed25519` host key as an unencrypted `openssh-key-v1` file,
with its public key next to it. The layout is the one
`ssh-keygen -t mldsa44-ed25519` writes and the one the server's loader
already reads, so a server host no longer needs OpenSSH 10.6 to create
its own host key. The server never generates a key on its own: a missing
host key still stops startup. CI checks compatibility against
`ssh-keygen` 10.6 in both directions.

## Motivation

Step 3 of `docs/deployment.md` creates the host key with
`ssh-keygen -t mldsa44-ed25519`. The composite type is the only host key
the server accepts (RFC-0012, ADR-0047), and only OpenSSH 10.6 or later
can generate it. On 2026-11-03, according to
[Repology](https://repology.org/project/openssh/versions), these do not
ship 10.6:

- **every Ubuntu release** (26.10 has 10.5p1);
- Debian 13 (10.0p1; 10.3p1 in backports);
- Fedora 44 (10.2p1);
- RHEL, Rocky and Alma 9 (9.9p1);
- openSUSE Leap 15.6 (9.6p1).

On those hosts an operator can do one of two things:

- **Install a newer OpenSSH just to run `ssh-keygen` once.** On most of
  them that means Homebrew on Linux on a server.
- **Generate the key on another machine and copy it over.** That moves
  the host's most valuable secret (threat model §5.5.3) across machines
  and through whatever channel the copy used.

The second is the easier path, and it is the worse one. The project
should make the safe path the easy one.

The problem does not depend on how QuantumSSH is installed: a source
build on Ubuntu has it too. That is why this is its own decision rather
than part of RFC-0017's distribution proposal
([#247](https://github.com/gonzafg2/quantumssh/pull/247)), as
`docs/rfcs/README.md` §"Scope: one decision per RFC" requires. The two
RFCs were accepted together, and each can be implemented without the
other. Until this one is implemented, step 3 of the operator guide keeps
`ssh-keygen`.

## Guide-level explanation

On a Linux host, the host-key lines of step 3 of the operator guide
become:

```sh
sudo install -d -m 0755 /etc/quantumssh
sudo quantumssh keygen /etc/quantumssh/ssh_host_mldsa44_ed25519_key
sudo chown quantumssh:quantumssh /etc/quantumssh/ssh_host_mldsa44_ed25519_key
```

The rest of step 3, installing `authorized_keys`, is unchanged.

Output:

```
wrote /etc/quantumssh/ssh_host_mldsa44_ed25519_key (private, 0600)
wrote /etc/quantumssh/ssh_host_mldsa44_ed25519_key.pub (public, 0644)
SHA256:<43 base64 characters>
```

The fingerprint matches what `server.started` logs. On a host with
OpenSSH 10.6 or later, it also matches what `ssh-keygen -lf` prints for
the `.pub` file; older `ssh-keygen` releases cannot parse the type. An
operator can publish the fingerprint out of band before the first
connection.

`keygen` refuses to replace a key. If either file exists, it exits
non-zero before it writes any key bytes. Rotating a host key stays a deliberate act:
move the old key aside, generate, restart.

## Reference-level explanation

### 1. Command line

```
quantumssh keygen <PATH>
```

This is the binary's first subcommand. Today the binary takes only flags
(`--help`, `--version`, `--config`, `--listen` and the rest). `keygen`
takes exactly one argument and no flags. It does not read the
configuration file, bind a socket or start a runtime, and it exits once
the files are written. The subsidiary ADR settles how the parser tells
the subcommand from the flags (§8).

### 2. Generation

1. Draw 64 bytes from the operating system's RNG through `getrandom`,
   the source the transport already uses. The first 32 bytes are the
   ML-DSA-44 seed and the last 32 the Ed25519 seed. This is the layout
   OpenSSH stores and the loader reads (`mldsa_seed ‖ ed25519_seed`).
   **An RNG error aborts the run, and there is no fallback.** It happens
   before any seed is used, and `keygen` never substitutes a zero, a
   partial or a derived seed. The two empty files this run created are
   removed and the exit status is non-zero. This is the threat model's
   rule (§3.3, "OS-provided randomness with no fallback") and
   ADR-0035 §3's "RNG failure fails closed". The check words are drawn
   from the same source under the same rule. A unit test injects a
   failing RNG and expects the abort, the cleanup and no output file.
2. Build the signing key with the existing `SigningKey::from_seeds`, the
   construction `HostKey::from_openssh_pem` uses on load (RFC-0012,
   ADR-0035, ADR-0047).
3. Encode the private key as an unencrypted `openssh-key-v1` container,
   matching OpenSSH's `ssh-mldsa-eddsa.c`:
   - the magic `openssh-key-v1\0`;
   - cipher `none`, kdf `none` and an empty kdf-options string;
   - a key count of one;
   - the public blob, `string("ssh-mldsa44-ed25519") ‖
     string(mldsa_pk ‖ ed25519_pk)` (RFC-0012);
   - a private section with:
     - two equal random check words;
     - key type `ssh-mldsa44-ed25519`;
     - `string(mldsa_pk ‖ ed25519_pk)`;
     - `string(seeds)`;
     - an empty comment. `ssh-keygen` writes `user@host` by default;
       an empty comment says nothing about the machine that generated
       the key;
     - padding bytes `1, 2, 3, …` until the private section's length is
       a multiple of 8, the block size OpenSSH uses for cipher `none`. No
       padding is added when the length is already a multiple of 8.
4. Encode the public key line as `ssh-mldsa44-ed25519 <base64 blob>`
   with no comment.

The encoder is new code. Unit tests check it on every run:

- **A round trip:** a key `keygen` encodes must parse with
  `HostKey::from_openssh_pem` and give the same public key. The loader
  checks the field order, the bounds, the check words and the consistency
  of the seeds with the public key.
- **The trailer the loader skips:** the loader does not parse the comment
  or the padding. A separate test asserts that the private section's
  length is a multiple of 8 and that the padding bytes are exactly
  `1, 2, 3, …`.

OpenSSH format compliance as a whole is checked by `ssh-keygen` 10.6
itself (§6). The tests generate their keys at run time; no private-key fixture is committed.

### 3. Writing the files

- **Creation:**
  - both files are opened with `O_CREAT | O_EXCL | O_NOFOLLOW`, so an
    existing file or a symlink at either path is an error, never a
    target;
  - **the private file is never readable by anyone else, from the moment
    it exists:** `<PATH>` is created with mode `0600` in the `open(2)`
    call itself, never with a library default such as `0666`. The
    `umask` can only remove bits, so the file can never start wider than
    `0600`. Fixing the mode later with `fchmod` would not be enough: a
    local user watching the directory could open the file in the window
    before the `fchmod`, and the descriptor would stay valid after it;
  - **the public file's mode is then widened explicitly:** `<PATH>.pub`
    is created with `0644`. A hardened `umask` such as `077` would narrow
    it to `0600`, so `keygen` sets it to `0644` with `fchmod` on the open
    descriptor. `fchmod(0600)` on `<PATH>` likewise undoes any narrowing
    of the owner bits;
  - the modes printed on success are the ones `fstat` reports, not the
    requested ones.
- **Order.**
  1. Both files are opened, empty, before the seeds are drawn or any key
     byte is written. If either open fails, whatever this run created is
     removed, and no key exists yet.
  2. The private file is written and `fsync`ed.
  3. The public file is written and `fsync`ed.
- **Any handled failure after step 1** removes both files this run
  created before exiting non-zero:
  - an RNG error (§2);
  - a failed `fchmod`;
  - a failed write;
  - a failed `fsync` of either file;
  - a failed public write. In those cases no half-written
  pair, empty `0600` file or stray `.pub` is left to block the next run.
- **An interrupted run is not a handled failure.** If `SIGKILL`, an OOM
  kill, a power loss or a default-handled `SIGINT` stops the process
  between step 1 and the end, cleanup does not run. One or both files may
  be left behind, empty or partly written. The next run refuses them
  (`O_EXCL`) and names them in its error. The operator removes them
  before retrying, and treats any private key that was left behind as
  never used. Writing to temporary names and renaming without replacing
  was considered. It would move the leftover to a temporary name rather
  than remove it, at the cost of platform-specific rename flags, so it
  is not proposed.
- **A failed removal** is its own error. The message names the path left
  behind, and the exit status is non-zero.
- **Data already on disk.** If the private file was written before the
  failure, unlinking it does not erase what reached the disk. The message
  says so, and the operator treats that key as never used. The order
  above makes this possible only when a write to the private file, its
  `fsync`, the public write or the public `fsync` fails, never because a
  file already existed.
- **Parent directory check, before any write.**
  - **Canonicalize the parent first.** `<PATH>` does not exist yet, so
    `keygen` canonicalizes `<PATH>`'s parent directory, failing closed on
    `ENOENT`, `EACCES` or a dangling symlink. It then walks the ancestors
    of the **canonical** parent. ADR-0029's startup check canonicalizes
    for the same reason: a lexical walk over a symlinked parent would
    check the wrong directories.
  - **Apply the startup rule.** Neither the canonical parent nor any
    directory above it may be group- or world-writable (ADR-0029).
  - **Create the files inside the checked directory.** Both files are
    created under the canonical parent joined with the leaf name.
    `O_NOFOLLOW` covers the leaf itself.
  - **A key the server would refuse is refused now.** A key written where
    the server would refuse to read it is an error at generation time,
    not at the next restart.
  - **Residual race.** A race between the check and the open remains, and
    it is accepted on ADR-0029's best-effort terms.
  - **Test.** A test uses a parent that is a symlink to a `0777`
    directory and expects a refusal.
- **Ownership.** `keygen` does not change ownership. The operator
  `chown`s the key to the service account, as the guide shows, because
  the root-owned `/etc/quantumssh` (ADR-0029) does not let that account
  create files.

### 4. Key material

- **Memory.** Every buffer that holds the seeds or any recoverable
  encoding of them lives in `Zeroizing` and is erased on drop and on every
  error path (threat model §4.3):
  - the seeds and the signing key;
  - the serialized private section;
  - the whole container;
  - its base64 body;
  - the PEM text handed to `write`.

  This is the same rule the loader applies when it reads those layers
  (`host_key.rs` and the PEM read in `main.rs`).
- **Output.** Nothing derived from the private key is printed or logged.
  The only output is the two paths and the fingerprint.

### 5. No implicit generation

The server never calls `keygen` logic.

- **A missing or unreadable host key** still stops startup with
  `server.config_error` (fail closed).
- **No first-start generation.** There is no "generate on first start",
  no `--generate-if-missing` and no install-time hook in the binary.
  Packaging that wants one, such as a future `.deb` maintainer script,
  calls `quantumssh keygen` explicitly and is decided in its own ADR.

### 6. Compatibility checks in CI

The interop container already carries OpenSSH 10.6p1 (ADR-0048). The
interop job gains two steps:

- `ssh-keygen -y -f <key written by keygen>` prints a public key
  byte-identical to `keygen`'s `.pub`, and `ssh-keygen -lf` prints the
  same fingerprint;
- a server started with a key `keygen` wrote completes the existing
  connect → auth → exec → close run with the stock client.

The reverse direction is already covered: the gate's host key comes from
`ssh-keygen` today. A failure of either step fails the gate.

### 7. Scope

- **One key type: `ssh-mldsa44-ed25519`.** The server accepts no other
  host key type (RFC-0012).
- **No passphrase.** The server reads only unencrypted keys.
- **No user keys, no certificates, no CA keys.** Those stay with
  `ssh-keygen` on the client side, where OpenSSH 10.6 is already a
  requirement.
- **No key rotation command and no fingerprint subcommand.** On the
  hosts this RFC is for, `keygen` prints the fingerprint when it writes
  the key and `server.started` logs it at every start. `ssh-keygen -lf`
  shows it only where OpenSSH is 10.6 or later.

### 8. Subsidiary ADR

One ADR records:

- the command-line parsing change;
- the encoder's module placement;
- the CI steps of §6.

### 9. Changes to other documents

| Document | Change |
|---|---|
| `docs/deployment.md` step 3 | Uses `quantumssh keygen` and `chown`. `ssh-keygen` 10.6 stays documented as an alternative |
| `crates/quantumssh/src/main.rs` help text | Lists the subcommand |
| `CHANGELOG.md` | An `Added` entry in the release that ships it |

## Drawbacks

- **New code on the most sensitive path.** `keygen` creates the host
  private key, the asset threat model §5.5.3 covers. The code is short
  and the cryptography is in crates the loader already trusts, but the
  container encoder, the file handling and the RNG call are new.
- **The command line grows a mode.** The binary stops being flags-only.
  Every future subcommand will be measured against this precedent, and
  "small surface" (MANIFIESTO) argues for very few of them.
- **The format has to track OpenSSH.** If a future OpenSSH changes how
  it stores composite keys, the two could diverge. The round trip in §6
  catches that on the pinned client but not on newer clients until the
  pin moves.
- **A second way to do the same thing.** Operators who already have
  OpenSSH 10.6 can use either tool. The guide recommends `keygen` and
  keeps `ssh-keygen` as an alternative, so both paths stay documented.

## Rationale and alternatives

### Alternative 1: keep `ssh-keygen` 10.6 as a server requirement

This adds no code. It leaves the operators of the distributions listed
under Motivation with a choice between installing an OpenSSH they do not
otherwise need on a server and copying the key across machines. Copying
the key is the worse of the two, and it is the one people will take.

### Alternative 2: generate the key automatically on first start

This is what many `sshd` packages do: Debian's `openssh-server`, for
example, generates host keys at install time. It would make a
missing key a silent success. The fingerprint operators should check
out of band would appear only after the server is already serving.
QuantumSSH fails closed on configuration problems, and a missing host
key is one of them.

### Alternative 3: a separate `quantumssh-keygen` binary

This keeps the server binary flags-only, at the cost of a second
artifact per target to build, attest, package and document. The code it
contains would be the same.

### Alternative 4: a flag on the server, `--generate-host-key <PATH>`

This mixes a one-shot tool into the server's flag set, where `--config`
and `--listen` would have to be rejected next to it. A subcommand states
the different mode more clearly.

### Alternative 5: `keygen --file <PATH>`

This would mirror `ssh-keygen -f`. The command takes exactly one
argument (§1), so a flag adds nothing but a second spelling to parse.
`keygen <PATH>` is kept.

### Alternative 6: print the public key line as well

It would help operators who paste the key into notes, but the `.pub`
file already holds it. Keeping stdout to the two paths and the
fingerprint (§4) keeps the output short and stable for scripts.

## Prior art

- **OpenSSH** has `ssh-keygen`, and `ssh-keygen -A` for every default host
  key type. Distribution packages run it at install time.
- **Dropbear** ships `dropbearkey`, a separate key-generation binary, and
  `dropbear -R` generates missing host keys at startup.
- **QuantumSSH's own loader** is the specification for the container
  this RFC writes: `crates/quantumssh-core/src/host_key.rs`, which
  follows OpenSSH's `ssh-mldsa-eddsa.c`.

## Unresolved questions

None that affects the decision. §1 fixes the command line, §4 fixes the
output, and §2 fixes the empty comment. The subsidiary ADR settles only
the parsing mechanics, the module placement and the CI steps (§8).

## Future possibilities

- Packaging hooks, such as a `.deb` `postinst`, that call `keygen`
  explicitly, if a future distribution ADR adds packages (TBD; #247
  defers them).
- A host-key rotation procedure in the operator guide, using `keygen`
  and a published fingerprint.
