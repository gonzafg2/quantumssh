# Test vectors

## `ml-kem-768-acvp.txt`

These are the ML-KEM-768 cases of NIST's ACVP-Server vectors for FIPS 203:
25 keyGen, 25 encapsulation, 10 decapsulation, 10 encapsulation-key
checks and 10 decapsulation-key checks. `tests/acvp_mlkem.rs` checks
each one byte for byte against the `ml-kem` crate (RFC-0003 §"Test
vectors and KAT plan", ADR-0019 §Decision 4).

- **Source.** [usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server)
  at commit `975de31eb83d87039ec88934fdc47d8c312b892d`:
  - `gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json`
  - `gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json`

  The file header records each source file's SHA-256.
- **Licence.** The ACVP-Server README states that "the software developed
  by NIST employees is not subject to copyright protection within the
  United States". The vectors are vendored here with that attribution.
- **Regenerating.** Fetch the two files at the commit above, then run:

  ```sh
  python3 scripts/extract-acvp-mlkem768.py 975de31eb83d87039ec88934fdc47d8c312b892d \
      ML-KEM-keyGen-FIPS203.json ML-KEM-encapDecap-FIPS203.json \
      > crates/quantumssh-core/tests/vectors/ml-kem-768-acvp.txt
  ```

  The script keeps only the `ML-KEM-768` groups and writes the
  `name = value` format the test parses. A new ACVP-Server commit is a
  reviewed change, like any vector update.

## `ml-dsa-44-acvp.txt`

These are the ML-DSA-44 cases of NIST's ACVP-Server vectors for FIPS 204,
the post-quantum half of the composite host key `ssh-mldsa44-ed25519`:
25 keyGen; 15 sigGen each through the internal interface,
deterministic and hedged, and through the external pure interface with a
context string, deterministic; 15 sigVer each through the internal and
the external pure interface. `tests/acvp_mldsa44.rs` checks each one byte
for byte against the `ml-dsa` crate (ADR-0035 §Decision 5).

- **Source.** [usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server)
  at commit `975de31eb83d87039ec88934fdc47d8c312b892d`:
  - `gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json`
  - `gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json`
  - `gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json`

  The file header records each source file's SHA-256.
- **Licence.** As for `ml-kem-768-acvp.txt` above.
- **Regenerating.** Fetch the three files at the commit above, then run:

  ```sh
  python3 scripts/extract-acvp-mldsa44.py 975de31eb83d87039ec88934fdc47d8c312b892d \
      ML-DSA-keyGen-FIPS204.json ML-DSA-sigGen-FIPS204.json ML-DSA-sigVer-FIPS204.json \
      > crates/quantumssh-core/tests/vectors/ml-dsa-44-acvp.txt
  ```

  The script keeps the `ML-DSA-44` groups listed above and fails if a
  group it expects is missing or duplicated.


## `mlkem768x25519-sha256-openssh.txt`

This is the golden vector for the hybrid combiner and the exchange hash
`H`, captured against an OpenSSH peer with a fixed-RNG profile (RFC-0003
§"Test vectors and KAT plan", threat model §5.2.4; #216). The tests in
`src/kex.rs` replay the server half of one captured session. They check
that it reproduces `S_REPLY` byte for byte and that the host key's
signature verifies over the recomputed `H`. They also check that keys
derived from the recomputed `K` and `H` open the first packet the client
sealed. OpenSSH had verified that signature over its own `H` and sealed
that packet with its own keys, so neither check rests on this code
agreeing with itself.

- **Source.** One session between the pinned OpenSSH client of the
  `openssh-interop` gate (ADR-0048) and the `quantumssh` release binary.
  The file header records the client's `ssh -V`, the commit and the
  image digest.
- **Fixed RNG.** The server runs with `scripts/fixed-getrandom.c`
  preloaded. The shim replaces `getrandom(3)` with a fixed-seed generator
  and logs every draw, so the vector can name the two draws the hybrid
  exchange consumed. No build of `quantumssh` contains a fixed-RNG path.
  The binary under capture is the release binary, unchanged.
- **Regenerating.** With Docker, from the repository root:

  ```sh
  scripts/capture-openssh-kex-vector.sh \
      > crates/quantumssh-core/tests/vectors/mlkem768x25519-sha256-openssh.txt
  ```

  The script takes the image, snapshot and client pins from
  `.github/workflows/interop.yml`, so it moves with an OpenSSH version
  bump. A new capture replaces the whole file, since every session draws
  fresh client keys. Like any vector update, it is a reviewed change.
