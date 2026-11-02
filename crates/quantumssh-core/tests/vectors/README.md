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

