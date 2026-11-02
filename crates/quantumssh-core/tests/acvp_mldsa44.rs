//! NIST ACVP-Server conformance vectors for ML-DSA-44 (FIPS 204), the
//! post-quantum half of the composite host key `ssh-mldsa44-ed25519`
//! (ADR-0035 §Decision 5).
//!
//! The vectors are `tests/vectors/ml-dsa-44-acvp.txt`, extracted by
//! `scripts/extract-acvp-mldsa44.py`, whose header records the
//! ACVP-Server commit and the SHA-256 of each source file. Every case is
//! checked byte for byte against the `ml-dsa` crate the host key signs
//! with. ACVP defines its vectors against FIPS 204's internal interfaces,
//! which `ml-dsa` exposes for tests only; production code never calls
//! them (ADR-0035 Alternative 5).

mod acvp;

use acvp::Case;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes,
    Keypair as _, MlDsa44, Seed, Signature, SigningKey, VerifyingKey,
};

const VECTORS: &str = include_str!("vectors/ml-dsa-44-acvp.txt");

fn cases(section: &str) -> Vec<Case> {
    acvp::cases(VECTORS, section)
}

/// ACVP gives signing keys only in the expanded 2560-byte form, which
/// only the deprecated decoder reads (as upstream's own harness does).
#[allow(deprecated)]
fn expanded_signing_key(case: &Case) -> ExpandedSigningKey<MlDsa44> {
    let bytes = ExpandedSigningKeyBytes::<MlDsa44>::try_from(case.hex("sk").as_slice())
        .expect("2560-byte sk");
    ExpandedSigningKey::from_expanded(&bytes)
}

fn verifying_key(case: &Case) -> VerifyingKey<MlDsa44> {
    let bytes =
        EncodedVerifyingKey::<MlDsa44>::try_from(case.hex("pk").as_slice()).expect("1312-byte pk");
    VerifyingKey::decode(&bytes)
}

/// `None` when the bytes are not a well-formed signature: a sigVer case
/// that ACVP expects to fail.
fn signature(case: &Case) -> Option<Signature<MlDsa44>> {
    let bytes = EncodedSignature::<MlDsa44>::try_from(case.hex("signature").as_slice()).ok()?;
    Signature::decode(&bytes)
}

/// `ML-DSA.KeyGen_internal(ξ)` (FIPS 204 Algorithm 6): the seed form the
/// composite host key stores.
#[test]
#[allow(deprecated)]
fn key_generation_matches_acvp() {
    let cases = cases("keyGen");
    assert_eq!(cases.len(), 25);
    for case in &cases {
        let seed = Seed::try_from(case.hex("seed").as_slice()).expect("32-byte seed");
        let key = SigningKey::<MlDsa44>::from_seed(&seed);
        assert_eq!(
            key.verifying_key().encode().as_slice(),
            case.hex("pk"),
            "tcId {}: pk",
            case.tc_id
        );
        assert_eq!(
            key.expanded_key().to_expanded().as_slice(),
            case.hex("sk"),
            "tcId {}: sk",
            case.tc_id
        );
    }
}

/// `ML-DSA.Sign_internal` (FIPS 204 Algorithm 7), deterministic: `rnd`
/// is all zeroes.
#[test]
fn deterministic_signing_matches_acvp() {
    let cases = cases("sigGen-internal-deterministic");
    assert_eq!(cases.len(), 15);
    for case in &cases {
        let signature =
            expanded_signing_key(case).sign_internal(&[&case.hex("message")], &[0u8; 32].into());
        assert_eq!(
            signature.encode().as_slice(),
            case.hex("signature"),
            "tcId {}",
            case.tc_id
        );
    }
}

/// `ML-DSA.Sign_internal`, hedged with each case's `rnd`: the variant the
/// host key signs with (ADR-0035 §3).
#[test]
fn hedged_signing_matches_acvp() {
    let cases = cases("sigGen-internal-hedged");
    assert_eq!(cases.len(), 15);
    for case in &cases {
        let rnd = case.hex("rnd").as_slice().try_into().expect("32-byte rnd");
        let signature = expanded_signing_key(case).sign_internal(&[&case.hex("message")], &rnd);
        assert_eq!(
            signature.encode().as_slice(),
            case.hex("signature"),
            "tcId {}",
            case.tc_id
        );
    }
}

/// `ML-DSA.Sign` (FIPS 204 Algorithm 2), deterministic, with a context
/// string: the public API and the `0 ‖ len(ctx) ‖ ctx ‖ M` framing the
/// composite signs through, with its label as the context.
#[test]
fn signing_with_a_context_matches_acvp() {
    let cases = cases("sigGen-external-deterministic");
    assert_eq!(cases.len(), 15);
    for case in &cases {
        let signature = expanded_signing_key(case)
            .sign_deterministic(&case.hex("message"), &case.hex("context"))
            .expect("context of at most 255 bytes");
        assert_eq!(
            signature.encode().as_slice(),
            case.hex("signature"),
            "tcId {}",
            case.tc_id
        );
    }
}

/// `ML-DSA.Verify_internal` (FIPS 204 Algorithm 8), valid and invalid
/// signatures alike.
#[test]
fn internal_verification_matches_acvp() {
    let cases = cases("sigVer-internal");
    assert_eq!(cases.len(), 15);
    assert!(cases.iter().any(|c| !c.passes()), "no negative case");
    for case in &cases {
        let valid = signature(case)
            .is_some_and(|sig| verifying_key(case).verify_internal(&case.hex("message"), &sig));
        assert_eq!(valid, case.passes(), "tcId {}", case.tc_id);
    }
}

/// `ML-DSA.Verify` (FIPS 204 Algorithm 3) with a context string: the
/// check a composite verifier runs on the ML-DSA half.
#[test]
fn verification_with_a_context_matches_acvp() {
    let cases = cases("sigVer-external");
    assert_eq!(cases.len(), 15);
    assert!(cases.iter().any(|c| !c.passes()), "no negative case");
    for case in &cases {
        let valid = signature(case).is_some_and(|sig| {
            verifying_key(case).verify_with_context(
                &case.hex("message"),
                &case.hex("context"),
                &sig,
            )
        });
        assert_eq!(valid, case.passes(), "tcId {}", case.tc_id);
    }
}
