//! NIST ACVP-Server conformance vectors for ML-KEM-768 (FIPS 203), the
//! post-quantum half of `mlkem768x25519-sha256` (RFC-0003 §"Test vectors
//! and KAT plan", ADR-0019 §Decision 4, threat model §5.2.4).
//!
//! The vectors are `tests/vectors/ml-kem-768-acvp.txt`, extracted by
//! `scripts/extract-acvp-mlkem768.py`, whose header records the
//! ACVP-Server commit and the SHA-256 of each source file. Every case is
//! checked byte for byte against the `ml-kem` crate the transport uses.

use ml_kem::kem::{Decapsulate as _, KeyExport as _};
// ACVP gives decapsulation keys only in the expanded 2400-byte form, so
// the comparison and the decoding go through the deprecated encoding.
#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding as _;
use ml_kem::{Ciphertext, DecapsulationKey, EncapsulationKey, MlKem768};

const VECTORS: &str = include_str!("vectors/ml-kem-768-acvp.txt");

/// One case: its section, `tcId` and `name = value` fields.
struct Case {
    section: String,
    tc_id: u32,
    fields: Vec<(String, String)>,
}

impl Case {
    fn hex(&self, name: &str) -> Vec<u8> {
        let value = self.text(name);
        assert_eq!(value.len() % 2, 0, "tcId {}: odd hex in {name}", self.tc_id);
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn text(&self, name: &str) -> &str {
        self.fields.iter().find(|(n, _)| n == name).map_or_else(
            || panic!("tcId {}: no {name}", self.tc_id),
            |(_, v)| v.as_str(),
        )
    }

    fn passes(&self) -> bool {
        match self.text("testPassed") {
            "true" => true,
            "false" => false,
            other => panic!("tcId {}: testPassed = {other}", self.tc_id),
        }
    }
}

fn cases(section: &str) -> Vec<Case> {
    let mut all = Vec::new();
    let mut current = String::new();
    for line in VECTORS.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            name.clone_into(&mut current);
            continue;
        }
        let (name, value) = line.split_once(" = ").expect("name = value");
        if name == "tcId" {
            all.push(Case {
                section: current.clone(),
                tc_id: value.parse().expect("tcId"),
                fields: Vec::new(),
            });
        } else {
            all.last_mut()
                .expect("field before tcId")
                .fields
                .push((name.to_owned(), value.to_owned()));
        }
    }
    let selected: Vec<Case> = all.into_iter().filter(|c| c.section == section).collect();
    assert!(!selected.is_empty(), "no [{section}] cases");
    selected
}

fn encapsulation_key(bytes: &[u8]) -> Option<EncapsulationKey<MlKem768>> {
    let array = ml_kem::Key::<EncapsulationKey<MlKem768>>::try_from(bytes).ok()?;
    EncapsulationKey::<MlKem768>::new(&array).ok()
}

/// The expanded 2400-byte form ACVP gives, through the deprecated
/// decoder: the seed form is what keys use, and ACVP has no seed for
/// decapsulation cases.
#[allow(deprecated)]
fn decapsulation_key(bytes: &[u8]) -> Option<DecapsulationKey<MlKem768>> {
    let expanded = ml_kem::ExpandedDecapsulationKey::<MlKem768>::try_from(bytes).ok()?;
    DecapsulationKey::<MlKem768>::from_expanded(&expanded).ok()
}

/// `ML-KEM.KeyGen_internal(d, z)` (FIPS 203 §6.1). ACVP's `dk` is the
/// expanded form, which only the deprecated encoding produces.
#[test]
#[allow(deprecated)]
fn key_generation_matches_acvp() {
    let cases = cases("keyGen");
    assert_eq!(cases.len(), 25);
    for case in &cases {
        let mut seed = case.hex("d");
        seed.extend_from_slice(&case.hex("z"));
        let seed = ml_kem::Seed::try_from(seed.as_slice()).expect("64-byte seed");
        let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
        assert_eq!(
            dk.encapsulation_key().to_bytes().as_slice(),
            case.hex("ek"),
            "tcId {}: ek",
            case.tc_id
        );
        assert_eq!(
            dk.to_expanded_bytes().as_slice(),
            case.hex("dk"),
            "tcId {}: dk",
            case.tc_id
        );
    }
}

/// `ML-KEM.Encaps_internal(ek, m)` (FIPS 203 §6.2).
#[test]
fn encapsulation_matches_acvp() {
    let cases = cases("encapsulation");
    assert_eq!(cases.len(), 25);
    for case in &cases {
        let ek = encapsulation_key(&case.hex("ek")).expect("valid ek");
        let m = ml_kem::B32::try_from(case.hex("m").as_slice()).expect("32-byte m");
        let (c, k) = ek.encapsulate_deterministic(&m);
        assert_eq!(c.as_slice(), case.hex("c"), "tcId {}: c", case.tc_id);
        assert_eq!(k.as_slice(), case.hex("k"), "tcId {}: k", case.tc_id);
    }
}

/// `ML-KEM.Decaps_internal(dk, c)` (FIPS 203 §6.3), implicit rejection
/// included: a modified ciphertext yields the rejection key ACVP expects.
#[test]
fn decapsulation_matches_acvp() {
    let cases = cases("decapsulation");
    assert_eq!(cases.len(), 10);
    for case in &cases {
        let dk = decapsulation_key(&case.hex("dk")).expect("valid dk");
        let c = Ciphertext::<MlKem768>::try_from(case.hex("c").as_slice()).expect("ciphertext");
        let k = dk.decapsulate(&c);
        assert_eq!(k.as_slice(), case.hex("k"), "tcId {}: k", case.tc_id);
    }
}

/// The encapsulation-key check of FIPS 203 §7.2, which the transport
/// applies to every client key through `EncapsulationKey::new` (ADR-0019).
#[test]
fn encapsulation_key_check_matches_acvp() {
    let cases = cases("encapsulationKeyCheck");
    assert_eq!(cases.len(), 10);
    for case in &cases {
        assert_eq!(
            encapsulation_key(&case.hex("ek")).is_some(),
            case.passes(),
            "tcId {}",
            case.tc_id
        );
    }
}

/// The decapsulation-key check of FIPS 203 §7.3.
#[test]
fn decapsulation_key_check_matches_acvp() {
    let cases = cases("decapsulationKeyCheck");
    assert_eq!(cases.len(), 10);
    for case in &cases {
        assert_eq!(
            decapsulation_key(&case.hex("dk")).is_some(),
            case.passes(),
            "tcId {}",
            case.tc_id
        );
    }
}
