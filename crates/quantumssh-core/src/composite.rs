//! The composite signature `ssh-mldsa44-ed25519`
//! (`draft-ietf-sshm-composite-sigs-00` §4.1.1 and §4.2.2.1, RFC-0012):
//! ML-DSA-44 and Ed25519 sign one message representative, and a
//! signature is valid only when both halves verify.
//!
//! The host key signs with it (ADR-0047) and the user CA's certificate
//! signatures are checked with it (ADR-0050 §4). ML-DSA comes from
//! `ml-dsa` (ADR-0035), signing hedged with the OS RNG.

use ed25519_dalek::Signer as _;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Keypair as _, MlDsa44, Seed};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

/// Algorithm name (`draft-ietf-sshm-composite-sigs-00` §4.1.1).
pub const ALGORITHM: &str = "ssh-mldsa44-ed25519";

/// The composite's domain separator and label (`COMPSIG-MLDSA44-Ed25519-SHA512`,
/// `draft-ietf-lamps-pq-composite-sigs`). The label is also ML-DSA's
/// FIPS 204 context string.
const PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";
const LABEL: &[u8] = b"COMPSIG-MLDSA44-Ed25519-SHA512";

const MLDSA_PUBLIC_LEN: usize = 1312;
const MLDSA_SIGNATURE_LEN: usize = 2420;
const SEED_LEN: usize = 32;

/// `mldsa_pk[1312] ‖ ed25519_pk[32]`.
pub const PUBLIC_LEN: usize = MLDSA_PUBLIC_LEN + 32;
/// `mldsa_sig[2420] ‖ ed25519_sig[64]`.
pub const SIGNATURE_LEN: usize = MLDSA_SIGNATURE_LEN + 64;
/// The private key as OpenSSH stores it: `mldsa_seed[32] ‖ ed25519_seed[32]`.
pub const SEEDS_LEN: usize = 2 * SEED_LEN;

/// `M' = Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ SHA512(M)`. SSH signs with an
/// empty `ctx`, so `len(ctx)` is the single byte 0.
fn message_representative(message: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(PREFIX.len() + LABEL.len() + 1 + 64);
    m.extend_from_slice(PREFIX);
    m.extend_from_slice(LABEL);
    m.push(0);
    m.extend_from_slice(&Sha512::digest(message));
    m
}

/// Signing failed: the OS RNG did not deliver the per-signature
/// randomness, or ML-DSA's rejection sampling ran out of attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignError;

/// A composite signing key: both halves zeroize on drop (RFC-0012
/// §Key material).
pub struct SigningKey {
    mldsa: ml_dsa::SigningKey<MlDsa44>,
    ed25519: ed25519_dalek::SigningKey,
    public: Box<[u8; PUBLIC_LEN]>,
}

impl SigningKey {
    /// Expands `mldsa_seed ‖ ed25519_seed` (FIPS 204 `KeyGen_internal`
    /// for the ML-DSA half).
    pub fn from_seeds(seeds: &[u8; SEEDS_LEN]) -> Self {
        let (mldsa_seed, ed25519_seed) = seeds.split_at(SEED_LEN);
        let mldsa_seed = Zeroizing::new(Seed::try_from(mldsa_seed).expect("32-byte half"));
        let ed25519_seed =
            Zeroizing::new(<[u8; SEED_LEN]>::try_from(ed25519_seed).expect("32-byte half"));
        let mldsa = ml_dsa::SigningKey::<MlDsa44>::from_seed(&mldsa_seed);
        let ed25519 = ed25519_dalek::SigningKey::from_bytes(&ed25519_seed);
        let mut public = Box::new([0u8; PUBLIC_LEN]);
        public[..MLDSA_PUBLIC_LEN].copy_from_slice(&mldsa.verifying_key().encode());
        public[MLDSA_PUBLIC_LEN..].copy_from_slice(ed25519.verifying_key().as_bytes());
        Self {
            mldsa,
            ed25519,
            public,
        }
    }

    /// `mldsa_pk ‖ ed25519_pk`.
    pub fn public_key(&self) -> &[u8; PUBLIC_LEN] {
        &self.public
    }

    /// Signs `message`: ML-DSA-44 hedged, with the label as context,
    /// then Ed25519, both over `M'`.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        let m = message_representative(message);
        let mldsa = self
            .mldsa
            .expanded_key()
            .sign_randomized(&m, LABEL, &mut getrandom::SysRng)
            .map_err(|_| SignError)?;
        let mut signature = Vec::with_capacity(SIGNATURE_LEN);
        signature.extend_from_slice(&mldsa.encode());
        signature.extend_from_slice(&self.ed25519.sign(&m).to_bytes());
        Ok(signature)
    }
}

/// A composite public key, ready to check signatures.
#[derive(Clone)]
pub struct VerifyingKey {
    mldsa: ml_dsa::VerifyingKey<MlDsa44>,
    ed25519: ed25519_dalek::VerifyingKey,
}

impl VerifyingKey {
    /// Parses `mldsa_pk ‖ ed25519_pk`. `None` when the length is wrong,
    /// the Ed25519 half is not a curve point, or it is small-order (weak)
    /// and would accept forged signatures.
    pub fn from_bytes(public: &[u8]) -> Option<Self> {
        if public.len() != PUBLIC_LEN {
            return None;
        }
        let (mldsa, ed25519) = public.split_at(MLDSA_PUBLIC_LEN);
        let mldsa =
            ml_dsa::VerifyingKey::decode(&EncodedVerifyingKey::<MlDsa44>::try_from(mldsa).ok()?);
        let ed25519 =
            ed25519_dalek::VerifyingKey::from_bytes(&<[u8; 32]>::try_from(ed25519).ok()?).ok()?;
        if ed25519.is_weak() {
            return None;
        }
        Some(Self { mldsa, ed25519 })
    }

    /// Whether `signature` (`mldsa_sig ‖ ed25519_sig`) is valid for
    /// `message`: both halves must verify, over the same `M'`.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        if signature.len() != SIGNATURE_LEN {
            return false;
        }
        let (mldsa, ed25519) = signature.split_at(MLDSA_SIGNATURE_LEN);
        let Some(mldsa) = EncodedSignature::<MlDsa44>::try_from(mldsa)
            .ok()
            .and_then(|enc| ml_dsa::Signature::decode(&enc))
        else {
            return false;
        };
        let Ok(ed25519) = ed25519_dalek::Signature::from_slice(ed25519) else {
            return false;
        };
        let m = message_representative(message);
        self.mldsa.verify_with_context(&m, LABEL, &mldsa)
            && self.ed25519.verify_strict(&m, &ed25519).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_seeds(&[byte; SEEDS_LEN])
    }

    #[test]
    fn signs_and_verifies() {
        let signing = key(5);
        let verifying = VerifyingKey::from_bytes(signing.public_key()).unwrap();
        let signature = signing.sign(b"exchange hash").unwrap();
        assert_eq!(signature.len(), SIGNATURE_LEN);
        assert!(verifying.verify(b"exchange hash", &signature));
        assert!(!verifying.verify(b"another hash", &signature));
    }

    #[test]
    fn signing_is_hedged() {
        let signing = key(6);
        // The ML-DSA half takes fresh randomness each time; Ed25519 is
        // deterministic.
        let a = signing.sign(b"m").unwrap();
        let b = signing.sign(b"m").unwrap();
        assert_ne!(a[..MLDSA_SIGNATURE_LEN], b[..MLDSA_SIGNATURE_LEN]);
        assert_eq!(a[MLDSA_SIGNATURE_LEN..], b[MLDSA_SIGNATURE_LEN..]);
    }

    /// RFC-0012's invariant: one valid half is not a valid composite.
    #[test]
    fn a_signature_is_refused_unless_both_halves_verify() {
        let signing = key(7);
        let other = key(8);
        let verifying = VerifyingKey::from_bytes(signing.public_key()).unwrap();
        let good = signing.sign(b"m").unwrap();
        let foreign = other.sign(b"m").unwrap();

        let mut only_mldsa = good.clone();
        only_mldsa[MLDSA_SIGNATURE_LEN..].copy_from_slice(&foreign[MLDSA_SIGNATURE_LEN..]);
        assert!(!verifying.verify(b"m", &only_mldsa));

        let mut only_ed25519 = good.clone();
        only_ed25519[..MLDSA_SIGNATURE_LEN].copy_from_slice(&foreign[..MLDSA_SIGNATURE_LEN]);
        assert!(!verifying.verify(b"m", &only_ed25519));

        assert!(!verifying.verify(b"m", &good[..SIGNATURE_LEN - 1]));
    }

    /// Each half signs `M'`, not the message: an Ed25519 signature over
    /// the bare message does not verify.
    #[test]
    fn the_halves_sign_the_message_representative() {
        let signing = key(9);
        let verifying = VerifyingKey::from_bytes(signing.public_key()).unwrap();
        let mut signature = signing.sign(b"m").unwrap();
        let bare = signing.ed25519.sign(b"m").to_bytes();
        signature[MLDSA_SIGNATURE_LEN..].copy_from_slice(&bare);
        assert!(!verifying.verify(b"m", &signature));

        let m = message_representative(b"m");
        assert_eq!(m.len(), 32 + 30 + 1 + 64);
        assert!(m.starts_with(b"CompositeAlgorithmSignatures2025COMPSIG-MLDSA44-Ed25519-SHA512\0"));
    }

    #[test]
    fn public_keys_of_the_wrong_shape_are_refused() {
        let public = *key(10).public_key();
        assert!(VerifyingKey::from_bytes(&public[..PUBLIC_LEN - 1]).is_none());
        // The identity point is small-order.
        let mut weak = public;
        weak[MLDSA_PUBLIC_LEN..].copy_from_slice(&[
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);
        assert!(VerifyingKey::from_bytes(&weak).is_none());
    }
}
