use rand::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

use crate::parameters::{
    CIPHERTEXT_BYTES, PUBLIC_KEY_BYTES, SECRET_KEY_BYTES, SHARED_SECRET_BYTES,
};
// use crate::symmetric::prng_init;

use crate::ffi::hqc1::{crypto_kem_dec, crypto_kem_enc, crypto_kem_keypair, prng_init};

/// Safe wrapper around the C `prng_init` function.
pub fn prng_init_ref(entropy_input: &[u8], personalization_string: &[u8]) {
    let mut entropy_copy = entropy_input.to_vec();
    let mut pers_copy = personalization_string.to_vec();
    unsafe {
        prng_init(
            entropy_copy.as_mut_ptr(),
            pers_copy.as_mut_ptr(),
            entropy_input.len() as u32,
            personalization_string.len() as u32,
        );
    }
}

/// Safe wrapper around the C `crypto_kem_keypair` function.
///
/// Note: the C implementation relies on the global `prng_init`/
/// `prng_get_bytes` state, so `prng_init_ref` must be called (with the
/// same entropy/personalization used to seed the Rust `prng_reader`)
/// before invoking this wrapper for a meaningful cross-validation.
pub fn crypto_kem_keypair_ref() -> (Vec<u8>, Vec<u8>) {
    let mut ek_kem = vec![0u8; PUBLIC_KEY_BYTES];
    let mut dk_kem = vec![0u8; SECRET_KEY_BYTES];
    unsafe {
        crypto_kem_keypair(ek_kem.as_mut_ptr(), dk_kem.as_mut_ptr());
    }
    (ek_kem, dk_kem)
}

/// Safe wrapper around the C `crypto_kem_enc` function.
///
/// Note: the C implementation relies on the global `prng_init`/
/// `prng_get_bytes` state, so `prng_init_ref` must be called (with the
/// same entropy/personalization used to seed the Rust `prng_reader`)
/// before invoking this wrapper for a meaningful cross-validation.
pub fn crypto_kem_enc_ref(ek_kem: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut c_kem = vec![0u8; CIPHERTEXT_BYTES];
    let mut k = vec![0u8; SHARED_SECRET_BYTES];
    unsafe {
        crypto_kem_enc(c_kem.as_mut_ptr(), k.as_mut_ptr(), ek_kem.as_ptr());
    }
    (c_kem, k)
}

/// Safe wrapper around the C `crypto_kem_dec` function.
pub fn crypto_kem_dec_ref(c_kem: &[u8], dk_kem: &[u8]) -> Vec<u8> {
    let mut k_prime = vec![0u8; SHARED_SECRET_BYTES];
    unsafe {
        crypto_kem_dec(k_prime.as_mut_ptr(), c_kem.as_ptr(), dk_kem.as_ptr());
    }
    k_prime
}

use serial_test::serial; // C side uses global PRNG state

#[test]
#[serial]
fn test_kem_keygen() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let entropy: Vec<u8> = (0..32).map(|_| rng.random_range(0..=u8::MAX)).collect();
        let pers: Vec<u8> = (0..16).map(|_| rng.random_range(0..=u8::MAX)).collect();

        // Seed both PRNGs identically
        let mut prng_reader = crate::symmetric::prng_init(&entropy, &pers);
        prng_init_ref(&entropy, &pers);

        let (ek_rs, dk_rs) = crate::kem::crypto_kem_keypair(&mut prng_reader);
        let (ek_ref, dk_ref) = crypto_kem_keypair_ref();

        assert_eq!(ek_rs, ek_ref, "ek_kem mismatch at iteration {}", i);
        assert_eq!(dk_rs, dk_ref, "dk_kem mismatch at iteration {}", i);
    }
}

#[test]
#[serial]
fn test_kem_enc() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let entropy: Vec<u8> = (0..32).map(|_| rng.random_range(0..=u8::MAX)).collect();
        let pers: Vec<u8> = (0..16).map(|_| rng.random_range(0..=u8::MAX)).collect();

        // Seed both PRNGs identically
        // let prng_reader = crate::symmetric::prng_init(&entropy, &pers);
        // prng_init_ref(&entropy, &pers);

        let mut kg_reader = crate::symmetric::prng_init(&entropy, &pers);
        let (ek_kem, _dk_kem) = crate::kem::crypto_kem_keypair(&mut kg_reader);

        prng_init_ref(&entropy, &pers);
        let (ek_kem_ref, _dk_kem_ref) = crypto_kem_keypair_ref();
        assert_eq!(ek_kem, ek_kem_ref, "keypair mismatch at iteration {}", i);

        // Re-seed for the enc step itself
        let mut enc_reader = crate::symmetric::prng_init(&entropy, &pers);
        prng_init_ref(&entropy, &pers);

        let (c_kem_rs, k_rs) = crate::kem::crypto_kem_enc(&mut enc_reader, &ek_kem);
        let (c_kem_ref, k_ref) = crypto_kem_enc_ref(&ek_kem);

        assert_eq!(c_kem_rs, c_kem_ref, "c_kem mismatch at iteration {}", i);
        assert_eq!(k_rs, k_ref, "K mismatch at iteration {}", i);
    }
}

#[test]
#[serial]
fn test_kem_dec() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let entropy: Vec<u8> = (0..32).map(|_| rng.random_range(0..=u8::MAX)).collect();
        let pers: Vec<u8> = (0..16).map(|_| rng.random_range(0..=u8::MAX)).collect();

        // Set up matching keypair and ciphertext on both sides
        let mut kg_reader = crate::symmetric::prng_init(&entropy, &pers);
        prng_init_ref(&entropy, &pers);
        let (ek_kem, dk_kem) = crate::kem::crypto_kem_keypair(&mut kg_reader);
        let (ek_kem_ref, dk_kem_ref) = {
            prng_init_ref(&entropy, &pers);
            crypto_kem_keypair_ref()
        };
        assert_eq!(ek_kem, ek_kem_ref);
        assert_eq!(dk_kem, dk_kem_ref);

        let mut enc_reader = crate::symmetric::prng_init(&entropy, &pers);
        prng_init_ref(&entropy, &pers);
        let (c_kem, _k) = crate::kem::crypto_kem_enc(&mut enc_reader, &ek_kem);
        let (c_kem_ref, _k_ref) = {
            prng_init_ref(&entropy, &pers);
            crypto_kem_enc_ref(&ek_kem)
        };
        assert_eq!(c_kem, c_kem_ref);

        // The actual test: dec has no PRNG dependency
        let k_prime_rs = crate::kem::crypto_kem_dec(&c_kem, &dk_kem);
        let k_prime_ref = crypto_kem_dec_ref(&c_kem, &dk_kem);

        assert_eq!(
            k_prime_rs, k_prime_ref,
            "Rust and C must agree at iteration {}",
            i
        );
    }
}

#[test]
#[serial]
fn test_kem_roundtrip() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let entropy: Vec<u8> = (0..32).map(|_| rng.random_range(0..=u8::MAX)).collect();
        let pers: Vec<u8> = (0..16).map(|_| rng.random_range(0..=u8::MAX)).collect();

        let mut kg_reader = crate::symmetric::prng_init(&entropy, &pers);
        let (ek_kem, dk_kem) = crate::kem::crypto_kem_keypair(&mut kg_reader);

        let mut enc_reader = crate::symmetric::prng_init(&entropy, &pers);
        let (c_kem, k) = crate::kem::crypto_kem_enc(&mut enc_reader, &ek_kem);

        let k_prime = crate::kem::crypto_kem_dec(&c_kem, &dk_kem);

        assert_eq!(
            k, k_prime,
            "decapsulated key must match encapsulated key at iteration {}",
            i
        );
    }
}
