use rand::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

use crate::parameters::{PUBLIC_KEY_BYTES, SECRET_KEY_BYTES};
// use crate::symmetric::prng_init;

unsafe extern "C" {
    fn prng_init(entropy_input: *mut u8, personalization_string: *mut u8, enlen: u32, perlen: u32);
    fn crypto_kem_keypair(ek_kem: *mut u8, dk_kem: *mut u8) -> i32;
}

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

// use serial_test::serial; // C side uses global PRNG state

#[test]
// #[serial]
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
