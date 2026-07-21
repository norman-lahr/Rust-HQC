use crate::parameters::{PARAM_SECURITY_BYTES, SALT_BYTES, SEED_BYTES};
use rand::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

unsafe extern "C" {
    fn hash_i(output: *mut u8, seed: *const u8);
    fn hash_g(output: *mut u8, hash_ek_kem: *const u8, m: *const u8, salt: *const u8);
}

/// Safe wrapper around the C hash_i function
fn hash_i_ref(seed: &[u8]) -> [u8; 64] {
    let mut output = [0u8; 64];
    unsafe {
        hash_i(output.as_mut_ptr(), seed.as_ptr());
    }
    output
}

/// Safe wrapper around the C `hash_g` function.
pub fn hash_g_ref(
    hash_ek_kem: &[u8; SEED_BYTES],
    m: &[u8; PARAM_SECURITY_BYTES],
    salt: &[u8; SALT_BYTES],
) -> [u8; 64] {
    let mut output = [0u8; 64];
    unsafe {
        hash_g(
            output.as_mut_ptr(),
            hash_ek_kem.as_ptr(),
            m.as_ptr(),
            salt.as_ptr(),
        );
    }
    output
}

#[test]
fn test_hash_i() {
    let seed = b"DEADBEEFDEADBEEFDEADBEEFDEADBEEF";
    let digest = crate::symmetric::hash_i(seed);
    let digest_ref = hash_i_ref(seed);
    assert_eq!(digest, digest_ref, "Both digest should be equal");
}

#[test]
fn test_rust_matches_ref() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let hash_ek_kem: [u8; SEED_BYTES] = std::array::from_fn(|_| rng.random_range(0..=u8::MAX));
        let m: [u8; PARAM_SECURITY_BYTES] = std::array::from_fn(|_| rng.random_range(0..=u8::MAX));
        let salt: [u8; SALT_BYTES] = std::array::from_fn(|_| rng.random_range(0..=u8::MAX));

        let output = crate::symmetric::hash_g(&hash_ek_kem, &m, &salt);
        let output_ref = hash_g_ref(&hash_ek_kem, &m, &salt);

        assert_eq!(
            output, output_ref,
            "Rust and C must agree at iteration {}",
            i
        );
    }
}
