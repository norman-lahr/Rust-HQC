use crate::kem::CiphertextKem;
use crate::parameters::{PARAM_SECURITY_BYTES, PUBLIC_KEY_BYTES, SALT_BYTES, SEED_BYTES};
use crate::pke::CiphertextPke;
use rand::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

unsafe extern "C" {
    fn hash_i(output: *mut u8, seed: *const u8);
    fn hash_g(output: *mut u8, hash_ek_kem: *const u8, m: *const u8, salt: *const u8);
    fn hash_h(output: *mut u8, ek_kem: *const u8);
    fn hash_j(
        output: *mut u8,
        hash_ek_kem: *const u8,
        sigma: *const u8,
        c_kem: *const CiphertextKem,
    );
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

/// Safe wrapper around the C `hash_h` function.
pub fn hash_h_ref(ek_kem: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    unsafe {
        hash_h(output.as_mut_ptr(), ek_kem.as_ptr());
    }
    output
}

/// Safe wrapper around the C `hash_j` function.
pub fn hash_j_ref(
    hash_ek_kem: &[u8; SEED_BYTES],
    sigma: &[u8; PARAM_SECURITY_BYTES],
    c_kem: &CiphertextKem,
) -> [u8; 32] {
    let mut output = [0u8; 32];
    unsafe {
        hash_j(
            output.as_mut_ptr(),
            hash_ek_kem.as_ptr(),
            sigma.as_ptr(),
            c_kem as *const CiphertextKem,
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
fn test_hash_g() {
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

#[test]
fn test_hash_h() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let ek_kem: Vec<u8> = (0..PUBLIC_KEY_BYTES)
            .map(|_| rng.random_range(0..=u8::MAX))
            .collect();

        let output_rs = crate::symmetric::hash_h(&ek_kem);
        let output_ref = hash_h_ref(&ek_kem);

        assert_eq!(
            output_rs, output_ref,
            "Rust and C must agree at iteration {}",
            i
        );
    }
}

#[test]
fn test_hash_j() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let hash_ek_kem: [u8; SEED_BYTES] = std::array::from_fn(|_| rng.random_range(0..=u8::MAX));
        let sigma: [u8; PARAM_SECURITY_BYTES] =
            std::array::from_fn(|_| rng.random_range(0..=u8::MAX));

        let c_kem = CiphertextKem {
            c_pke: CiphertextPke {
                u: std::array::from_fn(|_| rng.random_range(0..=u64::MAX)),
                v: std::array::from_fn(|_| rng.random_range(0..=u64::MAX)),
            },
            salt: std::array::from_fn(|_| rng.random_range(0..=u8::MAX)),
        };

        let output = crate::symmetric::hash_j(&hash_ek_kem, &sigma, &c_kem);
        let output_ref = hash_j_ref(&hash_ek_kem, &sigma, &c_kem);

        assert_eq!(
            output, output_ref,
            "Rust and C must agree at iteration {}",
            i
        );
    }
}
