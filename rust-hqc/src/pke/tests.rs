use crate::parameters::{SEED_BYTES, VEC_K_SIZE_64, VEC_N_SIZE_BYTES};
use crate::pke::CiphertextPke;
use rand::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

unsafe extern "C" {
    fn hqc_pke_keygen(ek_pke: *mut u8, dk_pke: *mut u8, seed: *mut u8);
    fn hqc_pke_encrypt(
        c_pke: *mut CiphertextPke,
        ek_pke: *const u8,
        m: *const u64,
        theta: *const u8,
    );
    fn hqc_pke_decrypt(m: *mut u64, dk_pke: *const u8, c_pke: *const CiphertextPke);
}

/// Safe wrapper around the C `hqc_pke_keygen` function.
pub fn hqc_pke_keygen_ref(seed: &[u8; SEED_BYTES]) -> (Vec<u8>, Vec<u8>) {
    let mut seed_copy = *seed; // C signature takes non-const uint8_t*
    let mut ek_pke = vec![0u8; SEED_BYTES + VEC_N_SIZE_BYTES];
    let mut dk_pke = vec![0u8; SEED_BYTES];
    unsafe {
        hqc_pke_keygen(
            ek_pke.as_mut_ptr(),
            dk_pke.as_mut_ptr(),
            seed_copy.as_mut_ptr(),
        );
    }
    (ek_pke, dk_pke)
}

/// Safe wrapper around the C `hqc_pke_encrypt` function.
pub fn hqc_pke_encrypt_ref(ek_pke: &[u8], m: &[u64], theta: &[u8; SEED_BYTES]) -> CiphertextPke {
    let mut c_pke = CiphertextPke::zeroed();
    unsafe {
        hqc_pke_encrypt(
            &mut c_pke as *mut CiphertextPke,
            ek_pke.as_ptr(),
            m.as_ptr(),
            theta.as_ptr(),
        );
    }
    c_pke
}

/// Safe wrapper around the C `hqc_pke_decrypt` function.
pub fn hqc_pke_decrypt_ref(dk_pke: &[u8; SEED_BYTES], c_pke: &CiphertextPke) -> Vec<u64> {
    let mut m = vec![0u64; VEC_K_SIZE_64];
    unsafe {
        hqc_pke_decrypt(
            m.as_mut_ptr(),
            dk_pke.as_ptr(),
            c_pke as *const CiphertextPke,
        );
    }
    m
}

#[test]
fn test_hqc_pke_keygen() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let seed: [u8; SEED_BYTES] = std::array::from_fn(|_| rng.random_range(0..=u8::MAX));

        let (ek, dk) = crate::pke::hqc_pke_keygen(&seed);
        let (ek_ref, dk_ref) = hqc_pke_keygen_ref(&seed);

        assert_eq!(ek, ek_ref, "ek_pke mismatch at iteration {}", i);
        assert_eq!(dk, dk_ref, "dk_pke mismatch at iteration {}", i);
    }
}

#[test]
fn test_hqc_pke_encrypt() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let seed: [u8; SEED_BYTES] = std::array::from_fn(|_| rng.random_range(0..=u8::MAX));
        let (ek_pke, _dk_pke) = crate::pke::hqc_pke_keygen(&seed);

        let m: [u64; VEC_K_SIZE_64] = std::array::from_fn(|_| rng.random_range(0..=u64::MAX));
        let theta: [u8; SEED_BYTES] = std::array::from_fn(|_| rng.random_range(0..=u8::MAX));

        let c_rs = crate::pke::hqc_pke_encrypt(&ek_pke, &m, &theta);
        let c_ref = hqc_pke_encrypt_ref(&ek_pke, &m, &theta);

        assert_eq!(c_rs, c_ref, "Rust and C must agree at iteration {}", i);
    }
}

#[cfg(test)]
#[test]
fn test_hqc_pke_decrypt() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let seed: [u8; SEED_BYTES] = std::array::from_fn(|_| rng.random_range(0..=u8::MAX));
        let (ek_pke, dk_pke) = crate::pke::hqc_pke_keygen(&seed);

        let m: [u64; VEC_K_SIZE_64] = std::array::from_fn(|_| rng.random_range(0..=u64::MAX));
        let theta: [u8; SEED_BYTES] = std::array::from_fn(|_| rng.random_range(0..=u8::MAX));

        let c_pke = crate::pke::hqc_pke_encrypt(&ek_pke, &m, &theta);

        let dk_pke_arr: [u8; SEED_BYTES] = dk_pke.try_into().unwrap();

        let m_rs = crate::pke::hqc_pke_decrypt(&dk_pke_arr, &c_pke);
        let m_ref = hqc_pke_decrypt_ref(&dk_pke_arr, &c_pke);

        assert_eq!(m_rs, m_ref, "Rust and C must agree at iteration {}", i);
    }
}
