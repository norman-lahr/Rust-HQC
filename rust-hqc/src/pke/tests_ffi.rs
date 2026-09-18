use crate::parameters::{HQC_1, SEED_BYTES};
use crate::pke::CiphertextPke;
use rand::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

use crate::ffi::hqc1::{hqc_pke_decrypt, hqc_pke_encrypt, hqc_pke_keygen};

/// Safe wrapper around the C `hqc_pke_keygen` function.
pub fn hqc_pke_keygen_ref(p: &crate::parameters::HqcParameters, seed: &[u8; SEED_BYTES]) -> (Vec<u8>, Vec<u8>) {
    let mut seed_copy = *seed; // C signature takes non-const uint8_t*
    let mut ek_pke = vec![0u8; SEED_BYTES + p.vec_n_size_bytes];
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
pub fn hqc_pke_encrypt_ref(
    p: &crate::parameters::HqcParameters,
    ek_pke: &[u8],
    m: &[u64],
    theta: &[u8; SEED_BYTES],
) -> CiphertextPke {
    // The C side expects one contiguous `u64` array holding u followed by v.
    // `CiphertextPke` is no longer `#[repr(C)]` with inline arrays — its
    // fields are `Vec`s — so casting the struct pointer would hand C the Vec
    // headers instead of the data. Marshal through a flat buffer and split.
    let mut flat = vec![0u64; 2 * p.vec_n_size_64];
    unsafe {
        hqc_pke_encrypt(
            flat.as_mut_ptr(),
            ek_pke.as_ptr(),
            m.as_ptr(),
            theta.as_ptr(),
        );
    }
    let v = flat.split_off(p.vec_n_size_64);
    CiphertextPke { u: flat, v }
}

/// Safe wrapper around the C `hqc_pke_decrypt` function.
pub fn hqc_pke_decrypt_ref(p: &crate::parameters::HqcParameters, dk_pke: &[u8; SEED_BYTES], c_pke: &CiphertextPke) -> Vec<u64> {
    let mut m = vec![0u64; p.vec_k_size_64];
    // Flatten u ++ v for the C side; see hqc_pke_encrypt_ref.
    let mut flat = Vec::with_capacity(2 * p.vec_n_size_64);
    flat.extend_from_slice(&c_pke.u);
    flat.extend_from_slice(&c_pke.v);
    unsafe {
        hqc_pke_decrypt(m.as_mut_ptr(), dk_pke.as_ptr(), flat.as_ptr());
    }
    m
}

#[test]
fn test_hqc_pke_keygen() {
    let p = &HQC_1;
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let seed: [u8; SEED_BYTES] = std::array::from_fn(|_| rng.random_range(0..=u8::MAX));

        let (ek, dk) = crate::pke::hqc_pke_keygen(p, &seed);
        let (ek_ref, dk_ref) = hqc_pke_keygen_ref(p, &seed);

        assert_eq!(ek, ek_ref, "ek_pke mismatch at iteration {}", i);
        assert_eq!(dk, dk_ref, "dk_pke mismatch at iteration {}", i);
    }
}

#[test]
fn test_hqc_pke_encrypt() {
    let p = &HQC_1;
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let seed: [u8; SEED_BYTES] = std::array::from_fn(|_| rng.random_range(0..=u8::MAX));
        let (ek_pke, _dk_pke) = crate::pke::hqc_pke_keygen(p, &seed);

        let m: Vec<u64> = (0..p.vec_k_size_64).map(|_| rng.random_range(0..=u64::MAX)).collect();
        let theta: [u8; SEED_BYTES] = std::array::from_fn(|_| rng.random_range(0..=u8::MAX));

        let c_rs = crate::pke::hqc_pke_encrypt(p, &ek_pke, &m, &theta);
        let c_ref = hqc_pke_encrypt_ref(p, &ek_pke, &m, &theta);

        assert_eq!(c_rs, c_ref, "Rust and C must agree at iteration {}", i);
    }
}

#[cfg(test)]
#[test]
fn test_hqc_pke_decrypt() {
    let p = &HQC_1;
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let seed: [u8; SEED_BYTES] = std::array::from_fn(|_| rng.random_range(0..=u8::MAX));
        let (ek_pke, dk_pke) = crate::pke::hqc_pke_keygen(p, &seed);

        let m: Vec<u64> = (0..p.vec_k_size_64).map(|_| rng.random_range(0..=u64::MAX)).collect();
        let theta: [u8; SEED_BYTES] = std::array::from_fn(|_| rng.random_range(0..=u8::MAX));

        let c_pke = crate::pke::hqc_pke_encrypt(p, &ek_pke, &m, &theta);

        let dk_pke_arr: [u8; SEED_BYTES] = dk_pke.try_into().unwrap();

        let m_rs = crate::pke::hqc_pke_decrypt(p, &dk_pke_arr, &c_pke);
        let m_ref = hqc_pke_decrypt_ref(p, &dk_pke_arr, &c_pke);

        assert_eq!(m_rs, m_ref, "Rust and C must agree at iteration {}", i);
    }
}
