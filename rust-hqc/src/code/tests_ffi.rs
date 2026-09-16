use crate::code::reed_muller::{RmCodeword, RmExpandedCdw, MULTIPLICITY};
use crate::code::reed_solomon::gf_mod;
use crate::parameters::{
    PARAM_DELTA, PARAM_FFT, PARAM_GF_MUL_ORDER, PARAM_N1, VEC_K_SIZE_64, VEC_N1N2_SIZE_64,
    VEC_N1_SIZE_64, VEC_N_SIZE_BYTES,
};
use rand::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

use crate::ffi::hqc1::{code_decode, code_encode, compute_elp, compute_error_values, compute_roots, compute_syndromes, compute_z_poly, correct_errors, encode, expand_and_sum, find_peaks, gf_mod_c, hadamard, reed_muller_decode, reed_muller_encode, reed_solomon_decode, reed_solomon_encode};

/// Safe wrapper around the C `encode` function.
pub fn encode_ref(message: i32) -> RmCodeword {
    let mut word = RmCodeword::zeroed();
    unsafe {
        encode(&mut word as *mut RmCodeword, message);
    }
    word
}

/// Safe wrapper around the C `hadamard` function.
pub fn hadamard_ref(src: &mut RmExpandedCdw, dst: &mut RmExpandedCdw) {
    unsafe {
        hadamard(src as *mut RmExpandedCdw, dst as *mut RmExpandedCdw);
    }
}

/// Safe wrapper around the C `expand_and_sum` function.
pub fn expand_and_sum_ref(dest: &mut RmExpandedCdw, src: &[RmCodeword; MULTIPLICITY]) {
    unsafe {
        expand_and_sum(dest as *mut RmExpandedCdw, src.as_ptr());
    }
}

/// Safe wrapper around the C `find_peaks` function.
pub fn find_peaks_ref(transform: &mut RmExpandedCdw) -> i32 {
    unsafe { find_peaks(transform as *mut RmExpandedCdw) }
}

/// Safe wrapper around the C `reed_muller_encode` function.
pub fn reed_muller_encode_ref(msg: &[u64; VEC_N1_SIZE_64]) -> [u64; VEC_N1N2_SIZE_64] {
    let mut cdw = [0u64; VEC_N1N2_SIZE_64];
    unsafe {
        reed_muller_encode(cdw.as_mut_ptr(), msg.as_ptr());
    }
    cdw
}

/// Safe wrapper around the C `reed_muller_decode` function.
pub fn reed_muller_decode_ref(cdw: &[u64; VEC_N1N2_SIZE_64]) -> [u64; VEC_N1_SIZE_64] {
    let mut msg = [0u64; VEC_N1_SIZE_64];
    unsafe {
        reed_muller_decode(msg.as_mut_ptr(), cdw.as_ptr());
    }
    msg
}

/// Safe wrapper around the C `mod` function.
// pub fn gf_mod_ref(i: u16, modulus: u16) -> u16 {
//     unsafe { gf_mod_c(i, modulus) }
// }

/// Safe wrapper around the C `reed_solomon_encode` function.
pub fn reed_solomon_encode_ref(msg: &[u64]) -> Vec<u64> {
    let mut cdw = vec![0u64; VEC_N1_SIZE_64];
    unsafe {
        reed_solomon_encode(cdw.as_mut_ptr(), msg.as_ptr());
    }
    cdw
}

/// Safe wrapper around the C `compute_syndromes` function.
pub fn compute_syndromes_ref(cdw: &[u8]) -> [u16; 2 * PARAM_DELTA] {
    let mut cdw_copy = cdw.to_vec(); // C signature takes non-const uint8_t*
    let mut syndromes = [0u16; 2 * PARAM_DELTA];
    unsafe {
        compute_syndromes(syndromes.as_mut_ptr(), cdw_copy.as_mut_ptr());
    }
    syndromes
}

/// Safe wrapper around the C `compute_elp` function.
pub fn compute_elp_ref(syndromes: &[u16]) -> ([u16; PARAM_DELTA + 1], u16) {
    let mut sigma = [0u16; PARAM_DELTA + 1];
    let deg_sigma = unsafe { compute_elp(sigma.as_mut_ptr(), syndromes.as_ptr()) };
    (sigma, deg_sigma)
}

/// Safe wrapper around the C `compute_roots` function.
pub fn compute_roots_ref(sigma: &[u16], error_len: usize) -> Vec<u8> {
    let mut sigma_copy = sigma.to_vec(); // C signature takes non-const uint16_t*
    let mut error = vec![0u8; error_len];
    unsafe {
        compute_roots(error.as_mut_ptr(), sigma_copy.as_mut_ptr());
    }
    error
}

/// Safe wrapper around the C `compute_z_poly` function.
pub fn compute_z_poly_ref(sigma: &[u16], degree: u16, syndromes: &[u16]) -> [u16; PARAM_DELTA + 1] {
    let mut z = [0u16; PARAM_DELTA + 1];
    unsafe {
        compute_z_poly(z.as_mut_ptr(), sigma.as_ptr(), degree, syndromes.as_ptr());
    }
    z
}

/// Safe wrapper around the C `compute_error_values` function.
pub fn compute_error_values_ref(z: &[u16], error: &[u8]) -> Vec<u16> {
    let mut error_values = vec![0u16; PARAM_N1];
    unsafe {
        compute_error_values(error_values.as_mut_ptr(), z.as_ptr(), error.as_ptr());
    }
    error_values
}

/// Safe wrapper around the C `correct_errors` function.
pub fn correct_errors_ref(cdw: &[u8], error_values: &[u16]) -> Vec<u8> {
    let mut cdw_copy = cdw.to_vec();
    unsafe {
        correct_errors(cdw_copy.as_mut_ptr(), error_values.as_ptr());
    }
    cdw_copy
}

/// Safe wrapper around the C `reed_solomon_decode` function.
pub fn reed_solomon_decode_ref(cdw: &[u64]) -> Vec<u64> {
    let mut cdw_copy = cdw.to_vec(); // C signature takes non-const uint64_t*
    let mut msg = vec![0u64; VEC_K_SIZE_64];
    unsafe {
        reed_solomon_decode(msg.as_mut_ptr(), cdw_copy.as_mut_ptr());
    }
    msg
}

/// Safe wrapper around the C `code_encode` function.
pub fn code_encode_ref(m: &[u64]) -> Vec<u64> {
    let mut em = vec![0u64; VEC_N1N2_SIZE_64];
    unsafe {
        code_encode(em.as_mut_ptr(), m.as_ptr());
    }
    em
}

/// Safe wrapper around the C `code_decode` function.
pub fn code_decode_ref(em: &[u64]) -> Vec<u64> {
    let mut m = vec![0u64; VEC_K_SIZE_64];
    unsafe {
        code_decode(m.as_mut_ptr(), em.as_ptr());
    }
    m
}

#[test]
fn test_rm_encode() {
    let mut rng = StdRng::seed_from_u64(4);
    const TEST_ROUNDS: u32 = 100;
    for _i in 0..=TEST_ROUNDS {
        let msg = rng.random::<i32>();
        let w = crate::code::reed_muller::encode(msg);
        let w_ref = encode_ref(msg);
        assert_eq!(
            w.u32, w_ref.u32,
            "Rust and C must agree for message {}",
            msg
        );
    }
}

#[test]
fn test_hadamard() {
    let mut src = [0i16; 128];
    let mut src_ref = [0i16; 128];
    for i in 0..128 {
        src[i] = i as i16;
        src_ref[i] = i as i16;
    }
    let mut dst = [0i16; 128];
    let mut dst_ref = [0i16; 128];

    crate::code::reed_muller::hadamard(&mut src, &mut dst);
    hadamard_ref(&mut src_ref, &mut dst_ref);

    assert_eq!(
        dst, dst_ref,
        "Rust and C implementations must produce identical results"
    );
}

#[test]
fn test_expand_and_sum() {
    let mut src = [RmCodeword::zeroed(); MULTIPLICITY];
    for i in 0..MULTIPLICITY {
        src[i].u32 = [0xDEADBEEFu32; 4];
    }
    let mut dest = [0i16; 128];
    let mut dest_ref = [0i16; 128];

    crate::code::reed_muller::expand_and_sum(&mut dest, &src);
    expand_and_sum_ref(&mut dest_ref, &src);

    assert_eq!(
        dest, dest_ref,
        "Rust and C implementations must produce identical results"
    );
}

#[test]
fn test_find_peaks() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);

    for i in 0..TEST_ROUNDS {
        // Generate random i16 values for transform
        let mut transform: RmExpandedCdw =
            std::array::from_fn(|_| rng.random_range(-32768..=32767));

        assert_eq!(
            crate::code::reed_muller::find_peaks(&transform),
            find_peaks_ref(&mut transform),
            "Rust and C must agree at iteration {}",
            i
        );
    }
}

#[test]
fn test_reed_muller_encode() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);

    for i in 0..TEST_ROUNDS {
        let msg: [u64; VEC_N1_SIZE_64] = std::array::from_fn(|_| rng.random_range(0..=u64::MAX));

        let cdw = crate::code::reed_muller::reed_muller_encode(&msg);
        let cdw_ref = reed_muller_encode_ref(&msg);

        assert_eq!(cdw, cdw_ref, "Rust and C must agree at iteration {}", i);
    }
}

#[test]
fn test_reed_muller_decode() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let msg: [u64; VEC_N1_SIZE_64] = std::array::from_fn(|_| rng.random_range(0..=u64::MAX));
        let cdw = crate::code::reed_muller::reed_muller_encode(&msg);

        let decoded = crate::code::reed_muller::reed_muller_decode(&cdw);
        let decoded_ref = reed_muller_decode_ref(&cdw);

        assert_eq!(
            decoded, decoded_ref,
            "Rust and C decode must agree at iteration {}",
            i
        );
    }
}

#[test]
fn test_gf_mod() {
    let modulus = PARAM_GF_MUL_ORDER as u16;
    for i in 0..(2 * modulus) {
        let r = crate::code::reed_solomon::gf_mod(i, modulus);
        let r_ref = i % modulus; //gf_mod_ref(i, modulus);
        assert_eq!(
            r, r_ref,
            "Rust and C must agree for i={}, modulus={}",
            i, modulus
        );
    }
}

#[test]
fn test_reed_solomon_encode() {
    let mut rng = StdRng::seed_from_u64(4u64);
    const TEST_ROUNDS: u64 = 100;
    for i in 0..TEST_ROUNDS {
        let msg: [u64; VEC_K_SIZE_64] = std::array::from_fn(|_| rng.random_range(0..=u64::MAX));
        let cdw = crate::code::reed_solomon::reed_solomon_encode(&msg);
        let cdw_ref = reed_solomon_encode_ref(&msg);

        assert_eq!(cdw, cdw_ref, "Rust and C must agree at iteration {}", i);
    }
}

#[test]
fn test_compute_syndrome() {
    let mut rng = StdRng::seed_from_u64(4u64);
    const TEST_ROUNDS: u64 = 100;
    for i in 0..TEST_ROUNDS {
        let cdw: Vec<u8> = (0..PARAM_N1)
            .map(|_| rng.random_range(0..=u8::MAX))
            .collect();

        let syndromes = crate::code::reed_solomon::compute_syndromes(&cdw);
        let syndromes_ref = compute_syndromes_ref(&cdw);

        assert_eq!(
            syndromes, syndromes_ref,
            "Rust and C must agree at iteration {}",
            i
        );
    }
}

#[test]
fn test_compute_elp() {
    let mut rng = StdRng::seed_from_u64(4u64);
    const TEST_ROUNDS: u64 = 100;
    for i in 0..TEST_ROUNDS {
        let syndromes: Vec<u16> = (0..2 * PARAM_DELTA)
            .map(|_| rng.random_range(0..=u16::MAX))
            .collect();

        let (sigma, deg) = crate::code::reed_solomon::compute_elp(&syndromes);
        let (sigma_ref, deg_ref) = compute_elp_ref(&syndromes);

        assert_eq!(sigma, sigma_ref, "sigma mismatch at iteration {}", i);
        assert_eq!(deg, deg_ref, "deg_sigma mismatch at iteration {}", i);
    }
}

#[test]
fn test_compute_roots() {
    let mut rng = StdRng::seed_from_u64(4u64);
    const TEST_ROUNDS: u64 = 100;
    let error_len = VEC_N_SIZE_BYTES;

    for i in 0..TEST_ROUNDS {
        let sigma: Vec<u16> = (0..(1usize << PARAM_FFT))
            .map(|_| rng.random_range(0..=u16::MAX))
            .collect();

        let mut error_rs = vec![0u8; error_len];
        crate::code::reed_solomon::compute_roots(&mut error_rs, &sigma);

        let error_ref = compute_roots_ref(&sigma, error_len);

        assert_eq!(
            error_rs, error_ref,
            "Rust and C must agree at iteration {}",
            i
        );
    }
}

#[test]
fn test_compute_z_poly() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let sigma: Vec<u16> = (0..(1usize << PARAM_FFT))
            .map(|_| rng.random_range(0..=u16::MAX))
            .collect();
        let syndromes: Vec<u16> = (0..2 * PARAM_DELTA)
            .map(|_| rng.random_range(0..=u16::MAX))
            .collect();
        let degree: u16 = rng.random_range(0..=PARAM_DELTA as u16);

        let z = crate::code::reed_solomon::compute_z_poly(&sigma, degree, &syndromes);
        let z_ref = compute_z_poly_ref(&sigma, degree, &syndromes);

        assert_eq!(z, z_ref, "Rust and C must agree at iteration {}", i);
    }
}

#[test]
fn test_compute_error_values() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let z: Vec<u16> = (0..PARAM_DELTA + 1)
            .map(|_| rng.random_range(0..=u16::MAX))
            .collect();
        let error: Vec<u8> = (0..PARAM_N1)
            .map(|_| rng.random_range(0..=u8::MAX))
            .collect();

        let ev = crate::code::reed_solomon::compute_error_values(&z, &error);
        let ev_ref = compute_error_values_ref(&z, &error);

        assert_eq!(ev, ev_ref, "Rust and C must agree at iteration {}", i);
    }
}

#[test]
fn test_correct_errors() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let cdw: Vec<u8> = (0..PARAM_N1)
            .map(|_| rng.random_range(0..=u8::MAX))
            .collect();
        let error_values: Vec<u16> = (0..PARAM_N1)
            .map(|_| rng.random_range(0..=u16::MAX))
            .collect();

        let mut cdw_rs = cdw.clone();
        crate::code::reed_solomon::correct_errors(&mut cdw_rs, &error_values);

        let cdw_ref = correct_errors_ref(&cdw, &error_values);

        assert_eq!(cdw_rs, cdw_ref, "Rust and C must agree at iteration {}", i);
    }
}

#[test]
fn test_reed_solomon_decode() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let msg_in: [u64; VEC_K_SIZE_64] = std::array::from_fn(|_| rng.random_range(0..=u64::MAX));
        let cdw = crate::code::reed_solomon::reed_solomon_encode(&msg_in);

        let msg_rs = crate::code::reed_solomon::reed_solomon_decode(&cdw);
        let msg_ref = reed_solomon_decode_ref(&cdw);

        assert_eq!(msg_rs, msg_ref, "Rust and C must agree at iteration {}", i);
    }
}

#[test]
fn test_code_encode() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let m: [u64; VEC_K_SIZE_64] = std::array::from_fn(|_| rng.random_range(0..=u64::MAX));

        let em = crate::code::code_encode(&m);
        let em_ref = code_encode_ref(&m);

        assert_eq!(em, em_ref, "Rust and C must agree at iteration {}", i);
    }
}

#[test]
fn test_code_decode() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let m_in: [u64; VEC_K_SIZE_64] = std::array::from_fn(|_| rng.random_range(0..=u64::MAX));
        let em = crate::code::code_encode(&m_in);

        let m = crate::code::code_decode(&em);
        let m_ref = code_decode_ref(&em);

        assert_eq!(m, m_ref, "Rust and C must agree at iteration {}", i);
    }
}
