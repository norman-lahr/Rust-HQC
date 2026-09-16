use crate::kem::CiphertextKem;
use crate::parameters::{
    SALT_BYTES, SEED_BYTES, VEC_N1N2_SIZE_BYTES, VEC_N_SIZE_64, VEC_N_SIZE_BYTES,
};
use crate::pke::CiphertextPke;
use rand::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

use crate::ffi::hqc1::{hqc_c_kem_from_string, hqc_c_kem_to_string, hqc_dk_pke_from_string, hqc_ek_pke_from_string};

/// Safe wrapper around the C `hqc_dk_pke_from_string` function.
pub fn hqc_dk_pke_from_string_ref(dk_pke: &[u8; SEED_BYTES]) -> [u64; VEC_N_SIZE_64] {
    let mut y = [0u64; VEC_N_SIZE_64];
    unsafe {
        hqc_dk_pke_from_string(y.as_mut_ptr(), dk_pke.as_ptr());
    }
    y
}

/// Safe wrapper around the C `hqc_ek_pke_from_string` function.
pub fn hqc_ek_pke_from_string_ref(ek_pke: &[u8]) -> ([u64; VEC_N_SIZE_64], [u64; VEC_N_SIZE_64]) {
    let mut h = [0u64; VEC_N_SIZE_64];
    let mut s = [0u64; VEC_N_SIZE_64];
    unsafe {
        hqc_ek_pke_from_string(h.as_mut_ptr(), s.as_mut_ptr(), ek_pke.as_ptr());
    }
    (h, s)
}

/// Safe wrapper around the C `hqc_c_kem_to_string` function.
pub fn hqc_c_kem_to_string_ref(c_kem: &CiphertextKem) -> Vec<u8> {
    let mut ct = vec![0u8; VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES + SALT_BYTES];
    unsafe {
        hqc_c_kem_to_string(ct.as_mut_ptr(), c_kem as *const CiphertextKem as *const u64);
    }
    ct
}

// /// Safe wrapper around the C `hqc_c_kem_from_string` function.
// pub fn hqc_c_kem_from_string_ref(ct: &[u8]) -> (CiphertextPke, [u8; SALT_BYTES]) {
//     let mut c_pke = CiphertextPke::default();
//     let mut salt = [0u8; SALT_BYTES];
//     unsafe {
//         hqc_c_kem_from_string(
//             &mut c_pke as *mut CiphertextPke as *mut u64,
//             salt.as_mut_ptr(),
//             ct.as_ptr(),
//         );
//     }
//     (c_pke, salt)
// }

#[test]
fn test_hqc_dk_pke_from_string_matches_ref() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let dk_pke: [u8; SEED_BYTES] = std::array::from_fn(|_| rng.random_range(0..=u8::MAX));

        let y = crate::parsing::hqc_dk_pke_from_string(&dk_pke);
        let y_ref = hqc_dk_pke_from_string_ref(&dk_pke);

        assert_eq!(y, y_ref, "Rust and C must agree at iteration {}", i);
    }
}

#[test]
fn test_hqc_ek_pke_from_string_matches_ref() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let ek_pke: Vec<u8> = (0..SEED_BYTES + VEC_N_SIZE_BYTES)
            .map(|_| rng.random_range(0..=u8::MAX))
            .collect();

        let (h, s) = crate::parsing::hqc_ek_pke_from_string(&ek_pke);
        let (h_ref, s_ref) = hqc_ek_pke_from_string_ref(&ek_pke);

        assert_eq!(h, h_ref, "h mismatch at iteration {}", i);
        assert_eq!(s, s_ref, "s mismatch at iteration {}", i);
    }
}

#[test]
fn test_hqc_c_kem_to_string_matches_ref() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let c_kem = CiphertextKem {
            c_pke: CiphertextPke {
                u: std::array::from_fn(|_| rng.random_range(0..=u64::MAX)),
                v: std::array::from_fn(|_| rng.random_range(0..=u64::MAX)),
            },
            salt: std::array::from_fn(|_| rng.random_range(0..=u8::MAX)),
        };

        let ct = crate::parsing::hqc_c_kem_to_string(&c_kem);
        let ct_ref = hqc_c_kem_to_string_ref(&c_kem);

        assert_eq!(ct, ct_ref, "Rust and C must agree at iteration {}", i);
    }
}

// #[test]
// fn test_hqc_c_kem_from_string_matches_ref() {
//     const TEST_ROUNDS: u64 = 100;
//     let mut rng = StdRng::seed_from_u64(4u64);
//     for i in 0..TEST_ROUNDS {
//         let ct: Vec<u8> = (0..VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES + SALT_BYTES)
//             .map(|_| rng.random_range(0..=u8::MAX))
//             .collect();

//         let (c_pke, salt) = crate::parsing::hqc_c_kem_from_string(&ct);
//         let (c_pke_ref, salt_ref) = hqc_c_kem_from_string_ref(&ct);

//         assert_eq!(c_pke, c_pke_ref, "c_pke mismatch at iteration {}", i);
//         assert_eq!(salt, salt_ref, "salt mismatch at iteration {}", i);
//     }
// }
