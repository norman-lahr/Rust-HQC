use crate::kem::CiphertextKem;
use crate::parameters::{HQC_1, SEED_BYTES, SALT_BYTES};
use crate::pke::CiphertextPke;
use rand::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

use crate::ffi::hqc1::{hqc_c_kem_from_string, hqc_c_kem_to_string, hqc_dk_pke_from_string, hqc_ek_pke_from_string};

/// Safe wrapper around the C `hqc_dk_pke_from_string` function.
pub fn hqc_dk_pke_from_string_ref(p: &crate::parameters::HqcParameters, dk_pke: &[u8; SEED_BYTES]) -> Vec<u64> {
    let mut y = vec![0u64; p.vec_n_size_64];
    unsafe {
        hqc_dk_pke_from_string(y.as_mut_ptr(), dk_pke.as_ptr());
    }
    y
}

/// Safe wrapper around the C `hqc_ek_pke_from_string` function.
pub fn hqc_ek_pke_from_string_ref(p: &crate::parameters::HqcParameters, ek_pke: &[u8]) -> (Vec<u64>, Vec<u64>) {
    let mut h = vec![0u64; p.vec_n_size_64];
    let mut s = vec![0u64; p.vec_n_size_64];
    unsafe {
        hqc_ek_pke_from_string(h.as_mut_ptr(), s.as_mut_ptr(), ek_pke.as_ptr());
    }
    (h, s)
}

/// Safe wrapper around the C `hqc_c_kem_to_string` function.
pub fn hqc_c_kem_to_string_ref(p: &crate::parameters::HqcParameters, c_kem: &CiphertextKem) -> Vec<u8> {
    let mut ct = vec![0u8; p.vec_n_size_bytes + p.vec_n1n2_size_bytes + SALT_BYTES];
    unsafe {
        // C expects u ++ v ++ salt contiguously. `CiphertextKem` holds a
        // `CiphertextPke` whose fields are now `Vec`s, so the struct pointer
        // would be the Vec headers; marshal through a flat buffer instead.
        let mut flat = Vec::with_capacity(2 * p.vec_n_size_64 + 1);
        flat.extend_from_slice(&c_kem.c_pke.u);
        flat.extend_from_slice(&c_kem.c_pke.v);
        let mut salt_words = [0u64; 2];
        salt_words[0] = u64::from_le_bytes(c_kem.salt[..8].try_into().unwrap());
        salt_words[1] = u64::from_le_bytes(c_kem.salt[8..].try_into().unwrap());
        flat.extend_from_slice(&salt_words);
        hqc_c_kem_to_string(ct.as_mut_ptr(), flat.as_ptr());
    }
    ct
}

// /// Safe wrapper around the C `hqc_c_kem_from_string` function.
// pub fn hqc_c_kem_from_string_ref(p: &crate::parameters::HqcParameters, ct: &[u8]) -> (CiphertextPke, [u8; SALT_BYTES]) {
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
    let p = &HQC_1;
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let dk_pke: [u8; SEED_BYTES] = std::array::from_fn(|_| rng.random_range(0..=u8::MAX));

        let y = crate::parsing::hqc_dk_pke_from_string(p, &dk_pke);
        let y_ref = hqc_dk_pke_from_string_ref(p, &dk_pke);

        assert_eq!(y, y_ref, "Rust and C must agree at iteration {}", i);
    }
}

#[test]
fn test_hqc_ek_pke_from_string_matches_ref() {
    let p = &HQC_1;
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let ek_pke: Vec<u8> = (0..SEED_BYTES + p.vec_n_size_bytes)
            .map(|_| rng.random_range(0..=u8::MAX))
            .collect();

        let (h, s) = crate::parsing::hqc_ek_pke_from_string(p, &ek_pke);
        let (h_ref, s_ref) = hqc_ek_pke_from_string_ref(p, &ek_pke);

        assert_eq!(h, h_ref, "h mismatch at iteration {}", i);
        assert_eq!(s, s_ref, "s mismatch at iteration {}", i);
    }
}

#[test]
fn test_hqc_c_kem_to_string_matches_ref() {
    let p = &HQC_1;
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        let c_kem = CiphertextKem {
            c_pke: CiphertextPke {
                u: (0..p.vec_n_size_64).map(|_| rng.random_range(0..=u64::MAX)).collect(),
                v: (0..p.vec_n_size_64).map(|_| rng.random_range(0..=u64::MAX)).collect(),
            },
            salt: std::array::from_fn(|_| rng.random_range(0..=u8::MAX)),
        };

        let ct = crate::parsing::hqc_c_kem_to_string(p, &c_kem);
        let ct_ref = hqc_c_kem_to_string_ref(p, &c_kem);

        assert_eq!(ct, ct_ref, "Rust and C must agree at iteration {}", i);
    }
}

// #[test]
// fn test_hqc_c_kem_from_string_matches_ref() {
//     const TEST_ROUNDS: u64 = 100;
//     let mut rng = StdRng::seed_from_u64(4u64);
//     for i in 0..TEST_ROUNDS {
//         let ct: Vec<u8> = (0..p.vec_n_size_bytes + p.vec_n1n2_size_bytes + SALT_BYTES)
//             .map(|_| rng.random_range(0..=u8::MAX))
//             .collect();

//         let (c_pke, salt) = crate::parsing::hqc_c_kem_from_string(p, &ct);
//         let (c_pke_ref, salt_ref) = hqc_c_kem_from_string_ref(p, &ct);

//         assert_eq!(c_pke, c_pke_ref, "c_pke mismatch at iteration {}", i);
//         assert_eq!(salt, salt_ref, "salt mismatch at iteration {}", i);
//     }
// }
