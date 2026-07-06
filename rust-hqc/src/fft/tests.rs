use crate::parameters::{PARAM_DELTA, PARAM_FFT, PARAM_M};

use rand::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

unsafe extern "C" {
    // fn compute_fft_betas(betas: *mut u16);
    // fn compute_subset_sums(subset_sums: *mut u16, set: *const u16, set_size: u16);
    // fn radix(f0: *mut u16, f1: *mut u16, f: *const u16, m_f: u32);
    // fn radix_big(f0: *mut u16, f1: *mut u16, f: *const u16, m_f: u32);
    fn fft(w: *mut u16, f: *const u16, f_coeffs: usize);
}

// /// Safe wrapper around the C `compute_fft_betas` function.
// pub fn compute_fft_betas_ref() -> [u16; PARAM_M - 1] {
//     let mut betas = [0u16; PARAM_M - 1];
//     unsafe {
//         compute_fft_betas(betas.as_mut_ptr());
//     }
//     betas
// }

// /// Safe wrapper around the C `compute_subset_sums` function.
// pub fn compute_subset_sums_ref(set: &[u16]) -> Vec<u16> {
//     let mut subset_sums = vec![0u16; 1 << set.len()];
//     unsafe {
//         compute_subset_sums(subset_sums.as_mut_ptr(), set.as_ptr(), set.len() as u16);
//     }
//     subset_sums
// }

// /// Safe wrapper around the C `radix` function.
// pub fn radix_ref(f: &[u16], m_f: u32) -> (Vec<u16>, Vec<u16>) {
//     let half = f.len() / 2;
//     let mut f0 = vec![0u16; half];
//     let mut f1 = vec![0u16; half];
//     unsafe {
//         radix(f0.as_mut_ptr(), f1.as_mut_ptr(), f.as_ptr(), m_f);
//     }
//     (f0, f1)
// }

// /// Safe wrapper around the C `radix_big` function.
// pub fn radix_big_ref(f: &[u16], m_f: u32) -> (Vec<u16>, Vec<u16>) {
//     let half = f.len() / 2;
//     let mut f0 = vec![0u16; half];
//     let mut f1 = vec![0u16; half];
//     unsafe {
//         radix_big(f0.as_mut_ptr(), f1.as_mut_ptr(), f.as_ptr(), m_f);
//     }
//     (f0, f1)
// }

/// Safe wrapper around the C `fft` function.
pub fn fft_ref(f: &[u16], f_coeffs: usize) -> Vec<u16> {
    let mut w = vec![0u16; 1usize << PARAM_M];
    unsafe {
        fft(w.as_mut_ptr(), f.as_ptr(), f_coeffs);
    }
    w
}

// #[test]
// fn test_compute_fft_betas() {
//     let betas = crate::fft::compute_fft_betas();
//     let betas_ref = compute_fft_betas_ref();
//     assert_eq!(
//         betas, betas_ref,
//         "Rust and C implementations must produce identical results"
//     );
// }

// #[test]
// fn test_compute_subset_sums() {
//     let set = crate::fft::compute_fft_betas(); // PARAM_M - 1 public basis elements
//     let mut subset_sums = vec![0u16; 1 << set.len()];
//     crate::fft::compute_subset_sums(&set, &mut subset_sums);

//     let subset_sums_ref = compute_subset_sums_ref(&set);

//     assert_eq!(
//         subset_sums, subset_sums_ref,
//         "Rust and C implementations must produce identical results"
//     );
// }

// #[test]
// fn test_rust_matches_ref() {
//     const TEST_ROUNDS: u64 = 100;
//     let mut rng = StdRng::seed_from_u64(4u64);
//     for i in 0..TEST_ROUNDS {
//         for m_f in 1..4 {
//             let f: [u16; 16] = std::array::from_fn(|_| rng.random_range(0..=u16::MAX));
//             let mut f0 = vec![0u16; 8];
//             let mut f1 = vec![0u16; 8];
//             crate::fft::radix(&mut f0, &mut f1, &f, m_f);

//             let (f0_ref, f1_ref) = radix_ref(&f, m_f);

//             assert_eq!(f0, f0_ref, "f0 mismatch at iteration {}", i);
//             assert_eq!(f1, f1_ref, "f1 mismatch at iteration {}", i);
//         }
//     }
// }

// #[test]
// fn test_rust_matches_ref_various_m_f() {
//     const TEST_ROUNDS: u64 = 100;
//     let mut rng = StdRng::seed_from_u64(4u64);
//     // radix_big is used for m_f > 4 (small cases handled directly in radix)
//     for m_f in 5..=PARAM_FFT {
//         let size = 1usize << m_f;
//         for i in 0..TEST_ROUNDS {
//             let f: Vec<u16> = (0..size).map(|_| rng.random_range(0..=u16::MAX)).collect();

//             let mut f0_rs = vec![0u16; size / 2];
//             let mut f1_rs = vec![0u16; size / 2];
//             crate::fft::radix_big(&mut f0_rs, &mut f1_rs, &f, m_f as u32);

//             let (f0_ref, f1_ref) = radix_big_ref(&f, m_f as u32);

//             assert_eq!(f0_rs, f0_ref, "f0 mismatch at m_f={}, iteration {}", m_f, i);
//             assert_eq!(f1_rs, f1_ref, "f1 mismatch at m_f={}, iteration {}", m_f, i);
//         }
//     }
// }

#[test]
fn test_fft() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    let f_coeffs = PARAM_DELTA + 1;

    for i in 0..TEST_ROUNDS {
        let f: Vec<u16> = (0..(1usize << PARAM_FFT))
            .map(|_| rng.random_range(0..=u16::MAX))
            .collect();

        let w = crate::fft::fft(&f, f_coeffs);
        let w_ref = fft_ref(&f, f_coeffs);

        assert_eq!(w, w_ref, "Rust and C must agree at iteration {}", i);
    }
}
