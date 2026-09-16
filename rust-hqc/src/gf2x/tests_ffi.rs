use crate::parameters::*;
use crate::vector::vect_set_random;

use crate::ffi::hqc1::{vect_mul, vect_set_random as ffi_vect_set_random, xof_init};

/// Safe wrapper around the C `vect_mul` function.
///
/// Computes `o = a1 * a2` over GF(2) mod (X^PARAM_N - 1).
///
/// # Arguments
/// * `a1` - Operand polynomial a(x) of `VEC_N_SIZE_64` 64-bit words.
/// * `a2` - Operand polynomial b(x) of `VEC_N_SIZE_64` 64-bit words.
///
/// # Returns
/// Result of `VEC_N_SIZE_64` 64-bit words.
pub fn vect_mul_ref(a1: &[u64; VEC_N_SIZE_64], a2: &[u64; VEC_N_SIZE_64]) -> [u64; VEC_N_SIZE_64] {
    let mut o = [0u64; VEC_N_SIZE_64];
    unsafe {
        vect_mul(o.as_mut_ptr(), a1.as_ptr(), a2.as_ptr());
    }
    o
}

#[test]
fn test_vect_mul() {
    const TEST_ROUNDS: u64 = 100;
    let seed: [u8; SEED_BYTES] = b"0ACE".repeat(SEED_BYTES / 4).try_into().unwrap();
    let mut ctx1 = crate::symmetric::xof_init(&seed);
    let mut ctx2 = crate::symmetric::xof_init(&seed);

    let mut pre;
    let mut post;

    let mut cycles_rust = 0;
    let mut cycles_c = 0;

    for i in 0..TEST_ROUNDS {
        let a1 = vect_set_random(&mut ctx1);
        let a2 = vect_set_random(&mut ctx1);
        let a1_ref = vect_set_random(&mut ctx2);
        let a2_ref = vect_set_random(&mut ctx2);

        unsafe {
            pre = core::arch::x86_64::_rdtsc();
        }
        let o_ref = vect_mul_ref(&a1_ref, &a2_ref);
        unsafe {
            post = core::arch::x86_64::_rdtsc();
        }
        cycles_c += post - pre;

        unsafe {
            pre = core::arch::x86_64::_rdtsc();
        }
        let o = crate::gf2x::vect_mul(&a1, &a2);
        unsafe {
            post = core::arch::x86_64::_rdtsc();
        }
        cycles_rust += post - pre;
        assert_eq!(o, o_ref, "Rust and C must match at iteration {}", i);
    }
    println!(
        "Mean of measured cycles: {} (Rust Function) vs. {} (C Reference) | Ratio {:?}",
        cycles_rust / TEST_ROUNDS,
        cycles_c / TEST_ROUNDS,
        cycles_rust as f64 / cycles_c as f64
    );
}
