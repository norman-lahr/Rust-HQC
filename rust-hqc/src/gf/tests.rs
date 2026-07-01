use rand::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

use crate::parameters::PARAM_M;

unsafe extern "C" {
    fn gf_generate(exp: *mut u16, log: *mut u16, m: i16);
    fn gf_reduce(x: u16) -> u16;
    fn gf_carryless_mul(c: *mut u8, a: u8, b: u8);
}

/// Safe wrapper around the C `gf_generate` function.
pub fn gf_generate_ref(m: u16) -> (Vec<u16>, Vec<u16>) {
    let field_size = 1usize << m;
    let mut exp = vec![0u16; field_size + 2];
    let mut log = vec![0u16; field_size];
    unsafe {
        gf_generate(exp.as_mut_ptr(), log.as_mut_ptr(), m as i16);
    }
    (exp, log)
}

/// Safe wrapper around the C `gf_reduce` function.
pub fn gf_reduce_ref(x: u16) -> u16 {
    unsafe { gf_reduce(x) }
}

/// Safe wrapper around the C `gf_carryless_mul` function.
pub fn gf_carryless_mul_ref(a: u8, b: u8) -> [u8; 2] {
    let mut c = [0u8; 2];
    unsafe {
        gf_carryless_mul(c.as_mut_ptr(), a, b);
    }
    c
}

#[test]
fn test_gf_generate() {
    let (exp, log) = crate::gf::gf_generate(PARAM_M as u16);
    let (exp_ref, log_ref) = gf_generate_ref(PARAM_M as u16);

    assert_eq!(exp, exp_ref, "Rust and C exp tables must be identical");
    assert_eq!(log, log_ref, "Rust and C log tables must be identical");
}

#[test]
fn test_gf_reduce_random() {
    const TEST_ROUNDS: u64 = 100;
    let mut rng = StdRng::seed_from_u64(4u64);
    for i in 0..TEST_ROUNDS {
        // x has degree <= 14, so x < 2^15
        let x: u16 = rng.random_range(0..(1u16 << 15));
        let r = crate::gf::gf_reduce(x);
        let r_ref = gf_reduce_ref(x);
        assert_eq!(
            r, r_ref,
            "Rust and C must agree at iteration {} for x={}",
            i, x
        );
    }
}

#[test]
fn test_gf_reduce_all_degree_14_values() {
    // Exhaustively test all values up to degree 14 (0..2^15)
    for x in 0..(1u32 << 15) {
        let r = crate::gf::gf_reduce(x as u16);
        let r_ref = gf_reduce_ref(x as u16);
        assert_eq!(r, r_ref, "Rust and C must agree for x={}", x);
    }
}

#[test]
fn test_gf_carryless_mul() {
    for a in 0..=255u16 {
        for b in 0..=255u16 {
            let a = a as u8;
            let b = b as u8;
            let r = crate::gf::gf_carryless_mul(a, b);
            let r_ref = gf_carryless_mul_ref(a, b);
            assert_eq!(r, r_ref, "Rust and C must agree for a={}, b={}", a, b);
        }
    }
}
