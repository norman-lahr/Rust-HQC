use crate::code::reed_muller::{RmCodeword, RmExpandedCdw, MULTIPLICITY};
use rand::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

unsafe extern "C" {
    fn encode(word: *mut RmCodeword, message: i32);
    fn hadamard(src: *mut RmExpandedCdw, dst: *mut RmExpandedCdw);
    fn expand_and_sum(dest: *mut RmExpandedCdw, src: *const RmCodeword);
}

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
