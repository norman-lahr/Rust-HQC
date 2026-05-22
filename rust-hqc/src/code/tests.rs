use crate::code::reed_muller::{RmCodeword, RmExpandedCdw, MULTIPLICITY};
use crate::parameters::{VEC_N1N2_SIZE_64, VEC_N1_SIZE_64};
use rand::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

unsafe extern "C" {
    fn encode(word: *mut RmCodeword, message: i32);
    fn hadamard(src: *mut RmExpandedCdw, dst: *mut RmExpandedCdw);
    fn expand_and_sum(dest: *mut RmExpandedCdw, src: *const RmCodeword);
    fn find_peaks(transform: *mut RmExpandedCdw) -> i32;
    fn reed_muller_encode(cdw: *mut u64, msg: *const u64);
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
