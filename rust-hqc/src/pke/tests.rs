use crate::parameters::{SEED_BYTES, VEC_N_SIZE_BYTES};
use rand::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

unsafe extern "C" {
    fn hqc_pke_keygen(ek_pke: *mut u8, dk_pke: *mut u8, seed: *mut u8);
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
