use crate::gf2x::vect_mul;
use crate::parameters::{PARAM_OMEGA, SEED_BYTES, VEC_N_SIZE_64, VEC_N_SIZE_BYTES};
use crate::symmetric::{hash_i, xof_init};
use crate::vector::{vect_add_into, vect_sample_fixed_weight1, vect_set_random};

/// Unpack an `u64` slice into a `Vec<u8>`, little-endian.
/// TODO Add helper module
fn u64_words_to_bytes(words: &[u64]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// Generates a key pair for the HQC public-key encryption (PKE) scheme.
///
/// Creates a public encryption key (`ek_pke`) and a private decryption key
/// (`dk_pke`) for use in the HQC PKE scheme, deterministically derived
/// from `seed`.
///
/// # Arguments
/// * `seed` - Seed used to deterministically generate the key pair.
///
/// # Returns
/// A tuple `(ek_pke, dk_pke)`:
/// * `ek_pke` - Encryption key of `SEED_BYTES + VEC_N_SIZE_BYTES` bytes.
/// * `dk_pke` - Decryption key of `SEED_BYTES` bytes.
pub fn hqc_pke_keygen(seed: &[u8; SEED_BYTES]) -> (Vec<u8>, Vec<u8>) {
    // Derive keypair seeds
    let mut keypair_seed = hash_i(seed); // [u8; 64] = 2 * SEED_BYTES

    let seed_dk: [u8; SEED_BYTES] = keypair_seed[..SEED_BYTES].try_into().unwrap();
    let seed_ek: [u8; SEED_BYTES] = keypair_seed[SEED_BYTES..].try_into().unwrap();

    // Compute decryption key
    let mut dk_reader = xof_init(&seed_dk);
    let mut y = vect_sample_fixed_weight1(&mut dk_reader, PARAM_OMEGA);
    let mut x = vect_sample_fixed_weight1(&mut dk_reader, PARAM_OMEGA);

    // Compute encryption key
    let mut ek_reader = xof_init(&seed_ek);
    let h = vect_set_random(&mut ek_reader);

    let mut s = vect_mul(&y, &h);
    let mut s_final = [0u64; VEC_N_SIZE_64];
    vect_add_into(&mut s_final, &x, &s);

    // Parse encryption key to bytes
    let mut ek_pke = Vec::with_capacity(SEED_BYTES + VEC_N_SIZE_BYTES);
    ek_pke.extend_from_slice(&seed_ek);
    ek_pke.extend_from_slice(&u64_words_to_bytes(&s_final)[..VEC_N_SIZE_BYTES]);

    // Parse decryption key to bytes
    let dk_pke = seed_dk.to_vec();

    // Zeroize sensitive data
    keypair_seed.iter_mut().for_each(|b| *b = 0);
    x.iter_mut().for_each(|w| *w = 0);
    y.iter_mut().for_each(|w| *w = 0);
    s.iter_mut().for_each(|w| *w = 0);
    s_final.iter_mut().for_each(|w| *w = 0);

    (ek_pke, dk_pke)
}

#[cfg(test)]
mod tests;
