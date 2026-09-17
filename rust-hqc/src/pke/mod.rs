use crate::code::{code_decode, code_encode};
use crate::gf2x::vect_mul;
use crate::parameters::{HqcParameters, SEED_BYTES};
use crate::parsing::{hqc_dk_pke_from_string, hqc_ek_pke_from_string};
use crate::symmetric::{hash_i, xof_init};
use crate::vector::{
    vect_add_into, vect_sample_fixed_weight1, vect_sample_fixed_weight2, vect_set_random,
    vect_truncate,
};

/// Unpack an `u64` slice into a `Vec<u8>`, little-endian.
/// TODO Add helper module
pub fn u64_words_to_bytes(words: &[u64]) -> Vec<u8> {
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
/// * `ek_pke` - Encryption key of `SEED_BYTES + p.vec_n_size_bytes` bytes.
/// * `dk_pke` - Decryption key of `SEED_BYTES` bytes.
pub fn hqc_pke_keygen(p: &HqcParameters, seed: &[u8; SEED_BYTES]) -> (Vec<u8>, Vec<u8>) {
    // Derive keypair seeds
    let mut keypair_seed = hash_i(seed); // [u8; 64] = 2 * SEED_BYTES

    let seed_dk: [u8; SEED_BYTES] = keypair_seed[..SEED_BYTES].try_into().unwrap();
    let seed_ek: [u8; SEED_BYTES] = keypair_seed[SEED_BYTES..].try_into().unwrap();

    // Compute decryption key
    let mut dk_reader = xof_init(&seed_dk);
    let mut y = vect_sample_fixed_weight1(p, &mut dk_reader, p.omega);
    let mut x = vect_sample_fixed_weight1(p, &mut dk_reader, p.omega);

    // Compute encryption key
    let mut ek_reader = xof_init(&seed_ek);
    let h = vect_set_random(p, &mut ek_reader);

    let mut s = vect_mul(p, &y, &h);
    let mut s_final = p.zero_vec_n();
    vect_add_into(&mut s_final, &x, &s);

    // Parse encryption key to bytes
    let mut ek_pke = Vec::with_capacity(SEED_BYTES + p.vec_n_size_bytes);
    ek_pke.extend_from_slice(&seed_ek);
    ek_pke.extend_from_slice(&u64_words_to_bytes(&s_final)[..p.vec_n_size_bytes]);

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

/// PKE ciphertext for the HQC scheme.
///
/// `#[repr(C)]` was dropped with the move to runtime parameters: no FFI
/// declaration passes this struct by pointer any more (phase 1 moved all
/// marshalling to pointer+length), so a fixed layout bought nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CiphertextPke {
    pub u: Vec<u64>,
    pub v: Vec<u64>,
}

impl CiphertextPke {
    pub fn zeroed(p: &HqcParameters) -> Self {
        Self {
            u: p.zero_vec_n(),
            v: p.zero_vec_n(),
        }
    }
}

/// Encrypts a message using the HQC public-key encryption (PKE) scheme.
///
/// Uses the given encryption key (`ek_pke`) and encryption randomness
/// (`theta`) to encrypt the message `m`, producing a ciphertext `c_pke`.
///
/// # Arguments
/// * `ek_pke` - Encryption key.
/// * `m`      - Message to be encrypted, `p.vec_k_size_64` words.
/// * `theta`  - Encryption randomness, `SEED_BYTES` bytes.
///
/// # Returns
/// The PKE ciphertext.
pub fn hqc_pke_encrypt(
    p: &HqcParameters,
    ek_pke: &[u8],
    m: &[u64],
    theta: &[u8; SEED_BYTES],
) -> CiphertextPke {
    let mut c_pke = CiphertextPke::zeroed(p);

    // Initialize Xof using theta
    let mut theta_reader = xof_init(theta);
    //
    // Retrieve h and s from public key
    let (h, s) = hqc_ek_pke_from_string(p, ek_pke); //

    // Generate r2, e and r1
    let mut r2 = vect_sample_fixed_weight2(p, &mut theta_reader, p.omega_r);
    let mut e = vect_sample_fixed_weight2(p, &mut theta_reader, p.omega_e);
    let mut r1 = vect_sample_fixed_weight2(p, &mut theta_reader, p.omega_r);

    // Compute u = r1 + r2.h
    let r2_h = vect_mul(p, &r2, &h);
    vect_add_into(&mut c_pke.u, &r1, &r2_h);

    // Compute v = C.encode(m)
    let encoded = code_encode(p, m);
    c_pke.v[..p.vec_n1n2_size_64].copy_from_slice(&encoded);

    // Compute v = C.encode(m) + Truncate(s.r2 + e)
    let r2_s = vect_mul(p, &r2, &s);
    let mut tmp = p.zero_vec_n();
    vect_add_into(&mut tmp, &e, &r2_s);
    let mut tmp_trunc = p.zero_vec_n();
    tmp_trunc.copy_from_slice(&tmp);
    vect_truncate(p, &mut tmp_trunc);

    let mut v_final = vec![0u64; p.vec_n1n2_size_64];
    vect_add_into(
        &mut v_final,
        &c_pke.v[..p.vec_n1n2_size_64],
        &tmp_trunc[..p.vec_n1n2_size_64],
    );
    c_pke.v[..p.vec_n1n2_size_64].copy_from_slice(&v_final);
    // c_pke.v[..p.vec_n1n2_size_64] = v_final;

    // Zeroize sensitive data
    r1.iter_mut().for_each(|w| *w = 0);
    r2.iter_mut().for_each(|w| *w = 0);
    e.iter_mut().for_each(|w| *w = 0);
    tmp.iter_mut().for_each(|w| *w = 0);
    tmp_trunc.iter_mut().for_each(|w| *w = 0);

    c_pke
}

/// Decrypts a ciphertext using the HQC public-key encryption (PKE) scheme.
///
/// Uses the given decryption key (`dk_pke`) to decrypt the ciphertext
/// `c_pke`, recovering the original message `m`.
///
/// Constant-time with respect to `dk_pke` and `c_pke`: delegates entirely
/// to already constant-time subroutines (`hqc_dk_pke_from_string`,
/// `vect_mul`, `vect_truncate`, `vect_add`, `code_decode`). Sensitive
/// intermediate data is zeroized before returning.
///
/// # Arguments
/// * `dk_pke` - Decryption key.
/// * `c_pke`  - Input PKE ciphertext.
///
/// # Returns
/// The decrypted message `m` of `p.vec_k_size_64` words.
pub fn hqc_pke_decrypt(
    p: &HqcParameters,
    dk_pke: &[u8; SEED_BYTES],
    c_pke: &CiphertextPke,
) -> Vec<u64> {
    // Parse decryption key dk_pke
    let mut y = hqc_dk_pke_from_string(p, dk_pke);

    // Compute u.y
    let uy = vect_mul(p, &y, &c_pke.u);

    // Truncate(u.y)
    let mut tmp1 = p.zero_vec_n();
    tmp1.copy_from_slice(&uy);
    vect_truncate(p, &mut tmp1);

    // Compute v - Truncate(u.y)
    let mut tmp2 = p.zero_vec_n();
    vect_add_into(
        &mut tmp2[..p.vec_n1n2_size_64],
        &c_pke.v[..p.vec_n1n2_size_64],
        &tmp1[..p.vec_n1n2_size_64],
    );

    // Compute plaintext m
    let m = code_decode(p, &tmp2[..p.vec_n1n2_size_64]);

    // Zeroize sensitive data
    y.iter_mut().for_each(|w| *w = 0);
    tmp1.iter_mut().for_each(|w| *w = 0);
    tmp2.iter_mut().for_each(|w| *w = 0);

    m
}

#[cfg(all(test, feature = "ref-ffi"))]
mod tests_ffi;
