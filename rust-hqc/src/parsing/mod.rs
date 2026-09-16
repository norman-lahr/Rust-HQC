use crate::kem::CiphertextKem;
use crate::parameters::{
    PARAM_OMEGA, SALT_BYTES, SEED_BYTES, VEC_N1N2_SIZE_64, VEC_N1N2_SIZE_BYTES, VEC_N_SIZE_64,
    VEC_N_SIZE_BYTES,
};
use crate::pke::{u64_words_to_bytes, CiphertextPke};
use crate::symmetric::xof_init;
use crate::vector::{vect_sample_fixed_weight1, vect_set_random};

/// Deserializes a decryption key into its internal vectorized form.
///
/// # Arguments
/// * `dk_pke` - Serialized decryption key of `SEED_BYTES` bytes.
///
/// # Returns
/// The internal vectorized key `y` of `VEC_N_SIZE_64` words.
pub fn hqc_dk_pke_from_string(dk_pke: &[u8; SEED_BYTES]) -> [u64; VEC_N_SIZE_64] {
    let mut dk_reader = xof_init(dk_pke);
    let y = vect_sample_fixed_weight1(&mut dk_reader, PARAM_OMEGA);
    // dk_reader (the XOF state) is dropped here — no separate zeroization
    // needed unless XofReader itself holds sensitive persistent state.
    y
}

/// Deserializes an encryption key into its internal representation.
///
/// # Arguments
/// * `ek_pke` - Serialized encryption key of `SEED_BYTES + VEC_N_SIZE_BYTES` bytes.
///
/// # Returns
/// A tuple `(h, s)`:
/// * `h` - First internal component, `VEC_N_SIZE_64` words.
/// * `s` - Second internal component, `VEC_N_SIZE_64` words.
pub fn hqc_ek_pke_from_string(ek_pke: &[u8]) -> ([u64; VEC_N_SIZE_64], [u64; VEC_N_SIZE_64]) {
    let seed_ek: [u8; SEED_BYTES] = ek_pke[..SEED_BYTES].try_into().unwrap();
    let mut ek_reader = xof_init(&seed_ek);
    let h = vect_set_random(&mut ek_reader);

    let s_bytes = &ek_pke[SEED_BYTES..SEED_BYTES + VEC_N_SIZE_BYTES];
    let mut s = [0u64; VEC_N_SIZE_64];
    for (i, chunk) in s_bytes.chunks(8).enumerate() {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        s[i] = u64::from_le_bytes(buf);
    }

    (h, s)
}

/// Serializes a KEM ciphertext structure into a byte array.
///
/// # Arguments
/// * `c_kem` - KEM ciphertext structure to be serialized.
///
/// # Returns
/// Serialized ciphertext of `VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES + SALT_BYTES` bytes.
pub fn hqc_c_kem_to_string(c_kem: &CiphertextKem) -> Vec<u8> {
    let mut ct = Vec::with_capacity(VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES + SALT_BYTES);
    ct.extend_from_slice(&u64_words_to_bytes(&c_kem.c_pke.u)[..VEC_N_SIZE_BYTES]);
    ct.extend_from_slice(&u64_words_to_bytes(&c_kem.c_pke.v)[..VEC_N1N2_SIZE_BYTES]);
    ct.extend_from_slice(&c_kem.salt);
    ct
}

/// Deserializes a KEM ciphertext byte array into its structured components.
///
/// # Arguments
/// * `ct` - Serialized KEM ciphertext.
///
/// # Returns
/// A tuple `(c_pke, salt)`:
/// * `c_pke` - Deserialized PKE ciphertext.
/// * `salt`  - Extracted salt of `SALT_BYTES` bytes.
pub fn hqc_c_kem_from_string(ct: &[u8]) -> (CiphertextPke, [u8; SALT_BYTES]) {
    let u_bytes = &ct[..VEC_N_SIZE_BYTES];
    let v_bytes = &ct[VEC_N_SIZE_BYTES..VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES];
    let salt_bytes = &ct[VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES
        ..VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES + SALT_BYTES];

    let mut u = [0u64; VEC_N_SIZE_64];
    for (i, chunk) in u_bytes.chunks(8).enumerate() {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        u[i] = u64::from_le_bytes(buf);
    }

    let mut v = [0u64; VEC_N_SIZE_64];
    for (i, chunk) in v_bytes.chunks(8).enumerate() {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        v[i] = u64::from_le_bytes(buf);
    }

    let mut salt = [0u8; SALT_BYTES];
    salt.copy_from_slice(salt_bytes);

    (CiphertextPke { u, v }, salt)
}

#[cfg(all(test, feature = "ref-ffi"))]
mod tests_ffi;
