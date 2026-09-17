use crate::kem::CiphertextKem;
use crate::parameters::{HqcParameters, SALT_BYTES, SEED_BYTES};
use crate::pke::{u64_words_to_bytes, CiphertextPke};
use crate::symmetric::xof_init;
use crate::vector::{vect_sample_fixed_weight1, vect_set_random};

/// Deserializes a decryption key into its internal vectorized form.
///
/// # Arguments
/// * `dk_pke` - Serialized decryption key of `SEED_BYTES` bytes.
///
/// # Returns
/// The internal vectorized key `y` of `p.vec_n_size_64` words.
pub fn hqc_dk_pke_from_string(p: &HqcParameters, dk_pke: &[u8; SEED_BYTES]) -> Vec<u64> {
    let mut dk_reader = xof_init(dk_pke);
    let y = vect_sample_fixed_weight1(p, &mut dk_reader, p.omega);
    // dk_reader (the XOF state) is dropped here — no separate zeroization
    // needed unless XofReader itself holds sensitive persistent state.
    y
}

/// Deserializes an encryption key into its internal representation.
///
/// # Arguments
/// * `ek_pke` - Serialized encryption key of `SEED_BYTES + p.vec_n_size_bytes` bytes.
///
/// # Returns
/// A tuple `(h, s)`:
/// * `h` - First internal component, `p.vec_n_size_64` words.
/// * `s` - Second internal component, `p.vec_n_size_64` words.
pub fn hqc_ek_pke_from_string(p: &HqcParameters, ek_pke: &[u8]) -> (Vec<u64>, Vec<u64>) {
    let seed_ek: [u8; SEED_BYTES] = ek_pke[..SEED_BYTES].try_into().unwrap();
    let mut ek_reader = xof_init(&seed_ek);
    let h = vect_set_random(p, &mut ek_reader);

    let s_bytes = &ek_pke[SEED_BYTES..SEED_BYTES + p.vec_n_size_bytes];
    let mut s = p.zero_vec_n();
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
/// Serialized ciphertext of `p.vec_n_size_bytes + p.vec_n1n2_size_bytes + SALT_BYTES` bytes.
pub fn hqc_c_kem_to_string(p: &HqcParameters, c_kem: &CiphertextKem) -> Vec<u8> {
    let mut ct = Vec::with_capacity(p.vec_n_size_bytes + p.vec_n1n2_size_bytes + SALT_BYTES);
    ct.extend_from_slice(&u64_words_to_bytes(&c_kem.c_pke.u)[..p.vec_n_size_bytes]);
    ct.extend_from_slice(&u64_words_to_bytes(&c_kem.c_pke.v)[..p.vec_n1n2_size_bytes]);
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
pub fn hqc_c_kem_from_string(p: &HqcParameters, ct: &[u8]) -> (CiphertextPke, [u8; SALT_BYTES]) {
    let u_bytes = &ct[..p.vec_n_size_bytes];
    let v_bytes = &ct[p.vec_n_size_bytes..p.vec_n_size_bytes + p.vec_n1n2_size_bytes];
    let salt_bytes = &ct[p.vec_n_size_bytes + p.vec_n1n2_size_bytes
        ..p.vec_n_size_bytes + p.vec_n1n2_size_bytes + SALT_BYTES];

    let mut u = p.zero_vec_n();
    for (i, chunk) in u_bytes.chunks(8).enumerate() {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        u[i] = u64::from_le_bytes(buf);
    }

    let mut v = p.zero_vec_n();
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
