use crate::kem::CiphertextKem;
use crate::parameters::{
    PARAM_SECURITY_BYTES, SALT_BYTES, SEED_BYTES, VEC_N1N2_SIZE_BYTES, VEC_N_SIZE_BYTES,
};
use crate::pke::u64_words_to_bytes;
use sha3::digest::XofReader;
use sha3::{Digest, Sha3_256, Sha3_512, Shake256};

/// Domain separator for HQC prng function.
pub const PRNG_DOMAIN: u8 = 0;

/// Domain separator for HQC extendable-output function.
pub const XOF_DOMAIN: u8 = 1;

/// Domain separator for the G(·) function in HQC.
pub const G_FCT_DOMAIN: u8 = 0;

/// Domain separator for the H(·) function in HQC.
pub const H_FCT_DOMAIN: u8 = 1;

/// Domain separator for the I(·) function in HQC.
pub const I_FCT_DOMAIN: u8 = 2;

/// Domain separator for the J(·) function in HQC.
pub const J_FCT_DOMAIN: u8 = 3;

/// SHAKE-256 with incremental API and domain separation.
///
/// Derived from the `SHAKE_256` construction. Initializes a SHAKE-256 XOF
/// reader by absorbing entropy, a personalization string, and a domain
/// separator, then finalizing into squeeze mode.
///
/// # Arguments
/// * `entropy_input`          - Input entropy bytes.
/// * `personalization_string` - Personalization string.
///
/// # Returns
/// An initialized `XofReader` ready for squeezing pseudorandom bytes.
pub fn prng_init(entropy_input: &[u8], personalization_string: &[u8]) -> impl XofReader {
    let domain = PRNG_DOMAIN;

    let mut hasher = Shake256::default();
    sha3::digest::Update::update(&mut hasher, entropy_input);
    sha3::digest::Update::update(&mut hasher, personalization_string);
    sha3::digest::Update::update(&mut hasher, &[domain]);
    sha3::digest::ExtendableOutput::finalize_xof(hasher)
}

/// A SHAKE-256 based PRNG.
///
/// Derived from the `SHAKE_256` construction. Squeezes `outlen` bytes
/// from the given PRNG reader.
///
/// # Arguments
/// * `reader` - An initialized PRNG reader (from `prng_init`).
/// * `outlen` - Number of bytes to squeeze.
///
/// # Returns
/// `outlen` pseudorandom bytes.
pub fn prng_get_bytes(reader: &mut impl XofReader, outlen: usize) -> Vec<u8> {
    let mut output = vec![0u8; outlen];
    reader.read(&mut output);
    output
}

/// Initializes a SHAKE256 XOF context with a given seed.
///
/// # Arguments
/// * `seed` - The input seed to be absorbed.
///
/// # Returns
/// A finalized `XofReader` ready for squeezing output.
pub fn xof_init(seed: &[u8; SEED_BYTES]) -> impl XofReader {
    let xof_domain = XOF_DOMAIN;
    let mut hasher = Shake256::default();
    sha3::digest::Update::update(&mut hasher, seed);
    sha3::digest::Update::update(&mut hasher, &[xof_domain]);
    sha3::digest::ExtendableOutput::finalize_xof(hasher)
}

/// Extracts pseudorandom bytes from a SHAKE256 XOF reader.
///
/// # Arguments
/// * `reader` - A SHAKE256 XOF reader from a previously initialized context.
/// * `output` - Buffer where the pseudorandom bytes will be written.
pub fn xof_get_bytes(reader: &mut impl XofReader, output: &mut [u8]) {
    reader.read(output);
}

/// Computes the hash function I (SHA3-512) with domain separation.
///
/// # Arguments
/// * `seed` - The input seed to be hashed.
///
/// # Returns
/// A 64-byte SHA3-512 hash output.
pub fn hash_i(seed: &[u8; SEED_BYTES]) -> [u8; 64] {
    let i_domain = I_FCT_DOMAIN;
    let mut hasher = Sha3_512::new();
    sha3::digest::Update::update(&mut hasher, seed);
    sha3::digest::Update::update(&mut hasher, &[i_domain]);
    sha3::digest::FixedOutput::finalize_fixed(hasher).into()
}

/// Computes the hash function G (SHA3-512) with domain separation.
///
/// # Arguments
/// * `hash_ek_kem` - Hash of the KEM encapsulation key, `SEED_BYTES` bytes.
/// * `m`           - Message bytes, `PARAM_SECURITY_BYTES` bytes.
/// * `salt`        - Salt value, `SALT_BYTES` bytes.
///
/// # Returns
/// 64-byte SHA3-512 hash output.
pub fn hash_g(
    hash_ek_kem: &[u8; SEED_BYTES],
    m: &[u8; PARAM_SECURITY_BYTES],
    salt: &[u8; SALT_BYTES],
) -> [u8; 64] {
    let g_domain = G_FCT_DOMAIN;

    let mut hasher = Sha3_512::new();
    hasher.update(hash_ek_kem);
    hasher.update(m);
    hasher.update(salt);
    hasher.update([g_domain]);
    hasher.finalize().into()
}

/// Computes the hash function H (SHA3-256) with domain separation.
///
/// # Arguments
/// * `ek_kem` - Encapsulation key of the KEM, `PUBLIC_KEY_BYTES` bytes.
///
/// # Returns
/// 32-byte SHA3-256 hash output.
pub fn hash_h(ek_kem: &[u8]) -> [u8; 32] {
    let h_domain = H_FCT_DOMAIN;

    let mut hasher = Sha3_256::new();
    hasher.update(ek_kem);
    hasher.update([h_domain]);
    hasher.finalize().into()
}

/// Computes the hash function J (SHA3-256) with domain separation.
///
/// # Arguments
/// * `hash_ek_kem` - Hash of the KEM encapsulation key, `SEED_BYTES` bytes.
/// * `sigma`       - The string sigma, `PARAM_SECURITY_BYTES` bytes.
/// * `c_kem`       - Ciphertext struct (includes `c_pke.u`, `c_pke.v`, and `salt`).
///
/// # Returns
/// 32-byte SHA3-256 hash output.
pub fn hash_j(
    hash_ek_kem: &[u8; SEED_BYTES],
    sigma: &[u8; PARAM_SECURITY_BYTES],
    c_kem: &CiphertextKem,
) -> [u8; 32] {
    let k_domain = J_FCT_DOMAIN;

    let u_bytes = u64_words_to_bytes(&c_kem.c_pke.u);
    let v_bytes = u64_words_to_bytes(&c_kem.c_pke.v);

    let mut hasher = Sha3_256::new();
    hasher.update(hash_ek_kem);
    hasher.update(sigma);
    hasher.update(&u_bytes[..VEC_N_SIZE_BYTES]);
    hasher.update(&v_bytes[..VEC_N1N2_SIZE_BYTES]);
    hasher.update(&c_kem.salt);
    hasher.update([k_domain]);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests;
