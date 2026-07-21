use crate::parameters::{PARAM_SECURITY_BYTES, SALT_BYTES, SEED_BYTES};
use sha3::digest::XofReader;
use sha3::{Digest, Sha3_512, Shake256};

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

#[cfg(test)]
mod tests;
