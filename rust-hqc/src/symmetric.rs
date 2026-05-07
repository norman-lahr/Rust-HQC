use crate::parameters::SEED_BYTES;
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

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" {
        fn hash_i(output: *mut u8, seed: *const u8);
    }

    /// Safe wrapper around the C hash_i function
    fn hash_i_ref(seed: &[u8]) -> [u8; 64] {
        let mut output = [0u8; 64];
        unsafe {
            hash_i(output.as_mut_ptr(), seed.as_ptr());
        }
        output
    }

    #[test]
    fn test_hash_i() {
        let seed = b"DEADBEEFDEADBEEFDEADBEEFDEADBEEF";
        let digest = crate::symmetric::hash_i(seed);
        let digest_ref = hash_i_ref(seed);
        assert_eq!(digest, digest_ref, "Both digest should be equal");
    }
}
