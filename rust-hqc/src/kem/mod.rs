use crate::parameters::{PARAM_SECURITY_BYTES, PUBLIC_KEY_BYTES, SALT_BYTES, SEED_BYTES};
use crate::pke::{hqc_pke_keygen, CiphertextPke};
use crate::symmetric::{prng_get_bytes, xof_get_bytes, xof_init};
use sha3::digest::XofReader;

/// KEM ciphertext for the HQC scheme.
#[repr(C)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CiphertextKem {
    pub c_pke: CiphertextPke,
    pub salt: [u8; SALT_BYTES],
}

/// Generates a keypair for the KEM (Key Encapsulation Mechanism) scheme.
///
/// Generates a public/private keypair used for key encapsulation and
/// decapsulation. The encapsulation key (`ek_kem`) is used to encapsulate
/// a shared secret, while the decapsulation key (`dk_kem`) is used to
/// recover it.
///
/// # Preconditions
/// `prng_reader` must be an already-initialized PRNG (via `prng_init`),
/// seeded from a secure entropy source; otherwise the generated keys
/// will be insecure/predictable.
///
/// # Arguments
/// * `prng_reader` - An initialized PRNG reader used to sample `seed_kem`.
///
/// # Returns
/// A tuple `(ek_kem, dk_kem)`.
pub fn crypto_kem_keypair(prng_reader: &mut impl XofReader) -> (Vec<u8>, Vec<u8>) {
    // Sample seed_kem
    let seed_kem_vec = prng_get_bytes(prng_reader, SEED_BYTES);
    let mut seed_kem: [u8; SEED_BYTES] = seed_kem_vec.try_into().unwrap();

    // Compute seed_pke and randomness sigma
    let mut seed_pke = [0u8; SEED_BYTES];
    let mut sigma = [0u8; PARAM_SECURITY_BYTES];
    {
        let mut ctx_kem = xof_init(&seed_kem);
        xof_get_bytes(&mut ctx_kem, &mut seed_pke);
        xof_get_bytes(&mut ctx_kem, &mut sigma);
    }
    // Compute HQC-PKE keypair
    let (ek_pke, mut dk_pke) = hqc_pke_keygen(&seed_pke);

    // Compute HQC-KEM keypair
    let ek_kem = ek_pke.clone();
    let mut dk_kem =
        Vec::with_capacity(PUBLIC_KEY_BYTES + SEED_BYTES + PARAM_SECURITY_BYTES + SEED_BYTES);
    dk_kem.extend_from_slice(&ek_kem);
    dk_kem.extend_from_slice(&dk_pke);
    dk_kem.extend_from_slice(&sigma);
    dk_kem.extend_from_slice(&seed_kem);

    // Zeroize sensitive data
    seed_kem.iter_mut().for_each(|b| *b = 0);
    sigma.iter_mut().for_each(|b| *b = 0);
    seed_pke.iter_mut().for_each(|b| *b = 0);
    dk_pke.iter_mut().for_each(|b| *b = 0);

    (ek_kem, dk_kem)
}

#[cfg(test)]
mod tests;
