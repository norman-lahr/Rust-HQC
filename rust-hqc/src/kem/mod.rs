use crate::parameters::{
    PARAM_SECURITY_BYTES, PUBLIC_KEY_BYTES, SALT_BYTES, SEED_BYTES, SHARED_SECRET_BYTES,
};
use crate::parsing::hqc_c_kem_to_string;
use crate::pke::{hqc_pke_encrypt, hqc_pke_keygen, CiphertextPke};
use crate::symmetric::{hash_g, hash_h, prng_get_bytes, xof_get_bytes, xof_init};
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

/// Performs key encapsulation using the KEM scheme.
///
/// Uses the encapsulation key (`ek_kem`) to generate a ciphertext
/// (`c_kem`) and a shared secret (`K`).
///
/// # Preconditions
/// `prng_reader` must be an already-initialized PRNG (via `prng_init`),
/// seeded from a secure entropy source; otherwise the generated message
/// and salt will be insecure/predictable.
///
/// # Arguments
/// * `prng_reader` - An initialized PRNG reader used to sample `m` and `salt`.
/// * `ek_kem`       - Encapsulation key.
///
/// # Returns
/// A tuple `(c_kem, K)`:
/// * `c_kem` - Serialized KEM ciphertext.
/// * `K`     - Shared secret of `SHARED_SECRET_BYTES` bytes.
pub fn crypto_kem_enc(prng_reader: &mut impl XofReader, ek_kem: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Sample message m and salt
    let m_vec = prng_get_bytes(prng_reader, PARAM_SECURITY_BYTES);
    let mut m: [u8; PARAM_SECURITY_BYTES] = m_vec.try_into().unwrap();

    let mut c_kem_t = CiphertextKem::default();
    let salt_vec = prng_get_bytes(prng_reader, SALT_BYTES);
    c_kem_t.salt.copy_from_slice(&salt_vec);

    // Compute shared key K and ciphertext c_kem
    let hash_ek_kem = hash_h(ek_kem);

    let m_arr: [u8; PARAM_SECURITY_BYTES] = m;
    let mut k_theta = hash_g(&hash_ek_kem, &m_arr, &c_kem_t.salt);

    let mut theta = [0u8; SEED_BYTES];
    theta.copy_from_slice(&k_theta[SEED_BYTES..SEED_BYTES + SEED_BYTES]);

    // Reinterpret m as u64 words for hqc_pke_encrypt
    let m_words: Vec<u64> = m
        .chunks(8)
        .map(|chunk| {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            u64::from_le_bytes(buf)
        })
        .collect();

    c_kem_t.c_pke = hqc_pke_encrypt(ek_kem, &m_words, &theta);

    let c_kem = hqc_c_kem_to_string(&c_kem_t);
    let k = k_theta[..SHARED_SECRET_BYTES].to_vec();

    // Zeroize sensitive data
    m.iter_mut().for_each(|b| *b = 0);
    k_theta.iter_mut().for_each(|b| *b = 0);
    theta.iter_mut().for_each(|b| *b = 0);

    (c_kem, k)
}

#[cfg(test)]
mod tests;
