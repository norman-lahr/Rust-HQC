use crate::parameters::{
    PARAM_SECURITY_BYTES, PUBLIC_KEY_BYTES, SALT_BYTES, SEED_BYTES, SHARED_SECRET_BYTES,
    VEC_N1N2_SIZE_BYTES, VEC_N_SIZE_BYTES,
};
use crate::parsing::{hqc_c_kem_from_string, hqc_c_kem_to_string};
use crate::pke::{hqc_pke_decrypt, hqc_pke_encrypt, hqc_pke_keygen, CiphertextPke};
use crate::symmetric::{hash_g, hash_h, hash_j, prng_get_bytes, xof_get_bytes, xof_init};
use crate::vector::vect_compare;
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

/// Performs key decapsulation using the KEM scheme.
///
/// Uses the decapsulation key (`dk_kem`) to recover the shared secret
/// (`K_prime`) from the given KEM ciphertext (`c_kem`).
///
/// Constant-time with respect to `dk_kem`, `c_kem`, and derived secret
/// material: the final re-encryption check uses branchless bitmasking
/// (`vect_compare`, `result` accumulation) rather than a data-dependent
/// branch, matching the C implicit-rejection pattern (Fujisaki-Okamoto
/// transform). Sensitive intermediate data is zeroized before returning.
///
/// # Arguments
/// * `c_kem`  - Input KEM ciphertext.
/// * `dk_kem` - Decapsulation key.
///
/// # Returns
/// The recovered (or rejection) shared secret `K_prime` of
/// `SHARED_SECRET_BYTES` bytes.
pub fn crypto_kem_dec(c_kem: &[u8], dk_kem: &[u8]) -> Vec<u8> {
    // Parse decapsulation key dk_kem
    let ek_pke = &dk_kem[..PUBLIC_KEY_BYTES];
    let mut dk_pke: [u8; SEED_BYTES] = dk_kem[PUBLIC_KEY_BYTES..PUBLIC_KEY_BYTES + SEED_BYTES]
        .try_into()
        .unwrap();
    let mut sigma: [u8; PARAM_SECURITY_BYTES] = dk_kem
        [PUBLIC_KEY_BYTES + SEED_BYTES..PUBLIC_KEY_BYTES + SEED_BYTES + PARAM_SECURITY_BYTES]
        .try_into()
        .unwrap();

    // Parse ciphertext c_kem
    let (c_pke, salt) = hqc_c_kem_from_string(c_kem);
    let c_kem_t = CiphertextKem { c_pke, salt };

    // Compute message m_prime
    let mut m_prime = hqc_pke_decrypt(&dk_pke, &c_kem_t.c_pke);

    // Compute shared key K_prime and ciphertext c_kem_prime
    let hash_ek_kem = hash_h(ek_pke);

    let m_prime_bytes: Vec<u8> = m_prime.iter().flat_map(|w| w.to_le_bytes()).collect();
    let m_prime_arr: [u8; PARAM_SECURITY_BYTES] =
        m_prime_bytes[..PARAM_SECURITY_BYTES].try_into().unwrap();

    let mut k_theta_prime = hash_g(&hash_ek_kem, &m_prime_arr, &c_kem_t.salt);

    let mut k_prime = k_theta_prime[..SHARED_SECRET_BYTES].to_vec();
    let mut theta_prime = [0u8; SEED_BYTES];
    theta_prime
        .copy_from_slice(&k_theta_prime[SHARED_SECRET_BYTES..SHARED_SECRET_BYTES + SEED_BYTES]);

    let c_pke_prime = hqc_pke_encrypt(ek_pke, &m_prime, &theta_prime);
    let c_kem_prime_t = CiphertextKem {
        c_pke: c_pke_prime,
        salt: c_kem_t.salt,
    };

    // Compute rejection key K_bar
    let mut k_bar = hash_j(&hash_ek_kem, &sigma, &c_kem_t).to_vec();

    // Constant-time comparison — implicit rejection (branchless)
    let u_bytes: Vec<u8> = c_kem_t
        .c_pke
        .u
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    let up_bytes: Vec<u8> = c_kem_prime_t
        .c_pke
        .u
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    let v_bytes: Vec<u8> = c_kem_t
        .c_pke
        .v
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    let vp_bytes: Vec<u8> = c_kem_prime_t
        .c_pke
        .v
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();

    let mut result: u8 = vect_compare(&u_bytes[..VEC_N_SIZE_BYTES], &up_bytes[..VEC_N_SIZE_BYTES]);
    result |= vect_compare(
        &v_bytes[..VEC_N1N2_SIZE_BYTES],
        &vp_bytes[..VEC_N1N2_SIZE_BYTES],
    );
    result |= vect_compare(&c_kem_t.salt, &c_kem_prime_t.salt);
    let result: u8 = result.wrapping_sub(1); // 0xFF if all matched, 0x00 if any mismatched

    for i in 0..SHARED_SECRET_BYTES {
        k_prime[i] = (k_prime[i] & result) ^ (k_bar[i] & !result);
    }

    // Zeroize sensitive data
    dk_pke.iter_mut().for_each(|b| *b = 0);
    sigma.iter_mut().for_each(|b| *b = 0);
    m_prime.iter_mut().for_each(|w| *w = 0);
    k_theta_prime.iter_mut().for_each(|b| *b = 0);
    k_bar.iter_mut().for_each(|b| *b = 0);
    theta_prime.iter_mut().for_each(|b| *b = 0);

    k_prime
}

#[cfg(all(test, feature = "ref-ffi"))]
mod tests_ffi;

#[cfg(test)]
mod tests_kat;
