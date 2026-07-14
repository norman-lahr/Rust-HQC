use crate::parameters::VEC_N1_SIZE_64;

mod reed_muller;
mod reed_solomon;

/// Encodes the message `m` to a codeword `em` using the concatenated code.
///
/// First encodes the message using the Reed-Solomon code, then applies
/// the duplicated Reed-Muller code to obtain the concatenated codeword.
///
/// # Arguments
/// * `m` - Input message of `VEC_K_SIZE_64` 64-bit words.
///
/// # Returns
/// Encoded codeword of `VEC_N1N2_SIZE_64` 64-bit words.
pub fn code_encode(m: &[u64]) -> Vec<u64> {
    let mut tmp: [u64; VEC_N1_SIZE_64] = reed_solomon::reed_solomon_encode(m)
        .try_into()
        .expect("reed_solomon_encode must return VEC_N1_SIZE_64 words");

    let em = reed_muller::reed_muller_encode(&tmp);

    // Zeroize sensitive data
    tmp.iter_mut().for_each(|w| *w = 0);

    em.to_vec()
}

#[cfg(test)]
mod tests;
