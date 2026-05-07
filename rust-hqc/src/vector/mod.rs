use crate::parameters::*;
use sha3::digest::XofReader;

/// Constant-time equality comparison for u32 values.
///
/// # Returns
/// `0xFFFFFFFF` if `a == b`, `0x00000000` otherwise.
#[inline]
pub fn compare_u32(a: u32, b: u32) -> u32 {
    let diff: u32 = a.wrapping_sub(b) | b.wrapping_sub(a);
    // If a == b: diff == 0, MSB of -diff is 0 → result is 0
    // If a != b: diff != 0, MSB of -diff is 1 → result is 0xFFFFFFFF
    1u32 ^ (diff >> 31)
}

/// Constant-time Barrett reduction modulo `PARAM_N`.
///
/// Reduces `x` modulo `PARAM_N` using the precomputed value
/// `PARAM_N_MU = ⌊2^32 / PARAM_N⌋`.
///
/// # Arguments
/// * `x` - Input value to reduce.
///
/// # Returns
/// `x mod PARAM_N` in constant time.
#[inline]
pub fn barrett_reduce(x: u32) -> u32 {
    let q = ((x as u64) * (PARAM_N_MU as u64)) >> 32;
    let r = x.wrapping_sub((q as u32).wrapping_mul(PARAM_N as u32));
    let reduce_flag = ((r.wrapping_sub(PARAM_N as u32)) >> 31) ^ 1;
    let mask = reduce_flag.wrapping_neg();
    r.wrapping_sub(mask & PARAM_N as u32)
}

/// Generates a random support set with uniform and unbiased sampling.
///
/// Implements a rejection sampling algorithm to generate `weight`
/// distinct indices uniformly at random from the interval `[0, PARAM_N)`.
///
///  Internally, it samples 24-bit random values and rejects any value ≥ UTILS_REJECTION_THRESHOLD,
/// where the threshold is precomputed as:
/// \f[
///   t = \left\lfloor \frac{2^{24}}{\text{PARAM\_N}} \right\rfloor \times \text{PARAM\_N}
/// \f]
///
/// # Arguments
/// * `reader` - SHAKE256 XOF reader used for random byte generation.
/// * `weight` - Desired Hamming weight (number of distinct indices).
///
/// # Returns
/// A `Vec<u32>` containing `weight` unique indices.
pub fn vect_generate_random_support1(reader: &mut impl XofReader, weight: usize) -> Vec<u32> {
    let mut support = Vec::with_capacity(weight);

    while support.len() < weight {
        // Sample 3 random bytes and combine into a 24-bit value
        let mut rand_bytes = [0u8; 3];
        reader.read(&mut rand_bytes);
        let candidate =
            (rand_bytes[0] as u32) | ((rand_bytes[1] as u32) << 8) | ((rand_bytes[2] as u32) << 16);

        // Rejection sampling — discard values above threshold
        if candidate >= UTILS_REJECTION_THRESHOLD {
            continue;
        }

        let candidate = barrett_reduce(candidate);

        // Only accept if not already in support (uniqueness check)
        if !support.contains(&candidate) {
            support.push(candidate);
        }
    }

    support
}

/// Generates a random support set of distinct indices.
///
/// Implements the **GenerateRandomSupport** algorithm from the specification.
///
/// # Arguments
/// * `reader` - Initialized SHAKE256 XOF reader used for randomness.
/// * `weight` - Number of elements to generate (Hamming weight).
///
/// # Returns
/// A `Vec<u32>` of `weight` unique indices.
pub fn vect_generate_random_support2(reader: &mut impl XofReader, weight: usize) -> Vec<u32> {
    // Read bytes then convert explicitly (little-endian)
    let mut rand_bytes = vec![0u8; 4 * weight];
    reader.read(&mut rand_bytes);
    let rand_u32: Vec<u32> = rand_bytes
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect();

    // Phase 1: Initial index assignment using scaling
    let mut support = vec![0u32; weight];
    for i in 0..weight {
        let buff = rand_u32[i] as u64;
        support[i] = i as u32 + ((buff * (PARAM_N as u64 - i as u64)) >> 32) as u32;
    }

    // Phase 2: Constant-time collision resolution (backwards pass)
    for i in (0..weight.saturating_sub(1)).rev() {
        // runs [weight-2, weight-3, ..., 1, 0]
        let mut found = 0u32;
        for j in (i + 1)..weight {
            found |= compare_u32(support[j], support[i]);
        }
        // Constant-time conditional assignment:
        // if found: support[i] = i
        // if !found: support[i] = support[i]  (unchanged)
        let mask = found.wrapping_neg();
        support[i] = (mask & i as u32) ^ (!mask & support[i]);
    }

    support
}

/// Sets bits in a vector based on a support set.
///
/// Writes `weight` positions from `support` into the bit-vector `v`.
/// Each index in `support` sets a corresponding bit in `v`.
///
/// # Arguments
/// * `v`       - Output bit-vector of `VEC_N_SIZE_64` 64-bit words.
/// * `support` - Slice of bit indices to set, from `vect_generate_random_support`.
pub fn vect_write_support_to_vector(v: &mut [u64; VEC_N_SIZE_64], support: &[u32]) {
    // Precompute word indices and bit masks for each support position
    let mut index_tab = [0u32; PARAM_OMEGA_R];
    let mut bit_tab = [0u64; PARAM_OMEGA_R];

    for (i, &s) in support.iter().enumerate() {
        index_tab[i] = s >> 6; // which 64-bit word of the PARAM_N-bit vector.
        let pos = (s & 0x3f) as u64; // which bit within the word
        bit_tab[i] = 1u64 << pos; // TODO Prone to platform-dependent timing attack!

        // // Build the bit mask purely from arithmetic — no shift with secret amount
        //  let mut bit = 0u64;
        //  for b in 0u32..64 {
        //      let matches = (b.wrapping_sub(pos) | pos.wrapping_sub(b)).wrapping_neg() >> 31;
        //      // matches == 0xFFFFFFFF if b == pos, else 0
        //      bit |= (1u64 << b) & (matches as u64);
        //  }
        //  bit_tab[i] = bit;
    }

    // For each 64-bit word, accumulate bits from matching support entries
    for i in 0..VEC_N_SIZE_64 {
        let mut val = 0u64;
        for j in 0..support.len() {
            let tmp = (i as u32).wrapping_sub(index_tab[j]);
            // val1 == 1 if tmp == 0 (i.e. word index matches), else 0
            let val1 = 1u32 ^ ((tmp | tmp.wrapping_neg()) >> 31);
            let mask = (val1 as u64).wrapping_neg();
            val |= bit_tab[j] & mask;
        }
        v[i] |= val;
    }
}

/// Generates a random binary vector of fixed Hamming weight.
///
/// Samples a binary vector with exactly `weight` bits set to 1, where
/// positions are chosen uniformly at random without bias.
///
/// Used exclusively during **key generation** to generate vectors **x** and **y**.
///
/// # Arguments
/// * `reader` - A previously initialized SHAKE-256 XOF reader.
/// * `weight` - Desired Hamming weight.
///
/// # Returns
/// A bit-vector of `VEC_N_SIZE_64` 64-bit words with exactly `weight` bits set.
pub fn vect_sample_fixed_weight1(
    reader: &mut impl XofReader,
    weight: usize,
) -> [u64; VEC_N_SIZE_64] {
    let support = vect_generate_random_support1(reader, weight);
    let mut v = [0u64; VEC_N_SIZE_64];
    vect_write_support_to_vector(&mut v, &support);
    v
}

/// Generates a random binary vector of fixed Hamming weight.
///
/// Implementation of Algorithm 5 in <https://eprint.iacr.org/2021/1631.pdf>
///
/// Used exclusively during **encryption** to generate vectors **r1**, **r2**, and **e**.
///
/// # Arguments
/// * `reader` - A previously initialized SHAKE-256 XOF reader.
/// * `weight` - Desired Hamming weight.
///
/// # Returns
/// A bit-vector of `VEC_N_SIZE_64` 64-bit words with exactly `weight` bits set.
pub fn vect_sample_fixed_weight2(
    reader: &mut impl XofReader,
    weight: usize,
) -> [u64; VEC_N_SIZE_64] {
    let support = vect_generate_random_support2(reader, weight);
    let mut v = [0u64; VEC_N_SIZE_64];
    vect_write_support_to_vector(&mut v, &support);
    v
}

/// Generates a random vector of dimension `PARAM_N`.
///
/// Generates a random binary vector of dimension `PARAM_N` by reading
/// random bytes from the XOF and masking off the extra bits in the
/// last 64-bit word.
///
/// # Arguments
/// * `reader` - Initialized SHAKE256 XOF reader.
///
/// # Returns
/// A random bit-vector of `VEC_N_SIZE_64` 64-bit words.
pub fn vect_set_random(reader: &mut impl XofReader) -> [u64; VEC_N_SIZE_64] {
    // Read random bytes safely
    let mut rand_bytes = [0u8; VEC_N_SIZE_BYTES];
    reader.read(&mut rand_bytes);

    // Convert bytes to u64 words in little-endian to match C behavior
    let mut v = [0u64; VEC_N_SIZE_64];

    for (i, chunk) in rand_bytes.chunks_exact(8).enumerate() {
        v[i] = u64::from_le_bytes(chunk.try_into().unwrap()); // ← always 8 bytes
    }
    // Handle remainder once, outside the loop
    let remainder = VEC_N_SIZE_BYTES % 8;
    if remainder > 0 {
        let mut last = [0u8; 8];
        last[..remainder].copy_from_slice(&rand_bytes[VEC_N_SIZE_BYTES - remainder..]);
        v[VEC_N_SIZE_64 - 1] = u64::from_le_bytes(last);
    }

    // Mask off bits beyond PARAM_N in the last word
    v[VEC_N_SIZE_64 - 1] &= bitmask(PARAM_N, 64);

    v
}

#[cfg(test)]
mod tests;
