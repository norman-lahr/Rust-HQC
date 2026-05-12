use crate::parameters::*;

/// Input size in words below which schoolbook_mul is used.
const KARATSUBA_THRESHOLD: usize = 16;

/// Total size in 64-bit words for the temporary buffer used by recursive Karatsuba.
const TMP_BUFFER_WORDS: usize = 16 * VEC_N_SIZE_64;

/// Schoolbook multiplication over GF(2).
///
/// Computes `r = a * b` where `a`, `b` are length-`n` words.
/// Result `r` is `2*n` words.
///
/// Constant-time: no secret-dependent branches or memory accesses.
///
/// # Arguments
/// * `r` - Result buffer of `2*n` 64-bit words.
/// * `a` - Operand a of `n` 64-bit words.
/// * `b` - Operand b of `n` 64-bit words.
pub fn schoolbook_mul(r: &mut [u64], a: &[u64], b: &[u64]) {
    let n = a.len();

    // Zero the result buffer
    r.fill(0);

    for i in 0..n {
        let ai = a[i];
        for bit in 0..64u32 {
            // Constant-time mask: all 1s if bit is set, all 0s otherwise
            // No branch on secret data
            let mask = ((ai >> bit) & 1u64).wrapping_neg();

            let base = i;
            let sh = bit;
            let inv = 64 - sh;

            if sh == 0 {
                // No shift needed — bit 0
                for j in 0..n {
                    r[base + j] ^= b[j] & mask;
                }
            } else {
                for j in 0..n {
                    r[base + j] ^= (b[j] << sh) & mask;
                    r[base + j + 1] ^= (b[j] >> inv) & mask;
                }
            }
        }
    }
}

/// Karatsuba multiplication over GF(2) with caller-supplied temporary buffer.
///
/// Falls back to `schoolbook_mul` when `n <= KARATSUBA_THRESHOLD`.
/// Otherwise splits operands in half and applies recursion.
///
/// # Arguments
/// * `r`          - Result buffer of `2*n` 64-bit words.
/// * `a`          - Operand a of `n` 64-bit words.
/// * `b`          - Operand b of `n` 64-bit words.
/// * `n`          - Size of `a`and `b` in 64-bit words.
/// * `tmp_buffer` - Temporary buffer of at least `8*n` words.
pub fn karatsuba_mul(r: &mut [u64], a: &[u64], b: &[u64], n: usize, tmp_buffer: &mut [u64]) {
    // let n = a.len();

    // Base case — fall back to schoolbook multiplication
    if n <= KARATSUBA_THRESHOLD {
        schoolbook_mul(r, a, b);
        return;
    }

    let m = n >> 1; // low half size
    let n0 = m; // low half size
    let n1 = n - m; // high half size (may be larger by 1)

    // Carve successive chunks out of tmp_buffer:
    // z0   [0      .. 2*n)      low * low        (2*n words)
    // z2   [2*n    .. 4*n)      high * high      (2*n words)
    // zmid [4*n    .. 6*n)      middle product   (2*n words)
    // ta   [6*n    .. 6*n+n1)   a0 ^ a1          (n1 words)
    // tb   [6*n+n1 .. 6*n+2*n1) b0 ^ b1          (n1 words)
    // child_buffer [8*n ..)     for child calls
    let (z0, rest) = tmp_buffer.split_at_mut(2 * n);
    let (z2, rest) = rest.split_at_mut(2 * n);
    let (zmid, rest) = rest.split_at_mut(2 * n);
    let (ta, rest) = rest.split_at_mut(n1);
    let (tb, child_buffer) = rest.split_at_mut(n1);

    // 1) low * low: z0 = a[0..n0] * b[0..n0]
    karatsuba_mul(z0, &a[..n0], &b[..n0], n0, child_buffer);

    // 2) high * high: z2 = a[m..] * b[m..]
    karatsuba_mul(z2, &a[m..], &b[m..], n1, child_buffer);

    // 3) compute ta = a0 ^ a1, tb = b0 ^ b1
    for i in 0..n1 {
        let loa = if i < n0 { a[i] } else { 0 };
        let lob = if i < n0 { b[i] } else { 0 };
        ta[i] = loa ^ a[m + i];
        tb[i] = lob ^ b[m + i];
    }

    // zmid = ta * tb = (a0^a1) * (b0^b1)
    karatsuba_mul(zmid, ta, tb, n1, child_buffer);

    // 4) assemble result into r
    r.fill(0);

    // r ^= z0 (low product at offset 0)
    for i in 0..2 * n0 {
        r[i] ^= z0[i];
    }

    // r ^= z2 (high product at offset 2*m)
    for i in 0..2 * n1 {
        r[2 * m + i] ^= z2[i];
    }

    // r ^= middle term at offset m
    // mid[i] = zmid[i] ^ z0[i] ^ z2[i]
    for i in 0..2 * n1 {
        let z0i = if i < 2 * n0 { z0[i] } else { 0 };
        let z2i = if i < 2 * n1 { z2[i] } else { 0 };
        let mid = zmid[i] ^ z0i ^ z2i;
        r[m + i] ^= mid;
    }
}

/// Modular reduction of a degree < 2n polynomial mod (X^n - 1).
///
/// Folds the high half of the full product back into the low half
/// and masks any excess bits in the last word.
///
/// # Arguments
/// * `o` - Result buffer of `VEC_N_SIZE_64` 64-bit words.
/// * `a` - Input buffer of `2 * VEC_N_SIZE_64` 64-bit words.
pub fn reduce(o: &mut [u64; VEC_N_SIZE_64], a: &[u64]) {
    assert_eq!(
        a.len(),
        2 * VEC_N_SIZE_64,
        "input must have length 2 * VEC_N_SIZE_64"
    );

    for i in 0..VEC_N_SIZE_64 {
        let r = a[i + VEC_N_SIZE_64 - 1] >> (PARAM_N & 0x3F);
        let carry = a[i + VEC_N_SIZE_64] << (64 - (PARAM_N & 0x3F));
        o[i] = a[i] ^ r ^ carry;
    }

    // Mask off bits beyond PARAM_N in the last word
    o[VEC_N_SIZE_64 - 1] &= bitmask(PARAM_N, 64);
}

/// Carry-less multiplication mod (X^PARAM_N - 1).
///
/// Computes `o = a1 * a2` over GF(2) mod (X^PARAM_N - 1).
///
/// # Arguments
/// * `a1` - Operand polynomial a(x) of `VEC_N_SIZE_64` 64-bit words.
/// * `a2` - Operand polynomial b(x) of `VEC_N_SIZE_64` 64-bit words.
///
/// # Returns
/// Result of `VEC_N_SIZE_64` 64-bit words.
pub fn vect_mul(a1: &[u64; VEC_N_SIZE_64], a2: &[u64; VEC_N_SIZE_64]) -> [u64; VEC_N_SIZE_64] {
    // Step 1: Multiply via Karatsuba into unreduced buffer
    let mut unreduced = vec![0u64; 2 * VEC_N_SIZE_64];
    let mut tmp_buffer = vec![0u64; TMP_BUFFER_WORDS];
    karatsuba_mul(&mut unreduced, a1, a2, VEC_N_SIZE_64, &mut tmp_buffer);

    // Step 2: Reduce modulo X^PARAM_N - 1
    let mut o = [0u64; VEC_N_SIZE_64];
    reduce(&mut o, &unreduced);
    o
}

#[cfg(test)]
mod tests;
