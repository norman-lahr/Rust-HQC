use crate::parameters::{PARAM_GF_POLY, PARAM_M};

/// Generates exp and log lookup tables of GF(2^m).
///
/// Note: This function is not used in the code; it was used to generate
/// the lookup table for GF(2^8).
///
/// The logarithm of 0 is defined as 2^8 by convention.
/// The last two elements of the exp table are needed by `gf_mul`.
///
/// # Arguments
/// * `m` - Parameter of Galois field GF(2^m).
///
/// # Returns
/// A tuple `(exp, log)` where:
/// * `exp` - Array of size `2^m + 2` containing powers of the primitive element.
/// * `log` - Array of size `2^m` containing logarithms of GF(2^m) elements.
pub fn gf_generate(m: u16) -> (Vec<u16>, Vec<u16>) {
    let field_size = 1usize << m;
    let mut exp = vec![0u16; field_size + 2];
    let mut log = vec![0u16; field_size];

    let alpha: u16 = 2; // primitive element of GF(2^m)
    let gf_poly: u16 = PARAM_GF_POLY as u16; // generator polynomial of GF(2^PARAM_M)
    let mut elt: u16 = 1;

    for i in 0..field_size - 1 {
        exp[i] = elt;
        log[elt as usize] = i as u16;

        elt = elt.wrapping_mul(alpha);
        if elt >= (1 << m) {
            elt ^= gf_poly;
        }
    }

    exp[field_size - 1] = 1;
    exp[field_size] = 2;
    exp[field_size + 1] = 4;
    log[0] = 0; // by convention

    (exp, log)
}

/// Feedback bit positions used for modular reduction by `PARAM_GF_POLY` = 0x11D.
///
/// These values are derived from the binary form of the polynomial:
/// `0x11D = 0b100011101` → bits set at positions: 8, 4, 3, 1, 0.
///
/// To reduce a polynomial modulo this irreducible polynomial:
/// - Bit 8 (the leading term) is handled via shifting: `mod = x >> 8`
/// - Bit 0 (constant term) is handled by the initial XOR
///
/// The remaining set bits at positions 4, 3, and 2 define where the shifted
/// high bits (`mod`) must be XORed back into the result. These represent the
/// feedback positions used during reduction.
pub const GF_REDUCTION_TAPS: [u8; 3] = [4, 3, 2];

/// Reduces a polynomial modulo `PARAM_GF_POLY` in GF(2^8).
///
/// Performs modular reduction of a 16-bit polynomial `x`
/// by the irreducible polynomial `PARAM_GF_POLY` = 0x11D
/// (i.e., x⁸ + x⁴ + x³ + x + 1), used in GF(2^8).
///
/// Assumes the input polynomial has degree ≤ 14 and uses a fixed
/// number of reduction steps and fixed feedback tap positions
/// (`{4, 3, 2}`) to produce a result of degree < 8.
///
/// # Arguments
/// * `x` - 16-bit input polynomial to reduce (deg(x) ≤ 14).
///
/// # Returns
/// Reduced 8-bit polynomial modulo `PARAM_GF_POLY` (deg(x) < 8).
pub fn gf_reduce(mut x: u16) -> u16 {
    const REDUCTION_STEPS: usize = 2; // deg(x) = 2*(8-1) = 14 → reduce twice
    const TAP_COUNT: usize = 3; // number of feedback positions

    for _ in 0..REDUCTION_STEPS {
        let mut m: u64 = (x >> PARAM_M) as u64; // extract upper bits
        x &= (1u16 << PARAM_M) - 1; // keep lower bits
        x ^= m as u16; // pre-XOR with no shift

        let mut z1: u16 = 0;
        for j in (0..TAP_COUNT).rev() {
            let z2 = GF_REDUCTION_TAPS[j] as u16;
            let dist = z2 - z1;
            m <<= dist;
            x ^= m as u16;
            z1 = z2;
        }
    }

    x
}

#[cfg(test)]
mod tests;
