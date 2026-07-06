use crate::parameters::{PARAM_GF_POLY, PARAM_M};

/// Powers of the root alpha of 1 + x^2 + x^3 + x^4 + x^8.
///
/// The last two elements are needed by `gf_mul`
/// (for example if both elements to multiply are zero).
pub const GF_EXP: [u16; 258] = [
    1, 2, 4, 8, 16, 32, 64, 128, 29, 58, 116, 232, 205, 135, 19, 38, 76, 152, 45, 90, 180, 117,
    234, 201, 143, 3, 6, 12, 24, 48, 96, 192, 157, 39, 78, 156, 37, 74, 148, 53, 106, 212, 181,
    119, 238, 193, 159, 35, 70, 140, 5, 10, 20, 40, 80, 160, 93, 186, 105, 210, 185, 111, 222, 161,
    95, 190, 97, 194, 153, 47, 94, 188, 101, 202, 137, 15, 30, 60, 120, 240, 253, 231, 211, 187,
    107, 214, 177, 127, 254, 225, 223, 163, 91, 182, 113, 226, 217, 175, 67, 134, 17, 34, 68, 136,
    13, 26, 52, 104, 208, 189, 103, 206, 129, 31, 62, 124, 248, 237, 199, 147, 59, 118, 236, 197,
    151, 51, 102, 204, 133, 23, 46, 92, 184, 109, 218, 169, 79, 158, 33, 66, 132, 21, 42, 84, 168,
    77, 154, 41, 82, 164, 85, 170, 73, 146, 57, 114, 228, 213, 183, 115, 230, 209, 191, 99, 198,
    145, 63, 126, 252, 229, 215, 179, 123, 246, 241, 255, 227, 219, 171, 75, 150, 49, 98, 196, 149,
    55, 110, 220, 165, 87, 174, 65, 130, 25, 50, 100, 200, 141, 7, 14, 28, 56, 112, 224, 221, 167,
    83, 166, 81, 162, 89, 178, 121, 242, 249, 239, 195, 155, 43, 86, 172, 69, 138, 9, 18, 36, 72,
    144, 61, 122, 244, 245, 247, 243, 251, 235, 203, 139, 11, 22, 44, 88, 176, 125, 250, 233, 207,
    131, 27, 54, 108, 216, 173, 71, 142, 1, 2, 4,
];

/// Logarithm of elements of GF(2^8) to the base alpha (root of 1 + x^2 + x^3 + x^4 + x^8).
/// The logarithm of 0 is set to 0 by convention.
pub const GF_LOG: [u16; 256] = [
    0, 0, 1, 25, 2, 50, 26, 198, 3, 223, 51, 238, 27, 104, 199, 75, 4, 100, 224, 14, 52, 141, 239,
    129, 28, 193, 105, 248, 200, 8, 76, 113, 5, 138, 101, 47, 225, 36, 15, 33, 53, 147, 142, 218,
    240, 18, 130, 69, 29, 181, 194, 125, 106, 39, 249, 185, 201, 154, 9, 120, 77, 228, 114, 166, 6,
    191, 139, 98, 102, 221, 48, 253, 226, 152, 37, 179, 16, 145, 34, 136, 54, 208, 148, 206, 143,
    150, 219, 189, 241, 210, 19, 92, 131, 56, 70, 64, 30, 66, 182, 163, 195, 72, 126, 110, 107, 58,
    40, 84, 250, 133, 186, 61, 202, 94, 155, 159, 10, 21, 121, 43, 78, 212, 229, 172, 115, 243,
    167, 87, 7, 112, 192, 247, 140, 128, 99, 13, 103, 74, 222, 237, 49, 197, 254, 24, 227, 165,
    153, 119, 38, 184, 180, 124, 17, 68, 146, 217, 35, 32, 137, 46, 55, 63, 209, 91, 149, 188, 207,
    205, 144, 135, 151, 178, 220, 252, 190, 97, 242, 86, 211, 171, 20, 42, 93, 158, 132, 60, 57,
    83, 71, 109, 65, 162, 31, 45, 67, 216, 183, 123, 164, 118, 196, 23, 73, 236, 127, 12, 111, 246,
    108, 161, 59, 82, 41, 157, 85, 170, 251, 96, 134, 177, 187, 204, 62, 90, 203, 89, 95, 176, 156,
    169, 160, 81, 11, 245, 22, 235, 122, 117, 44, 215, 79, 174, 213, 233, 230, 231, 173, 232, 116,
    214, 244, 234, 168, 80, 88, 175,
];

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

/// Constant-time equality-to-zero mask.
///
/// # Returns
/// `0xFFFFFFFF` if `x == 0`, `0x00000000` otherwise.
#[inline]
fn eq_zero_mask_u32(x: u32) -> u32 {
    // (x | -x) has its MSB set iff x != 0 (standard branchless nonzero test)
    let t = x | x.wrapping_neg();
    (t >> 31).wrapping_sub(1)
}

/// Carry-less multiplication of two GF(2) polynomials (byte-sized).
///
/// Implementation of algorithm `mul1` from
/// <https://hal.inria.fr/inria-00188261v4/document> with s=2, w=8.
///
/// Constant-time: no secret-dependent branches or memory accesses.
///
/// # Arguments
/// * `a` - First polynomial (secret).
/// * `b` - Second polynomial (secret).
///
/// # Returns
/// `[lo, hi]` — the carryless product split into low and high bytes.
pub fn gf_carryless_mul(a: u8, b: u8) -> [u8; 2] {
    let mut u = [0u16; 4];
    u[0] = 0;
    u[1] = (b as u16) & ((1u16 << 7) - 1);
    u[2] = u[1] << 1;
    u[3] = u[2] ^ u[1];

    let tmp1 = (a as u16) & 3;
    let mut g: u16 = 0;
    for i in 0..4u32 {
        let tmp2 = (tmp1 as u32).wrapping_sub(i);
        let mask = eq_zero_mask_u32(tmp2) as u16;
        g ^= u[i as usize] & mask;
    }
    let mut l: u16 = g;
    let mut h: u16 = 0;

    // Idiomatic replacement for the while loop
    for i in (2..8u8).step_by(2) {
        g = 0;
        let tmp3 = ((a >> i) as u16) & 3;
        for j in 0..4u32 {
            let tmp2 = (tmp3 as u32).wrapping_sub(j);
            let mask = eq_zero_mask_u32(tmp2) as u16;
            g ^= u[j as usize] & mask;
        }
        l ^= g << i;
        h ^= g >> (8 - i);
    }

    let bit7_mask: u16 = ((b >> 7) & 1) as u16;
    let mask: u16 = bit7_mask.wrapping_neg();
    l ^= ((a as u16) << 7) & mask;
    h ^= ((a as u16) >> 1) & mask;

    [l as u8, h as u8]
}

/// Multiplies two elements of GF(2^PARAM_M).
///
/// (delegates to `gf_carryless_mul` and `gf_reduce`, both constant-time).
///
/// # Arguments
/// * `a` - Element of GF(2^PARAM_M).
/// * `b` - Element of GF(2^PARAM_M).
///
/// # Returns
/// The product `a * b` in GF(2^PARAM_M).
pub fn gf_mul(a: u16, b: u16) -> u16 {
    let c = gf_carryless_mul(a as u8, b as u8);
    let tmp = (c[0] as u16) ^ ((c[1] as u16) << 8);
    gf_reduce(tmp)
}

/// Squares an element of GF(2^PARAM_M).
///
///
/// # Arguments
/// * `a` - Element of GF(2^PARAM_M).
///
/// # Returns
/// `a^2` in GF(2^PARAM_M).
pub fn gf_square(a: u16) -> u16 {
    let mut b: u32 = a as u32;
    let mut s: u32 = b & 1;

    for i in 1..PARAM_M {
        b <<= 1;
        s ^= b & (1u32 << (2 * i));
    }

    gf_reduce(s as u16)
}

/// Computes the inverse of an element of GF(2^8),
/// using the addition chain 1, 2, 3, 4, 7, 11, 15, 30, 60, 120, 127, 254.
///
/// # Arguments
/// * `a` - Element of GF(2^PARAM_M).
///
/// # Returns
/// The inverse of `a` in GF(2^PARAM_M).
pub fn gf_inverse(a: u16) -> u16 {
    let mut inv: u16 = gf_square(a); // a^2
    let tmp1: u16 = gf_mul(inv, a); // a^3
    inv = gf_square(inv); // a^4
    let tmp2: u16 = gf_mul(inv, tmp1); // a^7
    let tmp1: u16 = gf_mul(inv, tmp2); // a^11
    inv = gf_mul(tmp1, inv); // a^15
    inv = gf_square(inv); // a^30
    inv = gf_square(inv); // a^60
    inv = gf_square(inv); // a^120
    inv = gf_mul(inv, tmp2); // a^127
    inv = gf_square(inv); // a^254
    inv
}

#[cfg(test)]
mod tests;
