use crate::parameters::PARAM_GF_POLY;

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

#[cfg(test)]
mod tests;
