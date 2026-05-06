use crate::parameters::*;

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
