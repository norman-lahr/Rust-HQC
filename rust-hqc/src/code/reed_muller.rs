use crate::parameters::*;

/// 128-bit Reed-Muller RM(1,7) codeword.
///
/// Provides word-wise access (4 × 32-bit words).
///
/// `#[repr(C)]` ensures the memory layout matches the original C type:
/// ```c
/// typedef union {
///     uint8_t  u8[16];
///     uint32_t u32[4];
/// } rm_codeword_t;
/// ```
/// Required for correct FFI cross-validation against the C implementation.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RmCodeword {
    pub u32: [u32; 4],
}
// pub type RmCodeword = [u32; 4];

impl RmCodeword {
    /// Creates a zero-initialized codeword.
    pub fn zeroed() -> Self {
        Self { u32: [0u32; 4] }
    }

    /// Creates a codeword from 4 32-bit words.
    pub fn new(w0: u32, w1: u32, w2: u32, w3: u32) -> Self {
        Self {
            u32: [w0, w1, w2, w3],
        }
    }
}

/// Compile-time size check - must match C sizeof(rm_codeword_t) = 16 bytes.
const _: () = assert!(
    core::mem::size_of::<RmCodeword>() == 16,
    "RmCodeword must be exactly 16 bytes to match C layout"
);

/// Internal representation of a codeword with each bit expanded
/// to a 16-bit signed value.
///
/// Equivalent to C: `typedef int16_t rm_expanded_cdw[128];`
pub type RmExpandedCdw = [i16; 128];

/// Number of repeated 128-bit codeword blocks.
///
/// Calculates the ceiling of `PARAM_N2 / 128` to determine how many
/// copies of each 128-bit codeword are used in the code expansion.
pub const MULTIPLICITY: usize = PARAM_N2.div_ceil(128);

/// Broadcasts the least significant bit of `x` to a 32-bit mask.
///
/// Returns `0xFFFFFFFF` (all ones)  if `x & 1 == 1`
/// Returns `0x00000000` (all zeros) if `x & 1 == 0`
#[inline]
pub const fn bit0mask(x: u32) -> i32 {
    -((x & 1) as i32)
}

/// Encodes a single byte into a single RM(1,7) codeword.
///
/// Encoding matrix (bits numbered big endian):
/// ```text
/// 0   aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa
/// 1   cccccccc cccccccc cccccccc cccccccc
/// 2   f0f0f0f0 f0f0f0f0 f0f0f0f0 f0f0f0f0
/// 3   ff00ff00 ff00ff00 ff00ff00 ff00ff00
/// 4   ffff0000 ffff0000 ffff0000 ffff0000
/// 5   ffffffff 00000000 ffffffff 00000000
/// 6   ffffffff ffffffff 00000000 00000000
/// 7   ffffffff ffffffff ffffffff ffffffff
/// ```
///
/// Constant-time: all operations are branchless bitwise arithmetic.
///
/// # Arguments
/// * `message` - Input byte to encode.
///
/// # Returns
/// An `RmCodeword` containing the RM(1,7) encoded codeword.
pub fn encode(message: i32) -> RmCodeword {
    let mut first_word: i32;

    // Row 7: all-ones mask — broadcast bit 7
    first_word = bit0mask((message >> 7) as u32);

    // XOR with masked generator rows 0..4
    first_word ^= bit0mask((message >> 0) as u32) & 0xaaaaaaaa_u32 as i32;
    first_word ^= bit0mask((message >> 1) as u32) & 0xcccccccc_u32 as i32;
    first_word ^= bit0mask((message >> 2) as u32) & 0xf0f0f0f0_u32 as i32;
    first_word ^= bit0mask((message >> 3) as u32) & 0xff00ff00_u32 as i32;
    first_word ^= bit0mask((message >> 4) as u32) & 0xffff0000_u32 as i32;

    let mut word = RmCodeword::zeroed();

    // word[0]: rows 0..4 and row 7
    word.u32[0] = first_word as u32;

    // word[1]: additionally XOR row 5
    first_word ^= bit0mask((message >> 5) as u32);
    word.u32[1] = first_word as u32;

    // word[3]: additionally XOR row 6
    first_word ^= bit0mask((message >> 6) as u32);
    word.u32[3] = first_word as u32;

    // word[2]: undo row 5 (XOR again is its own inverse)
    first_word ^= bit0mask((message >> 5) as u32);
    word.u32[2] = first_word as u32;

    word
}

/// Performs the Hadamard transform of `src`, storing the result in `dst`.
///
/// # Arguments
/// * `src` - Input expanded codeword — overwritten during computation.
/// * `dst` - Output expanded codeword — contains result after transform.
pub fn hadamard(src: &mut RmExpandedCdw, dst: &mut RmExpandedCdw) {
    // Track which buffer is "current input" and "current output"
    // by copying after each pass — slightly less efficient but no unsafe
    let mut bufs: [RmExpandedCdw; 2] = [*src, [0i16; 128]];
    let mut cur = 0usize; // index of current input buffer

    for _pass in 0..7 {
        let next = 1 - cur;
        for i in 0..64usize {
            let a = bufs[cur][2 * i];
            let b = bufs[cur][2 * i + 1];
            bufs[next][i] = a.wrapping_add(b);
            bufs[next][i + 64] = a.wrapping_sub(b);
        }
        cur = next;
    }

    // After 7 passes (odd), result is in bufs[1] = dst
    *dst = bufs[cur];
}
