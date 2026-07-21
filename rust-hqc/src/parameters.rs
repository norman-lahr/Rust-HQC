use crate::api::*;
use std::ops::Div;
/// Creates a bitmask with `a % size` bits set.
/// Equivalent to C: `#define BITMASK(a, size) ((1UL << (a % size)) - 1)`
pub const fn bitmask(a: usize, size: usize) -> u64 {
    (1u64 << (a % size)) - 1
}

// -------------------------------------------------------
// Core scheme parameters
// -------------------------------------------------------

/// Parameter n of the scheme.
pub const PARAM_N: usize = 17669;
/// Parameter n1 of the scheme (length of Reed–Solomon code).
pub const PARAM_N1: usize = 46;
/// Parameter n2 of the scheme (length of Duplicated Reed–Muller code).
pub const PARAM_N2: usize = 384;
/// Length in bits of the concatenated code.
pub const PARAM_N1N2: usize = 17664;
/// Parameter omega of the scheme.
pub const PARAM_OMEGA: usize = 66;
/// Parameter omega_e of the scheme.
pub const PARAM_OMEGA_E: usize = 75;
/// Parameter omega_r of the scheme.
pub const PARAM_OMEGA_R: usize = 75;

// -------------------------------------------------------
// Security parameters
// -------------------------------------------------------

/// Security level corresponding to the chosen parameters.
pub const PARAM_SECURITY: usize = 128;
/// Security level in bytes.
pub const PARAM_SECURITY_BYTES: usize = 16;
/// Decryption failure rate exponent.
pub const PARAM_DFR_EXP: usize = 128;

// -------------------------------------------------------
// Key and ciphertext sizes
// -------------------------------------------------------

/// Size of the secret key in bytes.
pub const SECRET_KEY_BYTES: usize = CRYPTO_SECRETKEYBYTES;
/// Size of the public key in bytes.
pub const PUBLIC_KEY_BYTES: usize = CRYPTO_PUBLICKEYBYTES;
/// Size of the shared secret in bytes.
pub const SHARED_SECRET_BYTES: usize = CRYPTO_BYTES;
/// Size of the ciphertext in bytes.
pub const CIPHERTEXT_BYTES: usize = CRYPTO_CIPHERTEXTBYTES;

// -------------------------------------------------------
// Vector sizes in bytes
// -------------------------------------------------------

/// Size of array to store `PARAM_N` bits in bytes.
pub const VEC_N_SIZE_BYTES: usize = PARAM_N.div_ceil(8);
/// Size of array to store `PARAM_K` bits in bytes.
pub const VEC_K_SIZE_BYTES: usize = PARAM_K;
/// Size of array to store `PARAM_N1` bits in bytes.
pub const VEC_N1_SIZE_BYTES: usize = PARAM_N1;
/// Size of array to store `PARAM_N1N2` bits in bytes.
pub const VEC_N1N2_SIZE_BYTES: usize = PARAM_N1N2.div_ceil(8);

// -------------------------------------------------------
// Vector sizes in 64-bit words
// -------------------------------------------------------

/// Size of array to store `PARAM_N` bits in 64-bit words.
pub const VEC_N_SIZE_64: usize = PARAM_N.div_ceil(64);
/// Size of array to store `PARAM_N1` bits in 64-bit words.
pub const VEC_N1_SIZE_64: usize = PARAM_N1.div_ceil(8);
/// Size of array to store `PARAM_N1N2` bits in 64-bit words.
pub const VEC_N1N2_SIZE_64: usize = PARAM_N1N2.div_ceil(64);
/// Size of array to store `PARAM_K` bits in 64-bit words.
pub const VEC_K_SIZE_64: usize = PARAM_K.div_ceil(8);

// -------------------------------------------------------
// Reed–Solomon parameters
// -------------------------------------------------------

/// Error-correcting capacity (delta) of the Reed–Solomon code.
pub const PARAM_DELTA: usize = 15;
/// Degree m of the Galois field GF(2^m).
pub const PARAM_M: usize = 8;
/// Generator polynomial of GF(2^PARAM_M).
pub const PARAM_GF_POLY: usize = 0x11D;
/// Size of the multiplicative group of GF(2^PARAM_M) (2^PARAM_M − 1).
pub const PARAM_GF_MUL_ORDER: usize = 255;
/// Size of the information bits of the Reed–Solomon code.
pub const PARAM_K: usize = 16;
/// Size of the generator polynomial of the Reed–Solomon code.
pub const PARAM_G: usize = 31;
/// Exponent for additive FFT (2^PARAM_FFT points).
pub const PARAM_FFT: usize = 4;

/// Coefficients of the Reed–Solomon generator polynomial.
pub const RS_POLY_COEFS: [u8; 31] = [
    89, 69, 153, 116, 176, 117, 111, 75, 73, 233, 242, 233, 65, 210, 21, 139, 103, 173, 67, 118,
    105, 210, 174, 110, 74, 69, 228, 82, 255, 181, 1,
];

// -------------------------------------------------------
// Seed and salt sizes
// -------------------------------------------------------

/// Size of the seed in bytes.
pub const SEED_BYTES: usize = 32;
/// Size of a salt in bytes.
pub const SALT_BYTES: usize = 16;

// -------------------------------------------------------
// Barrett reduction
// -------------------------------------------------------

/// Precomputed multiplier for Barrett reduction: μ = ⌊2^32 / PARAM_N⌋.
pub const PARAM_N_MU: u64 = 243079;

// -------------------------------------------------------
// Sampling
// -------------------------------------------------------

/// Rejection threshold for uniform sampling in [0, PARAM_N).
pub const UTILS_REJECTION_THRESHOLD: u32 = 16767881;
