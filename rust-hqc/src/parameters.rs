//! Runtime-selectable HQC parameter sets.
//!
//! Every quantity that varies between HQC-1, HQC-3 and HQC-5 lives in
//! [`HqcParameters`]. The three instances are `const`-constructed into statics,
//! so [`HqcParameterSet::params`] is a table lookup with no allocation and
//! `&'static HqcParameters` is cheap to thread through call chains.
//!
//! The convention for the rest of the crate is that any function whose
//! behaviour depends on the parameter set takes `p: &HqcParameters` as its
//! first argument.
//!
//! Reference: `hqc_specifications_2025_08_22.pdf`, Tables 3-6.

// ---------------------------------------------------------------------------
// Invariants
//
// These are identical for all three parameter sets and are therefore plain
// consts rather than fields. In particular the whole `gf` module depends only
// on PARAM_M and PARAM_GF_POLY and needs no parameterization at all.
// ---------------------------------------------------------------------------

/// Degree m of the Galois field GF(2^m).
pub const PARAM_M: usize = 8;
/// Primitive polynomial of GF(2^PARAM_M): 1 + a^2 + a^3 + a^4 + a^8.
pub const PARAM_GF_POLY: u16 = 0x11D;
/// Order of the multiplicative group of GF(2^PARAM_M), i.e. 2^PARAM_M - 1.
pub const PARAM_GF_MUL_ORDER: usize = 255;
/// Size of a seed in bytes (spec section 4.2).
pub const SEED_BYTES: usize = 32;
/// Size of the salt in bytes (spec section 4.2).
pub const SALT_BYTES: usize = 16;
/// Size of the shared secret K in bytes (spec section 4.2).
pub const SHARED_SECRET_BYTES: usize = 32;

// ---------------------------------------------------------------------------
// Upper bounds over all parameter sets
//
// Working buffers whose worst-case size is small enough to keep on the stack
// are declared at these bounds and used up to a runtime length. This keeps the
// Reed-Solomon decoder and the fixed-weight support writer allocation-free
// under runtime parameter selection. The bounds are checked against every
// parameter set by the assertions at the bottom of this file.
// ---------------------------------------------------------------------------

/// Largest `vec_n_size_64` over all parameter sets (HQC-5).
pub const MAX_VEC_N_SIZE_64: usize = 901;
/// Largest `vec_n_size_bytes` over all parameter sets (HQC-5).
pub const MAX_VEC_N_SIZE_BYTES: usize = 7205;
/// Largest `omega_r` / `omega_e` over all parameter sets (HQC-5).
pub const MAX_OMEGA_R: usize = 149;
/// Largest `delta` over all parameter sets (HQC-5).
pub const MAX_DELTA: usize = 29;
/// Largest `g` (RS generator polynomial length) over all sets (HQC-5).
pub const MAX_G: usize = 59;
/// Largest `n1` (RS code length, in symbols) over all sets (HQC-5).
pub const MAX_N1: usize = 90;
/// Largest `multiplicity` over all parameter sets (HQC-3 and HQC-5).
pub const MAX_MULTIPLICITY: usize = 5;

// ---------------------------------------------------------------------------
// Parameter set handle
// ---------------------------------------------------------------------------

/// Selects one of the three HQC parameter sets at runtime.
///
/// Named after the spec's own instance names (`HQC-1`, `HQC-3`, `HQC-5`),
/// which track the NIST security categories rather than bit strengths.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum HqcParameterSet {
    /// NIST category 1 (128-bit classical security).
    Hqc1,
    /// NIST category 3 (192-bit classical security).
    Hqc3,
    /// NIST category 5 (256-bit classical security).
    Hqc5,
}

impl HqcParameterSet {
    /// All parameter sets, in ascending order of security.
    pub const ALL: [HqcParameterSet; 3] = [Self::Hqc1, Self::Hqc3, Self::Hqc5];

    /// Returns the parameters for this set.
    pub const fn params(self) -> &'static HqcParameters {
        match self {
            Self::Hqc1 => &HQC_1,
            Self::Hqc3 => &HQC_3,
            Self::Hqc5 => &HQC_5,
        }
    }

    /// NIST security category (1, 3 or 5).
    pub const fn nist_level(self) -> u8 {
        match self {
            Self::Hqc1 => 1,
            Self::Hqc3 => 3,
            Self::Hqc5 => 5,
        }
    }

    /// Classical security level in bits (128, 192 or 256).
    pub const fn security_bits(self) -> usize {
        self.params().security_bytes * 8
    }

    /// Canonical name, as used in the specification.
    ///
    /// This is the string an external binding (e.g. a Botan
    /// `HQC_Parameter_Set`) should map to and from; keeping it in one place
    /// means the mapping can be changed without touching anything else.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Hqc1 => "HQC-1",
            Self::Hqc3 => "HQC-3",
            Self::Hqc5 => "HQC-5",
        }
    }

    /// Parses a canonical name, accepting the security-bits spelling as an
    /// alias since much of the literature uses `HQC-128` / `-192` / `-256`.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "HQC-1" | "HQC-128" => Some(Self::Hqc1),
            "HQC-3" | "HQC-192" => Some(Self::Hqc3),
            "HQC-5" | "HQC-256" => Some(Self::Hqc5),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/// All parameter-set-dependent quantities for one HQC instance.
///
/// Constructed by [`HqcParameters::new`], which derives every field that the
/// specification defines in terms of another, so that the seven independent
/// parameters appear exactly once each in this file.
#[derive(Debug)]
pub struct HqcParameters {
    /// Which set this is.
    pub set: HqcParameterSet,

    // --- scheme parameters (spec Table 5) ---
    /// Ambient length n: smallest primitive prime greater than n1*n2.
    pub n: usize,
    /// Length n1 of the external Reed-Solomon code, in symbols over GF(256).
    pub n1: usize,
    /// Length n2 of the internal duplicated Reed-Muller code, in bits.
    pub n2: usize,
    /// Length n1*n2 of the concatenated code, in bits.
    pub n1n2: usize,
    /// Weight omega of the secret vectors (x, y).
    pub omega: usize,
    /// Weight omega_r of the encryption randomness (r1, r2).
    pub omega_r: usize,
    /// Weight omega_e of the encryption error e.
    pub omega_e: usize,

    // --- Reed-Solomon (spec section 3.4.2) ---
    /// Error-correcting capacity delta of the shortened RS code.
    pub delta: usize,
    /// Number of information symbols k of the RS code; also |m| in bytes.
    pub k: usize,
    /// Length of the RS generator polynomial, 2*delta + 1.
    pub g: usize,
    /// Coefficients of the RS generator polynomial, `g` entries.
    pub rs_poly: &'static [u16],
    /// Exponent for the additive FFT: the ELP is evaluated on 2^fft_exp points.
    pub fft_exp: usize,
    /// Flattened table of a^((i+1)*(j+1)) in GF(2^8), row-major.
    ///
    /// `2*delta` rows of `alpha_stride` entries; see [`Self::alpha_ij_pow`].
    pub alpha_ij_pow: &'static [u16],
    /// Row stride of [`Self::alpha_ij_pow`], equal to `n1 - 1`.
    pub alpha_stride: usize,

    // --- Reed-Muller (spec section 3.4.3, Table 4) ---
    /// Number of 128-bit RM(1,7) codeword repetitions, ceil(n2 / 128).
    pub multiplicity: usize,

    // --- fixed-weight sampling (spec section 3.2) ---
    /// Barrett multiplier mu = floor(2^32 / n).
    pub n_mu: u64,
    /// Rejection bound floor(2^24 / n) * n for uniform sampling in [0, n).
    pub rejection_threshold: u32,

    // --- derived buffer sizes ---
    /// Bytes needed to hold n bits.
    pub vec_n_size_bytes: usize,
    /// 64-bit words needed to hold n bits.
    pub vec_n_size_64: usize,
    /// Bytes needed to hold n1*n2 bits.
    pub vec_n1n2_size_bytes: usize,
    /// 64-bit words needed to hold n1*n2 bits.
    pub vec_n1n2_size_64: usize,
    /// Bytes needed to hold an RS codeword: n1 symbols of 8 bits.
    pub vec_n1_size_bytes: usize,
    /// 64-bit words needed to hold an RS codeword.
    pub vec_n1_size_64: usize,
    /// Bytes needed to hold a message m: k symbols of 8 bits.
    pub vec_k_size_bytes: usize,
    /// 64-bit words needed to hold a message m.
    pub vec_k_size_64: usize,

    // --- public API sizes (spec Table 6) ---
    /// Size of the security parameter in bytes; equals `k`.
    pub security_bytes: usize,
    /// |ek_KEM| = |seed| + ceil(n/8).
    pub ek_bytes: usize,
    /// |dk_KEM| = |ek_KEM| + |seed| + ceil(k/8) + |seed|, default format.
    pub dk_bytes: usize,
    /// |dk_KEM| = |seed| for the compressed format (spec section 3.5).
    pub dk_compressed_bytes: usize,
    /// |c_KEM| = ceil(n/8) + ceil(n1*n2/8) + |salt|.
    pub ct_bytes: usize,
    /// |K|, the shared secret size in bytes.
    pub ss_bytes: usize,
}

impl HqcParameters {
    /// Builds a parameter set from its independent parameters, deriving the
    /// rest.
    ///
    /// Derivations, each justified by the specification:
    /// - `n1n2 = n1 * n2` (section 3.5)
    /// - `k = n1 - 2*delta`: shortening removes the same amount from n and k,
    ///   and the unshortened code has `n - k = 2*delta` (section 3.4.2)
    /// - `g = 2*delta + 1` (section 3.4.2)
    /// - `multiplicity = ceil(n2 / 128)`, RM(1,7) having length 128 (Table 4)
    /// - `n_mu = floor(2^32 / n)`, `rejection_threshold = floor(2^24/n) * n`
    /// - key and ciphertext sizes per section 4.2
    #[allow(clippy::too_many_arguments)]
    const fn new(
        set: HqcParameterSet,
        n: usize,
        n1: usize,
        n2: usize,
        omega: usize,
        omega_r: usize,
        omega_e: usize,
        delta: usize,
        fft_exp: usize,
        rs_poly: &'static [u16],
        alpha_ij_pow: &'static [u16],
    ) -> Self {
        let n1n2 = n1 * n2;
        let k = n1 - 2 * delta;
        let g = 2 * delta + 1;

        let vec_n_size_bytes = n.div_ceil(8);
        let vec_n_size_64 = n.div_ceil(64);
        let vec_n1n2_size_bytes = n1n2.div_ceil(8);
        let vec_n1n2_size_64 = n1n2.div_ceil(64);

        let ek_bytes = SEED_BYTES + vec_n_size_bytes;

        // Guard the `1 << (n % 64)` and `1 << (64 - (n % 64))` shifts used by
        // vector::bitmask and gf2x::reduce, which are unsound at n % 64 == 0.
        assert!(n % 64 != 0);
        assert!(rs_poly.len() == g);
        assert!(alpha_ij_pow.len() == 2 * delta * (n1 - 1));

        Self {
            set,
            n,
            n1,
            n2,
            n1n2,
            omega,
            omega_r,
            omega_e,

            delta,
            k,
            g,
            rs_poly,
            fft_exp,
            alpha_ij_pow,
            alpha_stride: n1 - 1,

            multiplicity: n2.div_ceil(128),

            n_mu: (1u64 << 32) / (n as u64),
            rejection_threshold: ((1u32 << 24) / (n as u32)) * (n as u32),

            vec_n_size_bytes,
            vec_n_size_64,
            vec_n1n2_size_bytes,
            vec_n1n2_size_64,
            vec_n1_size_bytes: n1,
            vec_n1_size_64: n1.div_ceil(8),
            vec_k_size_bytes: k,
            vec_k_size_64: k.div_ceil(8),

            security_bytes: k,
            ek_bytes,
            dk_bytes: ek_bytes + SEED_BYTES + k + SEED_BYTES,
            dk_compressed_bytes: SEED_BYTES,
            ct_bytes: vec_n_size_bytes + vec_n1n2_size_bytes + SALT_BYTES,
            ss_bytes: SHARED_SECRET_BYTES,
        }
    }

    /// Mask selecting the significant bits of the final 64-bit word of an
    /// n-bit vector.
    ///
    /// Unlike the old free-standing `bitmask`, this is correct when
    /// `n % 64 == 0`: there the last word is *fully* significant, so the mask
    /// is all ones, whereas `(1 << (n % 64)) - 1` yields zero and silently
    /// clears it. No current parameter set hits that case (n % 64 is 5, 11 and
    /// 37), and `new` asserts it, but the runtime form should not depend on an
    /// invariant that a future parameter set could break.
    #[inline]
    pub const fn top_word_mask(&self) -> u64 {
        match self.n % 64 {
            0 => u64::MAX,
            bits => (1u64 << bits) - 1,
        }
    }

    /// Number of significant bits in the final 64-bit word of an n-bit vector.
    #[inline]
    pub const fn top_word_bits(&self) -> usize {
        match self.n % 64 {
            0 => 64,
            bits => bits,
        }
    }

    /// Returns row `i` of the alpha power table, `alpha_stride` entries wide.
    ///
    /// Rows are indexed `0 .. 2*delta`; entry `(i, j)` is
    /// `a^((i+1) * (j+1))` in GF(2^8).
    #[inline]
    pub fn alpha_ij_pow(&self, i: usize) -> &[u16] {
        let start = i * self.alpha_stride;
        &self.alpha_ij_pow[start..start + self.alpha_stride]
    }
}

// ---------------------------------------------------------------------------
// GF(2^8) helpers for const table generation
// ---------------------------------------------------------------------------

/// Carry-less multiply modulo [`PARAM_GF_POLY`], for const evaluation only.
///
/// This is deliberately separate from the `gf` module: it runs at compile time
/// on public constants, so it has no constant-time obligation, and the `gf`
/// module's runtime routines have no reason to be `const fn`.
const fn const_gf_mul(mut a: u16, mut b: u16) -> u16 {
    let mut r: u16 = 0;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        b >>= 1;
        a <<= 1;
        if a & 0x100 != 0 {
            a ^= PARAM_GF_POLY;
        }
    }
    r
}

/// Generates the flattened `a^((i+1)*(j+1))` table for `rows` x `cols`.
///
/// `LEN` must equal `rows * cols`. Generating this rather than transcribing it
/// removes roughly 5,200 lines of constants across the three parameter sets,
/// and with them any possibility of a transcription error.
const fn alpha_ij_pow_table<const LEN: usize>(rows: usize, cols: usize) -> [u16; LEN] {
    assert!(LEN == rows * cols);

    // a^0 .. a^254; a has order PARAM_GF_MUL_ORDER, so exponents reduce mod 255.
    let mut alpha = [0u16; PARAM_GF_MUL_ORDER];
    let mut acc: u16 = 1;
    let mut e = 0;
    while e < PARAM_GF_MUL_ORDER {
        alpha[e] = acc;
        acc = const_gf_mul(acc, 2);
        e += 1;
    }

    let mut out = [0u16; LEN];
    let mut i = 0;
    while i < rows {
        let mut j = 0;
        while j < cols {
            out[i * cols + j] = alpha[((i + 1) * (j + 1)) % PARAM_GF_MUL_ORDER];
            j += 1;
        }
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Static tables
// ---------------------------------------------------------------------------

/// Generator polynomial g1(x) of RS-S1[46, 16, 31] (spec section 3.4.2).
const RS_POLY_HQC_1: [u16; 31] = [
    89, 69, 153, 116, 176, 117, 111, 75, 73, 233, 242, 233, 65, 210, 21, 139, 103, 173, 67, 118,
    105, 210, 174, 110, 74, 69, 228, 82, 255, 181, 1,
];

/// Generator polynomial g2(x) of RS-S2[56, 24, 33] (spec section 3.4.2).
const RS_POLY_HQC_3: [u16; 33] = [
    45, 216, 239, 24, 253, 104, 27, 40, 107, 50, 163, 210, 227, 134, 224, 158, 119, 13, 158, 1,
    238, 164, 82, 43, 15, 232, 246, 142, 50, 189, 29, 232, 1,
];

/// Generator polynomial g3(x) of RS-S3[90, 32, 49] (spec section 3.4.2).
const RS_POLY_HQC_5: [u16; 59] = [
    49, 167, 49, 39, 200, 121, 124, 91, 240, 63, 148, 71, 150, 123, 87, 101, 32, 215, 159, 71, 201,
    115, 97, 210, 186, 183, 141, 217, 123, 12, 31, 243, 180, 219, 152, 239, 99, 141, 4, 246, 191,
    144, 8, 232, 47, 27, 141, 178, 130, 64, 124, 47, 39, 188, 216, 48, 199, 187, 1,
];

/// Alpha power table for HQC-1: 2*15 rows of 45.
const ALPHA_IJ_POW_HQC_1: [u16; 30 * 45] = alpha_ij_pow_table::<{ 30 * 45 }>(30, 45);
/// Alpha power table for HQC-3: 2*16 rows of 55.
const ALPHA_IJ_POW_HQC_3: [u16; 32 * 55] = alpha_ij_pow_table::<{ 32 * 55 }>(32, 55);
/// Alpha power table for HQC-5: 2*29 rows of 89.
const ALPHA_IJ_POW_HQC_5: [u16; 58 * 89] = alpha_ij_pow_table::<{ 58 * 89 }>(58, 89);

// ---------------------------------------------------------------------------
// The three parameter sets (spec Table 5)
// ---------------------------------------------------------------------------

/// HQC-1, NIST security category 1.
pub const HQC_1: HqcParameters = HqcParameters::new(
    HqcParameterSet::Hqc1,
    17669, // n
    46,    // n1
    384,   // n2
    66,    // omega
    75,    // omega_r
    75,    // omega_e
    15,    // delta
    4,     // fft_exp
    &RS_POLY_HQC_1,
    &ALPHA_IJ_POW_HQC_1,
);

/// HQC-3, NIST security category 3.
pub const HQC_3: HqcParameters = HqcParameters::new(
    HqcParameterSet::Hqc3,
    35851, // n
    56,    // n1
    640,   // n2
    100,   // omega
    114,   // omega_r
    114,   // omega_e
    16,    // delta
    5,     // fft_exp
    &RS_POLY_HQC_3,
    &ALPHA_IJ_POW_HQC_3,
);

/// HQC-5, NIST security category 5.
pub const HQC_5: HqcParameters = HqcParameters::new(
    HqcParameterSet::Hqc5,
    57637, // n
    90,    // n1
    640,   // n2
    131,   // omega
    149,   // omega_r
    149,   // omega_e
    29,    // delta
    5,     // fft_exp
    &RS_POLY_HQC_5,
    &ALPHA_IJ_POW_HQC_5,
);

// ---------------------------------------------------------------------------
// Compile-time consistency checks
// ---------------------------------------------------------------------------

/// Checks one parameter set against the sizes tabulated in the specification
/// and against the `MAX_*` bounds that stack-allocated buffers rely on.
const fn check(
    p: &HqcParameters,
    ek: usize,
    dk: usize,
    ct: usize,
    security_bits: usize,
    fft_exp: usize,
) -> bool {
    // Spec Table 6.
    assert!(p.ek_bytes == ek);
    assert!(p.dk_bytes == dk);
    assert!(p.ct_bytes == ct);
    assert!(p.ss_bytes == 32);
    assert!(p.security_bytes * 8 == security_bits);

    // Derivations that the spec states independently of the ones used above.
    assert!(p.g == 2 * p.delta + 1);
    assert!(p.k == p.security_bytes);
    assert!(p.n > p.n1n2);
    assert!(p.n - p.n1n2 < 64);
    assert!(p.fft_exp == fft_exp);
    assert!(1usize << p.fft_exp >= p.delta + 1);

    // Bounds relied on by max-sized stack buffers.
    assert!(p.vec_n_size_64 <= MAX_VEC_N_SIZE_64);
    assert!(p.vec_n_size_bytes <= MAX_VEC_N_SIZE_BYTES);
    assert!(p.omega_r <= MAX_OMEGA_R);
    assert!(p.omega_e <= MAX_OMEGA_R);
    assert!(p.omega <= MAX_OMEGA_R);
    assert!(p.delta <= MAX_DELTA);
    assert!(p.g <= MAX_G);
    assert!(p.n1 <= MAX_N1);
    assert!(p.multiplicity <= MAX_MULTIPLICITY);

    true
}

const _: () = assert!(check(&HQC_1, 2241, 2321, 4433, 128, 4));
const _: () = assert!(check(&HQC_3, 4514, 4602, 8978, 192, 5));
const _: () = assert!(check(&HQC_5, 7237, 7333, 14421, 256, 5));

// The Barrett and rejection constants are derived here but hardcoded in the C
// reference; pin them so a divergence is a compile error rather than a
// wrong-answer bug.
const _: () = assert!(HQC_1.n_mu == 243079 && HQC_1.rejection_threshold == 16767881);
const _: () = assert!(HQC_3.n_mu == 119800 && HQC_3.rejection_threshold == 16742417);
const _: () = assert!(HQC_5.n_mu == 74517 && HQC_5.rejection_threshold == 16772367);

// Multiplicities per spec Table 4.
const _: () = assert!(HQC_1.multiplicity == 3);
const _: () = assert!(HQC_3.multiplicity == 5);
const _: () = assert!(HQC_5.multiplicity == 5);

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent recomputation of the alpha table, to catch a mistake in the
    /// const generator itself rather than only in its inputs.
    fn alpha_reference(rows: usize, cols: usize) -> Vec<u16> {
        fn mul(mut a: u16, mut b: u16) -> u16 {
            let mut r = 0u16;
            while b != 0 {
                if b & 1 != 0 {
                    r ^= a;
                }
                b >>= 1;
                a <<= 1;
                if a & 0x100 != 0 {
                    a ^= PARAM_GF_POLY;
                }
            }
            r
        }
        let mut pow = vec![1u16; PARAM_GF_MUL_ORDER];
        for e in 1..PARAM_GF_MUL_ORDER {
            pow[e] = mul(pow[e - 1], 2);
        }
        let mut out = Vec::with_capacity(rows * cols);
        for i in 0..rows {
            for j in 0..cols {
                out.push(pow[((i + 1) * (j + 1)) % PARAM_GF_MUL_ORDER]);
            }
        }
        out
    }

    #[test]
    fn alpha_tables_match_reference() {
        for set in HqcParameterSet::ALL {
            let p = set.params();
            let expected = alpha_reference(2 * p.delta, p.alpha_stride);
            assert_eq!(p.alpha_ij_pow, expected.as_slice(), "{}", p.set.name());
        }
    }

    #[test]
    fn alpha_row_accessor_is_consistent() {
        for set in HqcParameterSet::ALL {
            let p = set.params();
            for i in 0..2 * p.delta {
                let row = p.alpha_ij_pow(i);
                assert_eq!(row.len(), p.alpha_stride);
                assert_eq!(row, &p.alpha_ij_pow[i * p.alpha_stride..][..p.alpha_stride]);
            }
        }
    }

    #[test]
    fn rs_generator_polynomials_are_monic_of_degree_2delta() {
        for set in HqcParameterSet::ALL {
            let p = set.params();
            assert_eq!(p.rs_poly.len(), 2 * p.delta + 1, "{}", p.set.name());
            assert_eq!(*p.rs_poly.last().unwrap(), 1, "{}", p.set.name());
        }
    }

    #[test]
    fn names_round_trip() {
        for set in HqcParameterSet::ALL {
            assert_eq!(HqcParameterSet::from_name(set.name()), Some(set));
        }
        assert_eq!(
            HqcParameterSet::from_name("HQC-128"),
            Some(HqcParameterSet::Hqc1)
        );
        assert_eq!(HqcParameterSet::from_name("HQC-2"), None);
    }

    #[test]
    fn parameter_sets_are_strictly_ordered() {
        let sets: Vec<_> = HqcParameterSet::ALL.iter().map(|s| s.params()).collect();
        for w in sets.windows(2) {
            assert!(w[0].n < w[1].n);
            assert!(w[0].ek_bytes < w[1].ek_bytes);
            assert!(w[0].ct_bytes < w[1].ct_bytes);
            assert!(w[0].security_bytes < w[1].security_bytes);
        }
    }
}

// ---------------------------------------------------------------------------
// Compatibility layer
//
// The names below are the flat, compile-time constants the crate used before
// parameter selection became a runtime choice. They are all bound to HQC-1.
//
// They exist so the migration can proceed module by module with the test suite
// green at every step, rather than as one unreviewable commit touching 26
// files. Each module that starts taking `p: &HqcParameters` drops its imports
// from here; when nothing imports them any more, delete this section.
//
// DO NOT add to this list, and do not reference it from any code that has
// already been migrated -- a module that mixes runtime parameters with these
// constants will silently compute HQC-1 sizes for an HQC-3 request.
// ---------------------------------------------------------------------------

/// The parameter set the compatibility constants below are bound to.
const COMPAT: &HqcParameters = &HQC_1;

/// Low-bit mask, as the crate defined it before the migration.
///
/// Prefer [`HqcParameters::top_word_mask`], which handles `a % size == 0`
/// correctly; this form returns 0 there instead of all ones.
pub const fn bitmask(a: usize, size: usize) -> u64 {
    (1u64 << (a % size)) - 1
}

pub const PARAM_N: usize = COMPAT.n;
pub const PARAM_N1: usize = COMPAT.n1;
pub const PARAM_N2: usize = COMPAT.n2;
pub const PARAM_N1N2: usize = COMPAT.n1n2;
pub const PARAM_OMEGA: usize = COMPAT.omega;
pub const PARAM_OMEGA_E: usize = COMPAT.omega_e;
pub const PARAM_OMEGA_R: usize = COMPAT.omega_r;
pub const PARAM_DELTA: usize = COMPAT.delta;
pub const PARAM_K: usize = COMPAT.k;
pub const PARAM_G: usize = COMPAT.g;
pub const PARAM_FFT: usize = COMPAT.fft_exp;
pub const PARAM_N_MU: u64 = COMPAT.n_mu;
pub const UTILS_REJECTION_THRESHOLD: u32 = COMPAT.rejection_threshold;
pub const PARAM_SECURITY: usize = COMPAT.security_bytes * 8;
pub const PARAM_SECURITY_BYTES: usize = COMPAT.security_bytes;
pub const PARAM_DFR_EXP: usize = COMPAT.security_bytes * 8;

pub const VEC_N_SIZE_BYTES: usize = COMPAT.vec_n_size_bytes;
pub const VEC_N_SIZE_64: usize = COMPAT.vec_n_size_64;
pub const VEC_N1N2_SIZE_BYTES: usize = COMPAT.vec_n1n2_size_bytes;
pub const VEC_N1N2_SIZE_64: usize = COMPAT.vec_n1n2_size_64;
pub const VEC_N1_SIZE_BYTES: usize = COMPAT.vec_n1_size_bytes;
pub const VEC_N1_SIZE_64: usize = COMPAT.vec_n1_size_64;
pub const VEC_K_SIZE_BYTES: usize = COMPAT.vec_k_size_bytes;
pub const VEC_K_SIZE_64: usize = COMPAT.vec_k_size_64;

pub const PUBLIC_KEY_BYTES: usize = COMPAT.ek_bytes;
pub const SECRET_KEY_BYTES: usize = COMPAT.dk_bytes;
pub const CIPHERTEXT_BYTES: usize = COMPAT.ct_bytes;

/// Generator polynomial of the shortened RS code, as `u8`.
///
/// The runtime field [`HqcParameters::rs_poly`] is `&[u16]`, matching how the
/// Reed-Solomon code consumes it; this narrows it back for the old callers,
/// which is lossless because every coefficient is a GF(2^8) element.
pub const RS_POLY_COEFS: [u8; 31] = {
    let mut out = [0u8; 31];
    let mut i = 0;
    while i < 31 {
        assert!(COMPAT.rs_poly[i] <= u8::MAX as u16);
        out[i] = COMPAT.rs_poly[i] as u8;
        i += 1;
    }
    out
};
