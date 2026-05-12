use super::*;

// -------------------------------------------------------
// Test Barrett Reduction
// -------------------------------------------------------

/// Reference implementation using plain modulo for comparison.
fn barrett_reduce_ref(x: u32) -> u32 {
    x % (PARAM_N as u32)
}

#[test]
fn test_barrett_reduce_sequential() {
    for x in 0..=(3 * PARAM_N as u32) {
        assert_eq!(
            barrett_reduce(x),
            barrett_reduce_ref(x),
            "mismatch at x = {}",
            x
        );
    }
}

// -------------------------------------------------------
// Test Fixed-weight Vector Generation
// -------------------------------------------------------

/// typedef struct { uint64_t ctx[26]; } shake256incctx;
#[repr(C)]
pub struct Shake256IncCtx {
    ctx: [u64; 26],
}

impl Shake256IncCtx {
    /// Creates a zeroed context, matching C's `= {0}` initialization.
    pub fn zeroed() -> Self {
        Self { ctx: [0u64; 26] }
    }
}

unsafe extern "C" {
    fn xof_init(xof_ctx: *mut Shake256IncCtx, seed: *const u8, seed_size: u32);

    fn shake256_inc_squeeze(output: *mut u8, output_size: u32, xof_ctx: *mut Shake256IncCtx);

    fn vect_generate_random_support1(ctx: *mut Shake256IncCtx, support: *mut u32, weight: u16);
    fn vect_generate_random_support2(ctx: *mut Shake256IncCtx, support: *mut u32, weight: u16);
    fn vect_write_support_to_vector(v: *mut u64, support: *const u32, weight: u16);
    fn vect_sample_fixed_weight1(ctx: *mut Shake256IncCtx, v: *mut u64, weight: u16);
    fn vect_sample_fixed_weight2(ctx: *mut Shake256IncCtx, v: *mut u64, weight: u16);
    fn vect_set_random(ctx: *mut Shake256IncCtx, v: *mut u64);
    fn vect_add(o: *mut u64, v1: *const u64, v2: *const u64, size: u32);
    fn vect_compare(v1: *const u8, v2: *const u8, size: u32) -> u8;
    fn vect_truncate(v: *mut u64);
}

/// Safe Rust wrapper around the C `xof_init` function.
///
/// # Arguments
/// * `seed` - Input seed to initialize the XOF context with.
///
/// # Returns
/// An initialized `Shake256IncCtx` ready for squeezing.
pub fn xof_init_ref(seed: &[u8]) -> Shake256IncCtx {
    let mut ctx = Shake256IncCtx::zeroed();
    unsafe {
        xof_init(
            &mut ctx as *mut Shake256IncCtx,
            seed.as_ptr(),
            seed.len() as u32,
        );
    }
    ctx
}

/// Safe wrapper to squeeze bytes from an initialized context.
///
/// # Arguments
/// * `ctx`    - Previously initialized `Shake256IncCtx`.
/// * `output` - Buffer to write squeezed bytes into.
pub fn xof_squeeze(ctx: &mut Shake256IncCtx, output: &mut [u8]) {
    unsafe {
        shake256_inc_squeeze(
            output.as_mut_ptr(),
            output.len() as u32,
            ctx as *mut Shake256IncCtx,
        );
    }
}

/// Safe wrapper around the C `vect_generate_random_support1` function.
///
/// # Arguments
/// * `ctx`    - Previously initialized `Shake256IncCtx`.
/// * `weight` - Desired Hamming weight.
///
/// # Returns
/// A `Vec<u32>` of `weight` unique indices in `[0, PARAM_N)`.
pub fn vect_generate_random_support1_ref(ctx: &mut Shake256IncCtx, weight: usize) -> Vec<u32> {
    let mut support = vec![0u32; weight];
    unsafe {
        vect_generate_random_support1(
            ctx as *mut Shake256IncCtx,
            support.as_mut_ptr(),
            weight as u16,
        );
    }
    support
}

/// Safe wrapper around the C `vect_generate_random_support1` function.
///
/// # Arguments
/// * `ctx`    - Previously initialized `Shake256IncCtx`.
/// * `weight` - Desired Hamming weight.
///
/// # Returns
/// A `Vec<u32>` of `weight` unique indices in `[0, PARAM_N)`.
pub fn vect_generate_random_support2_ref(ctx: &mut Shake256IncCtx, weight: usize) -> Vec<u32> {
    let mut support = vec![0u32; weight];
    unsafe {
        vect_generate_random_support2(
            ctx as *mut Shake256IncCtx,
            support.as_mut_ptr(),
            weight as u16,
        );
    }
    support
}

/// Safe wrapper around the C `vect_write_support_to_vector` function.
///
/// Writes `support` positions into the bit-vector `v`.
/// Each index in `support` sets a corresponding bit in `v`.
///
/// # Arguments
/// * `v`       - Output bit-vector of `VEC_N_SIZE_64` 64-bit words.
/// * `support` - Slice of bit indices to set.
pub fn vect_write_support_to_vector_ref(v: &mut [u64; VEC_N_SIZE_64], support: &[u32]) {
    unsafe {
        vect_write_support_to_vector(v.as_mut_ptr(), support.as_ptr(), support.len() as u16);
    }
}

/// Safe wrapper around the C `vect_sample_fixed_weight1` function.
///
/// Generates a random binary vector of fixed Hamming weight.
/// Used exclusively during **key generation** to generate vectors **x** and **y**.
///
/// # Arguments
/// * `ctx`    - Previously initialized `Shake256IncCtx`.
/// * `weight` - Desired Hamming weight.
///
/// # Returns
/// A bit-vector of `VEC_N_SIZE_64` 64-bit words with exactly `weight` bits set.
pub fn vect_sample_fixed_weight1_ref(
    ctx: &mut Shake256IncCtx,
    weight: usize,
) -> [u64; VEC_N_SIZE_64] {
    let mut v = [0u64; VEC_N_SIZE_64];
    unsafe {
        vect_sample_fixed_weight1(ctx as *mut Shake256IncCtx, v.as_mut_ptr(), weight as u16);
    }
    v
}

/// Safe wrapper around the C `vect_sample_fixed_weight2` function.
///
/// Generates a random binary vector of fixed Hamming weight.
///
/// Implementation of Algorithm 5 in <https://eprint.iacr.org/2021/1631.pdf>
///
/// Used exclusively during **encryption** to generate vectors **r1**, **r2**, and **e**.
/// # Arguments
/// * `ctx`    - Previously initialized `Shake256IncCtx`.
/// * `weight` - Desired Hamming weight.
///
/// # Returns
/// A bit-vector of `VEC_N_SIZE_64` 64-bit words with exactly `weight` bits set.
pub fn vect_sample_fixed_weight2_ref(
    ctx: &mut Shake256IncCtx,
    weight: usize,
) -> [u64; VEC_N_SIZE_64] {
    let mut v = [0u64; VEC_N_SIZE_64];
    unsafe {
        vect_sample_fixed_weight2(ctx as *mut Shake256IncCtx, v.as_mut_ptr(), weight as u16);
    }
    v
}

/// Safe wrapper around the C `vect_add` function.
///
/// Adds two vectors using XOR and writes the result into `o`.
///
/// # Arguments
/// * `o`    - Output vector.
/// * `v1`   - First input vector.
/// * `v2`   - Second input vector.
/// * `size` - Number of 64-bit words to process.
pub fn vect_add_ref(o: &mut [u64], v1: &[u64], v2: &[u64], size: usize) {
    assert!(o.len() >= size, "output buffer too small");
    assert!(v1.len() >= size, "v1 buffer too small");
    assert!(v2.len() >= size, "v2 buffer too small");
    unsafe {
        vect_add(o.as_mut_ptr(), v1.as_ptr(), v2.as_ptr(), size as u32);
    }
}

/// Safe wrapper around the C `vect_set_random` function.
///
/// Generates a random binary vector of dimension `PARAM_N` using
/// the XOF context, masking off any bits beyond `PARAM_N`.
///
/// # Arguments
/// * `ctx` - Previously initialized `Shake256IncCtx`.
///
/// # Returns
/// A random bit-vector of `VEC_N_SIZE_64` 64-bit words.
pub fn vect_set_random_ref(ctx: &mut Shake256IncCtx) -> [u64; VEC_N_SIZE_64] {
    let mut v = [0u64; VEC_N_SIZE_64];
    unsafe {
        vect_set_random(ctx as *mut Shake256IncCtx, v.as_mut_ptr());
    }
    v
}

/// Safe wrapper around the C `vect_compare` function.
///
/// Compares two vectors in constant time.
///
/// # Arguments
/// * `v1` - First input vector.
/// * `v2` - Second input vector.
///
/// # Returns
/// `0` if the vectors are equal, `1` otherwise.
pub fn vect_compare_ref(v1: &[u8], v2: &[u8]) -> u8 {
    assert_eq!(v1.len(), v2.len(), "vectors must have equal length");
    unsafe { vect_compare(v1.as_ptr(), v2.as_ptr(), v1.len() as u32) }
}

/// Safe wrapper around the C `vect_truncate` function.
///
/// Truncates a bit-vector in-place to `PARAM_N1N2` bits.
///
/// # Arguments
/// * `v` - Bit-vector of `VEC_N_SIZE_64` 64-bit words to truncate.
pub fn vect_truncate_ref(v: &mut [u64; VEC_N_SIZE_64]) {
    unsafe {
        vect_truncate(v.as_mut_ptr());
    }
}

#[test]
fn test_vect_generate_random_support1() {
    let seed: [u8; SEED_BYTES] = b"0ACE".repeat(SEED_BYTES / 4).try_into().unwrap();
    let seed_evil: [u8; SEED_BYTES] = b"1ACE".repeat(SEED_BYTES / 4).try_into().unwrap();

    let mut ctx = crate::symmetric::xof_init(&seed);
    let mut ctx_ref = xof_init_ref(&seed);

    for i in 0..100 {
        let support = crate::vector::vect_generate_random_support1(&mut ctx, PARAM_OMEGA);
        let support_ref = vect_generate_random_support1_ref(&mut ctx_ref, PARAM_OMEGA);

        assert_eq!(
            support, support_ref,
            "C and Rust implementations must produce identical support. Failed at i={}",
            i
        );
    }

    let mut ctx = crate::symmetric::xof_init(&seed);
    let mut ctx_ref_evil = xof_init_ref(&seed_evil);

    let support = crate::vector::vect_generate_random_support1(&mut ctx, PARAM_OMEGA);
    let support_ref_evil = vect_generate_random_support1_ref(&mut ctx_ref_evil, PARAM_OMEGA);

    assert_ne!(
        support, support_ref_evil,
        "C and Rust implementations must produce non-identical support"
    )
}

#[test]
fn test_vect_generate_random_support2() {
    let seed: [u8; SEED_BYTES] = b"0ACE".repeat(SEED_BYTES / 4).try_into().unwrap();
    let seed_evil: [u8; SEED_BYTES] = b"1ACE".repeat(SEED_BYTES / 4).try_into().unwrap();

    let mut ctx = crate::symmetric::xof_init(&seed);
    let mut ctx_ref = xof_init_ref(&seed);

    for i in 0..100 {
        let support = crate::vector::vect_generate_random_support2(&mut ctx, PARAM_OMEGA);
        let support_ref = vect_generate_random_support2_ref(&mut ctx_ref, PARAM_OMEGA);

        assert_eq!(
            support, support_ref,
            "C and Rust implementations must produce identical support. Failed at i={}",
            i
        );
    }

    let mut ctx = crate::symmetric::xof_init(&seed);
    let mut ctx_ref_evil = xof_init_ref(&seed_evil);

    let support = crate::vector::vect_generate_random_support2(&mut ctx, PARAM_OMEGA);
    let support_ref_evil = vect_generate_random_support2_ref(&mut ctx_ref_evil, PARAM_OMEGA);

    assert_ne!(
        support, support_ref_evil,
        "C and Rust implementations must produce non-identical support"
    )
}

#[test]
fn test_vect_write_support_to_vector() {
    let seed: [u8; SEED_BYTES] = b"0ACE".repeat(SEED_BYTES / 4).try_into().unwrap();

    let mut ctx = crate::symmetric::xof_init(&seed);

    for i in 0..100 {
        let mut support = crate::vector::vect_generate_random_support1(&mut ctx, PARAM_OMEGA);

        let mut v = [0u64; VEC_N_SIZE_64];
        let mut v_ref = [0u64; VEC_N_SIZE_64];

        crate::vector::vect_write_support_to_vector(&mut v, &support);
        vect_write_support_to_vector_ref(&mut v_ref, &support);

        assert_eq!(
            v, v_ref,
            "C and Rust must produce identical bit-vectors at iteration {}",
            i
        );

        support[10] = support[10].wrapping_neg();
        let mut v = [0u64; VEC_N_SIZE_64];

        crate::vector::vect_write_support_to_vector(&mut v, &support);

        assert_ne!(
            v, v_ref,
            "C and Rust must produce non-identical bit-vectors at iteration {}",
            i
        );
    }
}

#[test]
fn test_vect_sample_fixed_weight1() {
    let seed: [u8; SEED_BYTES] = b"0ACE".repeat(SEED_BYTES / 4).try_into().unwrap();

    let mut ctx = crate::symmetric::xof_init(&seed);
    let mut ctx_ref = xof_init_ref(&seed);

    for i in 0..100 {
        let v = crate::vector::vect_sample_fixed_weight1(&mut ctx, PARAM_OMEGA);
        let v_ref = crate::vector::tests::vect_sample_fixed_weight1_ref(&mut ctx_ref, PARAM_OMEGA);

        assert_eq!(
            v, v_ref,
            "C and Rust must produce identical bit-vectors at iteration {}",
            i
        );
    }
}

#[test]
fn test_vect_sample_fixed_weight2() {
    let seed: [u8; SEED_BYTES] = b"0ACE".repeat(SEED_BYTES / 4).try_into().unwrap();

    let mut ctx = crate::symmetric::xof_init(&seed);
    let mut ctx_ref = xof_init_ref(&seed);

    for i in 0..100 {
        let v = crate::vector::vect_sample_fixed_weight2(&mut ctx, PARAM_OMEGA);
        let v_ref = crate::vector::tests::vect_sample_fixed_weight2_ref(&mut ctx_ref, PARAM_OMEGA);

        assert_eq!(
            v, v_ref,
            "C and Rust must produce identical bit-vectors at iteration {}",
            i
        );
    }
}

#[test]
fn test_vect_set_random() {
    let seed: [u8; SEED_BYTES] = b"0ACE".repeat(SEED_BYTES / 4).try_into().unwrap();

    let mut ctx = crate::symmetric::xof_init(&seed);
    let mut ctx_ref = xof_init_ref(&seed);

    for i in 0..100 {
        let v = crate::vector::vect_set_random(&mut ctx);
        let v_ref = crate::vector::tests::vect_set_random_ref(&mut ctx_ref);
        assert_eq!(
            v, v_ref,
            "C and Rust must produce identical bit-vectors at iteration {}",
            i
        );
    }
}

#[test]
fn test_vect_add() {
    const TEST_ROUNDS: u64 = 100;
    let seed: [u8; SEED_BYTES] = b"0ACE".repeat(SEED_BYTES / 4).try_into().unwrap();
    let mut ctx1 = crate::symmetric::xof_init(&seed);

    for i in 0..TEST_ROUNDS {
        let v1 = crate::vector::vect_set_random(&mut ctx1);
        let v2 = crate::vector::vect_set_random(&mut ctx1);

        let mut o_proc = vec![0u64; VEC_N_SIZE_64];
        let mut o_ref = vec![0u64; VEC_N_SIZE_64];

        let o = crate::vector::vect_add(&v1, &v2, VEC_N_SIZE_64);
        crate::vector::vect_add_into(&mut o_proc, &v1, &v2);
        vect_add_ref(&mut o_ref, &v1, &v2, VEC_N_SIZE_64);

        assert_eq!(o, o_ref, "Rust and C must match at iteration {}", i);
        assert_eq!(o_proc, o_ref, "Rust and C must match at iteration {}", i);
    }
}

#[test]
fn test_vect_add_perf_comparison() {
    const TEST_ROUNDS: u64 = 100;
    let seed: [u8; SEED_BYTES] = b"0ACE".repeat(SEED_BYTES / 4).try_into().unwrap();
    let mut ctx1 = crate::symmetric::xof_init(&seed);

    let mut pre;
    let mut post;

    let mut cycles_rust = 0;
    let mut cycles_rust_proc = 0;
    let mut cycles_c = 0;

    for _i in 0..TEST_ROUNDS {
        let v1 = crate::vector::vect_set_random(&mut ctx1);
        let v2 = crate::vector::vect_set_random(&mut ctx1);
        let mut o_ref = vec![0u64; VEC_N_SIZE_64];

        unsafe {
            pre = core::arch::x86_64::_rdtsc();
        }
        vect_add_ref(&mut o_ref, &v1, &v2, VEC_N_SIZE_64);
        unsafe {
            post = core::arch::x86_64::_rdtsc();
        }

        cycles_c += post - pre;
    }
    for _i in 0..TEST_ROUNDS {
        let v1 = crate::vector::vect_set_random(&mut ctx1);
        let v2 = crate::vector::vect_set_random(&mut ctx1);
        let _o;
        unsafe {
            pre = core::arch::x86_64::_rdtsc();
        }
        _o = crate::vector::vect_add(&v1, &v2, VEC_N_SIZE_64);
        unsafe {
            post = core::arch::x86_64::_rdtsc();
        }
        cycles_rust += post - pre;
    }
    for _i in 0..TEST_ROUNDS {
        let v1 = crate::vector::vect_set_random(&mut ctx1);
        let v2 = crate::vector::vect_set_random(&mut ctx1);
        let mut o_proc = vec![0u64; VEC_N_SIZE_64];

        unsafe {
            pre = core::arch::x86_64::_rdtsc();
        }
        crate::vector::vect_add_into(&mut o_proc, &v1, &v2);
        unsafe {
            post = core::arch::x86_64::_rdtsc();
        }

        cycles_rust_proc += post - pre;
    }

    println!(
        "Mean of measured cycles: {} (Rust Function) vs. {} (Rust Procedure) vs. {} (C Reference)",
        cycles_rust / TEST_ROUNDS,
        cycles_rust_proc / TEST_ROUNDS,
        cycles_c / TEST_ROUNDS
    );
}

#[test]
fn test_vect_compare() {
    const TEST_ROUNDS: u64 = 100;
    let seed: [u8; SEED_BYTES] = b"0ACE".repeat(SEED_BYTES / 4).try_into().unwrap();
    let mut ctx1 = crate::symmetric::xof_init(&seed);

    for i in 0..TEST_ROUNDS {
        let mut v1 = vec![0u8; VEC_N_SIZE_BYTES];
        let mut v2 = vec![0u8; VEC_N_SIZE_BYTES];
        ctx1.read(&mut v1);
        ctx1.read(&mut v2);
        if v1[0] % 2 == 0 {
            v1 = v2.clone();
            assert_eq!(v1, v2);
        }
        assert_eq!(
            crate::vector::vect_compare(&v1, &v2),
            vect_compare_ref(&v1, &v2),
            "Rust and C must agree at iteration {}",
            i
        );
    }
}

#[test]
fn test_vect_truncate() {
    const TEST_ROUNDS: u64 = 100;
    let seed: [u8; SEED_BYTES] = b"0ACE".repeat(SEED_BYTES / 4).try_into().unwrap();
    let mut ctx1 = crate::symmetric::xof_init(&seed);
    let mut ctx2 = crate::symmetric::xof_init(&seed);

    for i in 0..TEST_ROUNDS {
        let mut v = crate::vector::vect_set_random(&mut ctx1);
        let mut v_ref = crate::vector::vect_set_random(&mut ctx2);

        crate::vector::vect_truncate(&mut v);
        vect_truncate_ref(&mut v_ref);

        assert_eq!(v, v_ref, "Rust and C must match at iteration {}", i);
    }
}
