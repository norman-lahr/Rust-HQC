//! Declarations for the HQC C reference implementation.
//!
//! Compiled only under the `ref-ffi` feature. Nothing in the library proper
//! may reference this module -- it exists so differential tests can compare
//! the Rust port against the C original function by function.
//!
//! # Why these live in one place
//!
//! These declarations were previously spread across nine `tests.rs` files,
//! and two symbols were declared twice: `xof_init` in both `symmetric/tests.rs`
//! and `vector/tests.rs`, and `hash_i` in both `symmetric/tests.rs` and
//! `main.rs`. Rust does not check duplicate `extern` declarations against each
//! other, so two copies that disagree on a signature compile cleanly and are
//! undefined behaviour at run time. One declaration per symbol removes that
//! failure mode entirely.
//!
//! # Safety
//!
//! Every function here is `unsafe`. The C side writes through raw pointers
//! with lengths fixed by the compile-time parameter set of the linked archive,
//! and performs no bounds checking. Callers must pass buffers sized by the
//! same parameter set the C library was built for.
//!
//! # Known limitation: `static` functions
//!
//! Twelve of these are declared `static` in the C sources and so are absent
//! from the archive symbol table. They are marked STATIC below. Linking them
//! requires the un-static patch described in `build.rs`; without it, any test
//! touching them fails at link time, not at run time.
//!
//! # Variant-sized C structs
//!
//! `ciphertext_pke_t` is `uint64_t u[p.vec_n_size_64]` followed by an identical
//! `v`, so its size depends on the parameter set. It is declared here as
//! `*mut u64` rather than as three per-variant `#[repr(C)]` structs: two
//! contiguous `u64` arrays have alignment 8 and no padding, so the layout is
//! identical, and the declaration stops being variant-dependent. Correctness
//! then rests on the caller sizing the buffer from the right parameter set,
//! which is exactly what runtime selection provides.
//!
//! `rm_codeword_t` is a 16-byte union and is variant-independent, so
//! [`RmCodeword`] is shared.

#![allow(dead_code)]

pub mod hqc1;
pub mod hqc3;
pub mod hqc5;
pub mod variants;

pub use variants::{Ref1, Ref3, Ref5, RefImpl};

#[cfg(test)]
mod tests_variants;

pub use crate::code::reed_muller::{RmCodeword, RmExpandedCdw};

/// Mirrors C's `typedef struct { uint64_t ctx[26]; } shake256incctx;`
///
/// Previously defined independently in both `symmetric/tests.rs` and
/// `vector/tests.rs`. Two `#[repr(C)]` definitions of one C type is the same
/// silent-UB hazard as two `extern` declarations of one function.
#[repr(C)]
pub struct Shake256IncCtx {
    ctx: [u64; 26],
}

impl Shake256IncCtx {
    /// Zeroed context, matching C's `= {0}` initialization.
    pub fn zeroed() -> Self {
        Self { ctx: [0u64; 26] }
    }
}


/// Functions that are `static` in the C sources and need the un-static patch.
pub const STATIC_IN_C: &[&str] = &[
    "barrett_reduce",
    "compute_elp",
    "compute_error_values",
    "compute_fft_betas",
    "compute_roots",
    "compute_subset_sums",
    "compute_syndromes",
    "compute_z_poly",
    "correct_errors",
    "gf_reduce",
    "radix",
    "radix_big",
];

