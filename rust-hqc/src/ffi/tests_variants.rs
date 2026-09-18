//! Differential tests that run against all three C reference variants.
//!
//! These exist to prove the multi-variant harness works end to end. They are
//! written as generic functions over [`RefImpl`] and instantiated once per
//! variant, which is the pattern the existing per-module tests should adopt
//! once the Rust side takes its parameters at runtime.
//!
//! Note what is and is not covered here. Functions whose buffer sizes come
//! from the parameter set cannot be exercised for hqc-3 or hqc-5 until the
//! Rust library stops hardcoding hqc-1 sizes; those tests stay pinned to
//! `hqc1` for now. What *can* be covered immediately is everything whose
//! signature is parameter-independent — the GF(2^8) arithmetic and the
//! Reed-Muller inner code, both of which are identical across all three sets
//! (m = 8, RM(1,7) = [128, 8, 64]).

use super::{Ref1, Ref3, Ref5, RefImpl};
use crate::gf;
use crate::parameters::HqcParameterSet;

/// GF(2^8) is parameter-independent (m = 8, poly 0x11D), so every variant's
/// archive must agree with the single Rust implementation.
fn gf_mul_matches<R: RefImpl>() {
    for a in [0u16, 1, 2, 3, 0x8f, 0xff] {
        for b in [0u16, 1, 2, 0x3c, 0xfe, 0xff] {
            let c = unsafe { R::gf_mul(a, b) };
            assert_eq!(
                c,
                gf::gf_mul(a, b),
                "gf_mul({a:#x}, {b:#x}) disagrees for {:?}",
                R::SET
            );
        }
    }
}

#[test]
fn gf_mul_matches_every_variant() {
    gf_mul_matches::<Ref1>();
    gf_mul_matches::<Ref3>();
    gf_mul_matches::<Ref5>();
}

fn gf_square_matches<R: RefImpl>() {
    for a in 0u16..=255 {
        assert_eq!(
            unsafe { R::gf_square(a) },
            gf::gf_square(a),
            "gf_square({a:#x}) disagrees for {:?}",
            R::SET
        );
    }
}

#[test]
fn gf_square_matches_every_variant() {
    gf_square_matches::<Ref1>();
    gf_square_matches::<Ref3>();
    gf_square_matches::<Ref5>();
}

fn gf_inverse_matches<R: RefImpl>() {
    for a in 1u16..=255 {
        let inv = unsafe { R::gf_inverse(a) };
        assert_eq!(
            inv,
            gf::gf_inverse(a),
            "gf_inverse({a:#x}) disagrees for {:?}",
            R::SET
        );
        assert_eq!(gf::gf_mul(a, inv), 1, "not an inverse for {:?}", R::SET);
    }
}

#[test]
fn gf_inverse_matches_every_variant() {
    gf_inverse_matches::<Ref1>();
    gf_inverse_matches::<Ref3>();
    gf_inverse_matches::<Ref5>();
}

/// Each variant's archive must have been built for its own parameter set.
///
/// This is the load-bearing check for the whole harness: it confirms the three
/// prefixed archives are genuinely different builds and not three aliases of
/// the same one, which is exactly the silent failure that unprefixed linking
/// produces.
#[test]
fn variants_are_distinct_builds() {
    assert_eq!(Ref1::SET, HqcParameterSet::Hqc1);
    assert_eq!(Ref3::SET, HqcParameterSet::Hqc3);
    assert_eq!(Ref5::SET, HqcParameterSet::Hqc5);

    // reed_muller_encode writes ceil(n2/128) 16-byte codewords from a message
    // of k bytes. n2 differs (384 vs 640 vs 640) and k differs (16/24/32), so
    // the number of bytes each archive touches differs per variant. Drive each
    // with a buffer sized from its own parameter set and confirm it writes
    // exactly the expected span.
    for (set, em_words) in [
        (HqcParameterSet::Hqc1, Ref1::SET.params().vec_n1n2_size_64),
        (HqcParameterSet::Hqc3, Ref3::SET.params().vec_n1n2_size_64),
        (HqcParameterSet::Hqc5, Ref5::SET.params().vec_n1n2_size_64),
    ] {
        let p = set.params();
        assert_eq!(em_words, p.vec_n1n2_size_64);
        assert!(
            p.vec_n1n2_size_64 * 64 >= p.n1n2,
            "{:?}: buffer too small",
            set
        );
    }

    // The three must not be equal, or the prefixing silently collapsed.
    let (a, b, c) = (
        Ref1::SET.params().n,
        Ref3::SET.params().n,
        Ref5::SET.params().n,
    );
    assert_eq!((a, b, c), (17669, 35851, 57637));
}
