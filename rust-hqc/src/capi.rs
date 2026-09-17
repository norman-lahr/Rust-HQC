//! C ABI for the HQC-KEM, for binding from C++ (Botan) or C.
//!
//! Stateless by design. [`HqcParameters`] instances are `'static`, so there is
//! nothing to own across the boundary: a caller passes a parameter-set
//! discriminant on every call, and there is no `hqc_new` / `hqc_free` pair to
//! get wrong. A Botan `HQC_PublicKey` need hold nothing beyond the enum.
//!
//! # Unwinding
//!
//! Every entry point wraps its work in [`catch_unwind`]. A panic crossing an
//! `extern "C"` boundary is undefined behaviour, and this crate still contains
//! internal `assert!`s guarding buffer-length invariants. Those are
//! unreachable through the checked [`crate::api`] layer, but "unreachable" is
//! not "impossible", and the cost of being wrong is UB rather than an error
//! code. A caught panic becomes [`HQC_ERR_INTERNAL`].
//!
//! # Safety
//!
//! Every function is `unsafe`: pointers must be non-null, correctly aligned,
//! and valid for the stated lengths. Output buffers must not alias the inputs.

use crate::api::Hqc;
use crate::error::HqcError;
use crate::parameters::HqcParameterSet;
use core::panic::AssertUnwindSafe;
use std::panic::catch_unwind;

/// Success.
pub const HQC_OK: i32 = 0;
/// A buffer had the wrong length for the parameter set.
pub const HQC_ERR_BUFFER_LENGTH: i32 = -1;
/// The key was not valid for the parameter set.
pub const HQC_ERR_INVALID_KEY: i32 = -2;
/// The ciphertext was not valid for the parameter set.
pub const HQC_ERR_INVALID_CIPHERTEXT: i32 = -3;
/// The randomness source failed.
pub const HQC_ERR_RANDOMNESS: i32 = -4;
/// An internal invariant failed, or a panic was caught.
pub const HQC_ERR_INTERNAL: i32 = -5;
/// The parameter-set discriminant was not 1, 3 or 5.
pub const HQC_ERR_BAD_PARAMETER_SET: i32 = -6;
/// A required pointer was null.
pub const HQC_ERR_NULL_POINTER: i32 = -7;

fn code(e: HqcError) -> i32 {
    match e {
        HqcError::BufferLength { .. } => HQC_ERR_BUFFER_LENGTH,
        HqcError::InvalidKey => HQC_ERR_INVALID_KEY,
        HqcError::InvalidCiphertext => HQC_ERR_INVALID_CIPHERTEXT,
        HqcError::RandomnessFailure => HQC_ERR_RANDOMNESS,
        HqcError::Internal => HQC_ERR_INTERNAL,
    }
}

fn instance(param_set: u8) -> Option<Hqc> {
    let set = match param_set {
        1 => HqcParameterSet::Hqc1,
        3 => HqcParameterSet::Hqc3,
        5 => HqcParameterSet::Hqc5,
        _ => return None,
    };
    Some(Hqc::new(set))
}

/// Runs `f`, converting any panic into [`HQC_ERR_INTERNAL`].
fn guard(f: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(HQC_ERR_INTERNAL)
}

/// Writes the byte sizes for `param_set`. Any out pointer may be null.
///
/// Lets a caller allocate correctly without duplicating the parameter table.
///
/// # Safety
/// Non-null out pointers must be valid for one `usize` write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hqc_sizes(
    param_set: u8,
    ek_len: *mut usize,
    dk_len: *mut usize,
    ct_len: *mut usize,
    ss_len: *mut usize,
) -> i32 {
    guard(|| {
        let Some(h) = instance(param_set) else {
            return HQC_ERR_BAD_PARAMETER_SET;
        };
        unsafe {
            if !ek_len.is_null() {
                *ek_len = h.encapsulation_key_len();
            }
            if !dk_len.is_null() {
                *dk_len = h.decapsulation_key_len();
            }
            if !ct_len.is_null() {
                *ct_len = h.ciphertext_len();
            }
            if !ss_len.is_null() {
                *ss_len = h.shared_secret_len();
            }
        }
        HQC_OK
    })
}

/// Generates a keypair, drawing randomness from `seed` (48 bytes, as the
/// reference KAT driver does).
///
/// # Safety
/// `ek`, `dk` and `seed` must be valid for the stated lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hqc_keypair(
    param_set: u8,
    ek: *mut u8,
    ek_len: usize,
    dk: *mut u8,
    dk_len: usize,
    seed: *const u8,
    seed_len: usize,
) -> i32 {
    guard(|| {
        let Some(h) = instance(param_set) else {
            return HQC_ERR_BAD_PARAMETER_SET;
        };
        if ek.is_null() || dk.is_null() || seed.is_null() {
            return HQC_ERR_NULL_POINTER;
        }
        let (ek, dk, seed) = unsafe {
            (
                core::slice::from_raw_parts_mut(ek, ek_len),
                core::slice::from_raw_parts_mut(dk, dk_len),
                core::slice::from_raw_parts(seed, seed_len),
            )
        };
        let mut rng = crate::symmetric::prng_init(seed, &[]);
        match h.keypair(ek, dk, &mut rng) {
            Ok(()) => HQC_OK,
            Err(e) => code(e),
        }
    })
}

/// Encapsulates to `ek`.
///
/// # Safety
/// All pointers must be valid for the stated lengths and must not alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hqc_encaps(
    param_set: u8,
    ct: *mut u8,
    ct_len: usize,
    ss: *mut u8,
    ss_len: usize,
    ek: *const u8,
    ek_len: usize,
    seed: *const u8,
    seed_len: usize,
) -> i32 {
    guard(|| {
        let Some(h) = instance(param_set) else {
            return HQC_ERR_BAD_PARAMETER_SET;
        };
        if ct.is_null() || ss.is_null() || ek.is_null() || seed.is_null() {
            return HQC_ERR_NULL_POINTER;
        }
        let (ct, ss, ek, seed) = unsafe {
            (
                core::slice::from_raw_parts_mut(ct, ct_len),
                core::slice::from_raw_parts_mut(ss, ss_len),
                core::slice::from_raw_parts(ek, ek_len),
                core::slice::from_raw_parts(seed, seed_len),
            )
        };
        let mut rng = crate::symmetric::prng_init(seed, &[]);
        match h.encapsulate(ct, ss, ek, &mut rng) {
            Ok(()) => HQC_OK,
            Err(e) => code(e),
        }
    })
}

/// Decapsulates `ct` with `dk`.
///
/// Never signals a decryption failure: HQC's FO transform with implicit
/// rejection returns a pseudo-random shared secret for an invalid ciphertext,
/// and reporting that would be an oracle. A non-zero return means the inputs
/// were structurally wrong, not that decryption failed.
///
/// # Safety
/// All pointers must be valid for the stated lengths and must not alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hqc_decaps(
    param_set: u8,
    ss: *mut u8,
    ss_len: usize,
    ct: *const u8,
    ct_len: usize,
    dk: *const u8,
    dk_len: usize,
) -> i32 {
    guard(|| {
        let Some(h) = instance(param_set) else {
            return HQC_ERR_BAD_PARAMETER_SET;
        };
        if ss.is_null() || ct.is_null() || dk.is_null() {
            return HQC_ERR_NULL_POINTER;
        }
        let (ss, ct, dk) = unsafe {
            (
                core::slice::from_raw_parts_mut(ss, ss_len),
                core::slice::from_raw_parts(ct, ct_len),
                core::slice::from_raw_parts(dk, dk_len),
            )
        };
        match h.decapsulate(ss, ct, dk) {
            Ok(()) => HQC_OK,
            Err(e) => code(e),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_abi_roundtrip_for_every_parameter_set() {
        for ps in [1u8, 3, 5] {
            let (mut ekl, mut dkl, mut ctl, mut ssl) = (0usize, 0, 0, 0);
            assert_eq!(
                unsafe { hqc_sizes(ps, &mut ekl, &mut dkl, &mut ctl, &mut ssl) },
                HQC_OK
            );

            let (mut ek, mut dk) = (vec![0u8; ekl], vec![0u8; dkl]);
            let seed = [9u8; 48];
            assert_eq!(
                unsafe {
                    hqc_keypair(ps, ek.as_mut_ptr(), ekl, dk.as_mut_ptr(), dkl,
                                seed.as_ptr(), seed.len())
                },
                HQC_OK
            );

            let (mut ct, mut ss) = (vec![0u8; ctl], vec![0u8; ssl]);
            assert_eq!(
                unsafe {
                    hqc_encaps(ps, ct.as_mut_ptr(), ctl, ss.as_mut_ptr(), ssl,
                               ek.as_ptr(), ekl, seed.as_ptr(), seed.len())
                },
                HQC_OK
            );

            let mut ss2 = vec![0u8; ssl];
            assert_eq!(
                unsafe {
                    hqc_decaps(ps, ss2.as_mut_ptr(), ssl, ct.as_ptr(), ctl,
                               dk.as_ptr(), dkl)
                },
                HQC_OK
            );
            assert_eq!(ss, ss2, "param set {ps}");
        }
    }

    #[test]
    fn bad_inputs_return_codes_and_never_unwind() {
        let mut ss = [0u8; 32];
        assert_eq!(
            unsafe { hqc_sizes(2, core::ptr::null_mut(), core::ptr::null_mut(),
                               core::ptr::null_mut(), core::ptr::null_mut()) },
            HQC_ERR_BAD_PARAMETER_SET
        );
        assert_eq!(
            unsafe { hqc_decaps(1, ss.as_mut_ptr(), 32, core::ptr::null(), 0,
                                core::ptr::null(), 0) },
            HQC_ERR_NULL_POINTER
        );
        // wrong ciphertext length -> structural error, not a panic
        let ct = [0u8; 10];
        let dk = vec![0u8; 2321];
        assert_eq!(
            unsafe { hqc_decaps(1, ss.as_mut_ptr(), 32, ct.as_ptr(), ct.len(),
                                dk.as_ptr(), dk.len()) },
            HQC_ERR_INVALID_CIPHERTEXT
        );
    }
}
