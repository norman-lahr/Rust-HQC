//! Uniform access to the three C reference variants.
//!
//! The C reference bakes its parameter set into `parameters.h` at compile
//! time, so each variant is a separate archive exporting the same functions
//! under a different symbol prefix. A differential test at runtime parameter
//! set X must call the archive built for X — no amount of refactoring on the
//! Rust side changes that.
//!
//! Implementing one trait over the three lets a single generic test body cover
//! all of them:
//!
//! ```ignore
//! fn check_gf_mul<R: RefImpl>() {
//!     for (a, b) in [(2u16, 3u16), (0x8f, 0x3c)] {
//!         assert_eq!(unsafe { R::gf_mul(a, b) }, gf::gf_mul(a, b), "{:?}", R::SET);
//!     }
//! }
//!
//! #[test]
//! fn gf_mul_matches_all_variants() {
//!     check_gf_mul::<Ref1>();
//!     check_gf_mul::<Ref3>();
//!     check_gf_mul::<Ref5>();
//! }
//! ```
#![allow(dead_code)]

use super::{RmCodeword, RmExpandedCdw, Shake256IncCtx};
use crate::parameters::HqcParameterSet;

/// One C reference variant.
///
/// # Safety
///
/// Every method forwards directly to C, which writes through raw pointers with
/// lengths fixed by `SET`. Callers must size buffers from `SET.params()` — not
/// from whatever parameter set the Rust side is currently using. Getting this
/// wrong is a heap overflow, not a failed assertion.
pub trait RefImpl {
    /// The parameter set this archive was compiled for.
    const SET: HqcParameterSet;

    unsafe fn code_decode(m: *mut u64, em: *const u64);
    unsafe fn code_encode(em: *mut u64, m: *const u64);
    unsafe fn compute_elp(sigma: *mut u16, syndromes: *const u16) -> u16;
    unsafe fn compute_error_values(error_values: *mut u16, z: *const u16, error: *const u8);
    unsafe fn compute_fft_betas(betas: *mut u16);
    unsafe fn compute_roots(error: *mut u8, sigma: *mut u16);
    unsafe fn compute_subset_sums(subset_sums: *mut u16, set: *const u16, set_size: u16);
    unsafe fn compute_syndromes(syndromes: *mut u16, cdw: *mut u8);
    unsafe fn compute_z_poly(z: *mut u16, sigma: *const u16, degree: u16, syndromes: *const u16);
    unsafe fn correct_errors(cdw: *mut u8, error_values: *const u16);
    unsafe fn crypto_kem_dec(k_prime: *mut u8, c_kem: *const u8, dk_kem: *const u8) -> i32;
    unsafe fn crypto_kem_enc(c_kem: *mut u8, k: *mut u8, ek_kem: *const u8) -> i32;
    unsafe fn crypto_kem_keypair(ek_kem: *mut u8, dk_kem: *mut u8) -> i32;
    unsafe fn encode(word: *mut RmCodeword, message: i32);
    unsafe fn expand_and_sum(dest: *mut RmExpandedCdw, src: *const RmCodeword);
    unsafe fn fft(w: *mut u16, f: *const u16, f_coeffs: usize);
    unsafe fn fft_retrieve_error_poly(error: *mut u8, w: *const u16);
    unsafe fn find_peaks(transform: *mut RmExpandedCdw) -> i32;
    unsafe fn gf_carryless_mul(c: *mut u8, a: u8, b: u8);
    unsafe fn gf_generate(exp: *mut u16, log: *mut u16, m: i16);
    unsafe fn gf_inverse(a: u16) -> u16;
    unsafe fn gf_mod_c(i: u16, modulus: u16) -> u16;
    unsafe fn gf_mul(a: u16, b: u16) -> u16;
    unsafe fn gf_reduce(x: u16) -> u16;
    unsafe fn gf_square(a: u16) -> u16;
    unsafe fn hadamard(src: *mut RmExpandedCdw, dst: *mut RmExpandedCdw);
    unsafe fn hash_g(output: *mut u8, hash_ek_kem: *const u8, m: *const u8, salt: *const u8);
    unsafe fn hash_h(output: *mut u8, ek_kem: *const u8);
    unsafe fn hash_i(output: *mut u8, seed: *const u8);
    unsafe fn hash_j(output: *mut u8, hash_ek_kem: *const u8, sigma: *const u8, c_kem: *const u64,);
    unsafe fn hqc_c_kem_from_string(c_pke: *mut u64, salt: *mut u8, ct: *const u8);
    unsafe fn hqc_c_kem_to_string(ct: *mut u8, c_kem: *const u64);
    unsafe fn hqc_dk_pke_from_string(y: *mut u64, dk_pke: *const u8);
    unsafe fn hqc_ek_pke_from_string(h: *mut u64, s: *mut u64, ek_pke: *const u8);
    unsafe fn hqc_pke_decrypt(m: *mut u64, dk_pke: *const u8, c_pke: *const u64);
    unsafe fn hqc_pke_encrypt(c_pke: *mut u64, ek_pke: *const u8, m: *const u64, theta: *const u8,);
    unsafe fn hqc_pke_keygen(ek_pke: *mut u8, dk_pke: *mut u8, seed: *mut u8);
    unsafe fn prng_init(entropy_input: *mut u8, personalization_string: *mut u8, enlen: u32, perlen: u32);
    unsafe fn radix(f0: *mut u16, f1: *mut u16, f: *const u16, m_f: u32);
    unsafe fn radix_big(f0: *mut u16, f1: *mut u16, f: *const u16, m_f: u32);
    unsafe fn reed_muller_decode(msg: *mut u64, cdw: *const u64);
    unsafe fn reed_muller_encode(cdw: *mut u64, msg: *const u64);
    unsafe fn reed_solomon_decode(msg: *mut u64, cdw: *mut u64);
    unsafe fn reed_solomon_encode(cdw: *mut u64, msg: *const u64);
    unsafe fn schoolbook_mul(r: *mut u64, a: *const u64, b: *const u64, n: usize);
    unsafe fn shake256_inc_squeeze(output: *mut u8, output_size: u32, xof_ctx: *mut Shake256IncCtx);
    unsafe fn vect_add(o: *mut u64, v1: *const u64, v2: *const u64, size: u32);
    unsafe fn vect_compare(v1: *const u8, v2: *const u8, size: u32) -> u8;
    unsafe fn vect_generate_random_support1(ctx: *mut Shake256IncCtx, support: *mut u32, weight: u16);
    unsafe fn vect_generate_random_support2(ctx: *mut Shake256IncCtx, support: *mut u32, weight: u16);
    unsafe fn vect_mul(o: *mut u64, a1: *const u64, a2: *const u64);
    unsafe fn vect_sample_fixed_weight1(ctx: *mut Shake256IncCtx, v: *mut u64, weight: u16);
    unsafe fn vect_sample_fixed_weight2(ctx: *mut Shake256IncCtx, v: *mut u64, weight: u16);
    unsafe fn vect_set_random(ctx: *mut Shake256IncCtx, v: *mut u64);
    unsafe fn vect_truncate(v: *mut u64);
    unsafe fn vect_write_support_to_vector(v: *mut u64, support: *const u32, weight: u16);
    unsafe fn xof_get_bytes(xof_ctx: *mut Shake256IncCtx, output: *mut u8, output_size: u32);
    unsafe fn xof_init(xof_ctx: *mut Shake256IncCtx, seed: *const u8, seed_size: u32);
}

/// The HQC-1 archive.
pub struct Ref1;

impl RefImpl for Ref1 {
    const SET: HqcParameterSet = HqcParameterSet::Hqc1;

    #[inline]
    unsafe fn code_decode(m: *mut u64, em: *const u64) {
        unsafe { super::hqc1::code_decode(m, em) }
    }
    #[inline]
    unsafe fn code_encode(em: *mut u64, m: *const u64) {
        unsafe { super::hqc1::code_encode(em, m) }
    }
    #[inline]
    unsafe fn compute_elp(sigma: *mut u16, syndromes: *const u16) -> u16 {
        unsafe { super::hqc1::compute_elp(sigma, syndromes) }
    }
    #[inline]
    unsafe fn compute_error_values(error_values: *mut u16, z: *const u16, error: *const u8) {
        unsafe { super::hqc1::compute_error_values(error_values, z, error) }
    }
    #[inline]
    unsafe fn compute_fft_betas(betas: *mut u16) {
        unsafe { super::hqc1::compute_fft_betas(betas) }
    }
    #[inline]
    unsafe fn compute_roots(error: *mut u8, sigma: *mut u16) {
        unsafe { super::hqc1::compute_roots(error, sigma) }
    }
    #[inline]
    unsafe fn compute_subset_sums(subset_sums: *mut u16, set: *const u16, set_size: u16) {
        unsafe { super::hqc1::compute_subset_sums(subset_sums, set, set_size) }
    }
    #[inline]
    unsafe fn compute_syndromes(syndromes: *mut u16, cdw: *mut u8) {
        unsafe { super::hqc1::compute_syndromes(syndromes, cdw) }
    }
    #[inline]
    unsafe fn compute_z_poly(z: *mut u16, sigma: *const u16, degree: u16, syndromes: *const u16) {
        unsafe { super::hqc1::compute_z_poly(z, sigma, degree, syndromes) }
    }
    #[inline]
    unsafe fn correct_errors(cdw: *mut u8, error_values: *const u16) {
        unsafe { super::hqc1::correct_errors(cdw, error_values) }
    }
    #[inline]
    unsafe fn crypto_kem_dec(k_prime: *mut u8, c_kem: *const u8, dk_kem: *const u8) -> i32 {
        unsafe { super::hqc1::crypto_kem_dec(k_prime, c_kem, dk_kem) }
    }
    #[inline]
    unsafe fn crypto_kem_enc(c_kem: *mut u8, k: *mut u8, ek_kem: *const u8) -> i32 {
        unsafe { super::hqc1::crypto_kem_enc(c_kem, k, ek_kem) }
    }
    #[inline]
    unsafe fn crypto_kem_keypair(ek_kem: *mut u8, dk_kem: *mut u8) -> i32 {
        unsafe { super::hqc1::crypto_kem_keypair(ek_kem, dk_kem) }
    }
    #[inline]
    unsafe fn encode(word: *mut RmCodeword, message: i32) {
        unsafe { super::hqc1::encode(word, message) }
    }
    #[inline]
    unsafe fn expand_and_sum(dest: *mut RmExpandedCdw, src: *const RmCodeword) {
        unsafe { super::hqc1::expand_and_sum(dest, src) }
    }
    #[inline]
    unsafe fn fft(w: *mut u16, f: *const u16, f_coeffs: usize) {
        unsafe { super::hqc1::fft(w, f, f_coeffs) }
    }
    #[inline]
    unsafe fn fft_retrieve_error_poly(error: *mut u8, w: *const u16) {
        unsafe { super::hqc1::fft_retrieve_error_poly(error, w) }
    }
    #[inline]
    unsafe fn find_peaks(transform: *mut RmExpandedCdw) -> i32 {
        unsafe { super::hqc1::find_peaks(transform) }
    }
    #[inline]
    unsafe fn gf_carryless_mul(c: *mut u8, a: u8, b: u8) {
        unsafe { super::hqc1::gf_carryless_mul(c, a, b) }
    }
    #[inline]
    unsafe fn gf_generate(exp: *mut u16, log: *mut u16, m: i16) {
        unsafe { super::hqc1::gf_generate(exp, log, m) }
    }
    #[inline]
    unsafe fn gf_inverse(a: u16) -> u16 {
        unsafe { super::hqc1::gf_inverse(a) }
    }
    #[inline]
    unsafe fn gf_mod_c(i: u16, modulus: u16) -> u16 {
        unsafe { super::hqc1::gf_mod_c(i, modulus) }
    }
    #[inline]
    unsafe fn gf_mul(a: u16, b: u16) -> u16 {
        unsafe { super::hqc1::gf_mul(a, b) }
    }
    #[inline]
    unsafe fn gf_reduce(x: u16) -> u16 {
        unsafe { super::hqc1::gf_reduce(x) }
    }
    #[inline]
    unsafe fn gf_square(a: u16) -> u16 {
        unsafe { super::hqc1::gf_square(a) }
    }
    #[inline]
    unsafe fn hadamard(src: *mut RmExpandedCdw, dst: *mut RmExpandedCdw) {
        unsafe { super::hqc1::hadamard(src, dst) }
    }
    #[inline]
    unsafe fn hash_g(output: *mut u8, hash_ek_kem: *const u8, m: *const u8, salt: *const u8) {
        unsafe { super::hqc1::hash_g(output, hash_ek_kem, m, salt) }
    }
    #[inline]
    unsafe fn hash_h(output: *mut u8, ek_kem: *const u8) {
        unsafe { super::hqc1::hash_h(output, ek_kem) }
    }
    #[inline]
    unsafe fn hash_i(output: *mut u8, seed: *const u8) {
        unsafe { super::hqc1::hash_i(output, seed) }
    }
    #[inline]
    unsafe fn hash_j(output: *mut u8, hash_ek_kem: *const u8, sigma: *const u8, c_kem: *const u64,) {
        unsafe { super::hqc1::hash_j(output, hash_ek_kem, sigma, c_kem) }
    }
    #[inline]
    unsafe fn hqc_c_kem_from_string(c_pke: *mut u64, salt: *mut u8, ct: *const u8) {
        unsafe { super::hqc1::hqc_c_kem_from_string(c_pke, salt, ct) }
    }
    #[inline]
    unsafe fn hqc_c_kem_to_string(ct: *mut u8, c_kem: *const u64) {
        unsafe { super::hqc1::hqc_c_kem_to_string(ct, c_kem) }
    }
    #[inline]
    unsafe fn hqc_dk_pke_from_string(y: *mut u64, dk_pke: *const u8) {
        unsafe { super::hqc1::hqc_dk_pke_from_string(y, dk_pke) }
    }
    #[inline]
    unsafe fn hqc_ek_pke_from_string(h: *mut u64, s: *mut u64, ek_pke: *const u8) {
        unsafe { super::hqc1::hqc_ek_pke_from_string(h, s, ek_pke) }
    }
    #[inline]
    unsafe fn hqc_pke_decrypt(m: *mut u64, dk_pke: *const u8, c_pke: *const u64) {
        unsafe { super::hqc1::hqc_pke_decrypt(m, dk_pke, c_pke) }
    }
    #[inline]
    unsafe fn hqc_pke_encrypt(c_pke: *mut u64, ek_pke: *const u8, m: *const u64, theta: *const u8,) {
        unsafe { super::hqc1::hqc_pke_encrypt(c_pke, ek_pke, m, theta) }
    }
    #[inline]
    unsafe fn hqc_pke_keygen(ek_pke: *mut u8, dk_pke: *mut u8, seed: *mut u8) {
        unsafe { super::hqc1::hqc_pke_keygen(ek_pke, dk_pke, seed) }
    }
    #[inline]
    unsafe fn prng_init(entropy_input: *mut u8, personalization_string: *mut u8, enlen: u32, perlen: u32) {
        unsafe { super::hqc1::prng_init(entropy_input, personalization_string, enlen, perlen) }
    }
    #[inline]
    unsafe fn radix(f0: *mut u16, f1: *mut u16, f: *const u16, m_f: u32) {
        unsafe { super::hqc1::radix(f0, f1, f, m_f) }
    }
    #[inline]
    unsafe fn radix_big(f0: *mut u16, f1: *mut u16, f: *const u16, m_f: u32) {
        unsafe { super::hqc1::radix_big(f0, f1, f, m_f) }
    }
    #[inline]
    unsafe fn reed_muller_decode(msg: *mut u64, cdw: *const u64) {
        unsafe { super::hqc1::reed_muller_decode(msg, cdw) }
    }
    #[inline]
    unsafe fn reed_muller_encode(cdw: *mut u64, msg: *const u64) {
        unsafe { super::hqc1::reed_muller_encode(cdw, msg) }
    }
    #[inline]
    unsafe fn reed_solomon_decode(msg: *mut u64, cdw: *mut u64) {
        unsafe { super::hqc1::reed_solomon_decode(msg, cdw) }
    }
    #[inline]
    unsafe fn reed_solomon_encode(cdw: *mut u64, msg: *const u64) {
        unsafe { super::hqc1::reed_solomon_encode(cdw, msg) }
    }
    #[inline]
    unsafe fn schoolbook_mul(r: *mut u64, a: *const u64, b: *const u64, n: usize) {
        unsafe { super::hqc1::schoolbook_mul(r, a, b, n) }
    }
    #[inline]
    unsafe fn shake256_inc_squeeze(output: *mut u8, output_size: u32, xof_ctx: *mut Shake256IncCtx) {
        unsafe { super::hqc1::shake256_inc_squeeze(output, output_size, xof_ctx) }
    }
    #[inline]
    unsafe fn vect_add(o: *mut u64, v1: *const u64, v2: *const u64, size: u32) {
        unsafe { super::hqc1::vect_add(o, v1, v2, size) }
    }
    #[inline]
    unsafe fn vect_compare(v1: *const u8, v2: *const u8, size: u32) -> u8 {
        unsafe { super::hqc1::vect_compare(v1, v2, size) }
    }
    #[inline]
    unsafe fn vect_generate_random_support1(ctx: *mut Shake256IncCtx, support: *mut u32, weight: u16) {
        unsafe { super::hqc1::vect_generate_random_support1(ctx, support, weight) }
    }
    #[inline]
    unsafe fn vect_generate_random_support2(ctx: *mut Shake256IncCtx, support: *mut u32, weight: u16) {
        unsafe { super::hqc1::vect_generate_random_support2(ctx, support, weight) }
    }
    #[inline]
    unsafe fn vect_mul(o: *mut u64, a1: *const u64, a2: *const u64) {
        unsafe { super::hqc1::vect_mul(o, a1, a2) }
    }
    #[inline]
    unsafe fn vect_sample_fixed_weight1(ctx: *mut Shake256IncCtx, v: *mut u64, weight: u16) {
        unsafe { super::hqc1::vect_sample_fixed_weight1(ctx, v, weight) }
    }
    #[inline]
    unsafe fn vect_sample_fixed_weight2(ctx: *mut Shake256IncCtx, v: *mut u64, weight: u16) {
        unsafe { super::hqc1::vect_sample_fixed_weight2(ctx, v, weight) }
    }
    #[inline]
    unsafe fn vect_set_random(ctx: *mut Shake256IncCtx, v: *mut u64) {
        unsafe { super::hqc1::vect_set_random(ctx, v) }
    }
    #[inline]
    unsafe fn vect_truncate(v: *mut u64) {
        unsafe { super::hqc1::vect_truncate(v) }
    }
    #[inline]
    unsafe fn vect_write_support_to_vector(v: *mut u64, support: *const u32, weight: u16) {
        unsafe { super::hqc1::vect_write_support_to_vector(v, support, weight) }
    }
    #[inline]
    unsafe fn xof_get_bytes(xof_ctx: *mut Shake256IncCtx, output: *mut u8, output_size: u32) {
        unsafe { super::hqc1::xof_get_bytes(xof_ctx, output, output_size) }
    }
    #[inline]
    unsafe fn xof_init(xof_ctx: *mut Shake256IncCtx, seed: *const u8, seed_size: u32) {
        unsafe { super::hqc1::xof_init(xof_ctx, seed, seed_size) }
    }
}

/// The HQC-3 archive.
pub struct Ref3;

impl RefImpl for Ref3 {
    const SET: HqcParameterSet = HqcParameterSet::Hqc3;

    #[inline]
    unsafe fn code_decode(m: *mut u64, em: *const u64) {
        unsafe { super::hqc3::code_decode(m, em) }
    }
    #[inline]
    unsafe fn code_encode(em: *mut u64, m: *const u64) {
        unsafe { super::hqc3::code_encode(em, m) }
    }
    #[inline]
    unsafe fn compute_elp(sigma: *mut u16, syndromes: *const u16) -> u16 {
        unsafe { super::hqc3::compute_elp(sigma, syndromes) }
    }
    #[inline]
    unsafe fn compute_error_values(error_values: *mut u16, z: *const u16, error: *const u8) {
        unsafe { super::hqc3::compute_error_values(error_values, z, error) }
    }
    #[inline]
    unsafe fn compute_fft_betas(betas: *mut u16) {
        unsafe { super::hqc3::compute_fft_betas(betas) }
    }
    #[inline]
    unsafe fn compute_roots(error: *mut u8, sigma: *mut u16) {
        unsafe { super::hqc3::compute_roots(error, sigma) }
    }
    #[inline]
    unsafe fn compute_subset_sums(subset_sums: *mut u16, set: *const u16, set_size: u16) {
        unsafe { super::hqc3::compute_subset_sums(subset_sums, set, set_size) }
    }
    #[inline]
    unsafe fn compute_syndromes(syndromes: *mut u16, cdw: *mut u8) {
        unsafe { super::hqc3::compute_syndromes(syndromes, cdw) }
    }
    #[inline]
    unsafe fn compute_z_poly(z: *mut u16, sigma: *const u16, degree: u16, syndromes: *const u16) {
        unsafe { super::hqc3::compute_z_poly(z, sigma, degree, syndromes) }
    }
    #[inline]
    unsafe fn correct_errors(cdw: *mut u8, error_values: *const u16) {
        unsafe { super::hqc3::correct_errors(cdw, error_values) }
    }
    #[inline]
    unsafe fn crypto_kem_dec(k_prime: *mut u8, c_kem: *const u8, dk_kem: *const u8) -> i32 {
        unsafe { super::hqc3::crypto_kem_dec(k_prime, c_kem, dk_kem) }
    }
    #[inline]
    unsafe fn crypto_kem_enc(c_kem: *mut u8, k: *mut u8, ek_kem: *const u8) -> i32 {
        unsafe { super::hqc3::crypto_kem_enc(c_kem, k, ek_kem) }
    }
    #[inline]
    unsafe fn crypto_kem_keypair(ek_kem: *mut u8, dk_kem: *mut u8) -> i32 {
        unsafe { super::hqc3::crypto_kem_keypair(ek_kem, dk_kem) }
    }
    #[inline]
    unsafe fn encode(word: *mut RmCodeword, message: i32) {
        unsafe { super::hqc3::encode(word, message) }
    }
    #[inline]
    unsafe fn expand_and_sum(dest: *mut RmExpandedCdw, src: *const RmCodeword) {
        unsafe { super::hqc3::expand_and_sum(dest, src) }
    }
    #[inline]
    unsafe fn fft(w: *mut u16, f: *const u16, f_coeffs: usize) {
        unsafe { super::hqc3::fft(w, f, f_coeffs) }
    }
    #[inline]
    unsafe fn fft_retrieve_error_poly(error: *mut u8, w: *const u16) {
        unsafe { super::hqc3::fft_retrieve_error_poly(error, w) }
    }
    #[inline]
    unsafe fn find_peaks(transform: *mut RmExpandedCdw) -> i32 {
        unsafe { super::hqc3::find_peaks(transform) }
    }
    #[inline]
    unsafe fn gf_carryless_mul(c: *mut u8, a: u8, b: u8) {
        unsafe { super::hqc3::gf_carryless_mul(c, a, b) }
    }
    #[inline]
    unsafe fn gf_generate(exp: *mut u16, log: *mut u16, m: i16) {
        unsafe { super::hqc3::gf_generate(exp, log, m) }
    }
    #[inline]
    unsafe fn gf_inverse(a: u16) -> u16 {
        unsafe { super::hqc3::gf_inverse(a) }
    }
    #[inline]
    unsafe fn gf_mod_c(i: u16, modulus: u16) -> u16 {
        unsafe { super::hqc3::gf_mod_c(i, modulus) }
    }
    #[inline]
    unsafe fn gf_mul(a: u16, b: u16) -> u16 {
        unsafe { super::hqc3::gf_mul(a, b) }
    }
    #[inline]
    unsafe fn gf_reduce(x: u16) -> u16 {
        unsafe { super::hqc3::gf_reduce(x) }
    }
    #[inline]
    unsafe fn gf_square(a: u16) -> u16 {
        unsafe { super::hqc3::gf_square(a) }
    }
    #[inline]
    unsafe fn hadamard(src: *mut RmExpandedCdw, dst: *mut RmExpandedCdw) {
        unsafe { super::hqc3::hadamard(src, dst) }
    }
    #[inline]
    unsafe fn hash_g(output: *mut u8, hash_ek_kem: *const u8, m: *const u8, salt: *const u8) {
        unsafe { super::hqc3::hash_g(output, hash_ek_kem, m, salt) }
    }
    #[inline]
    unsafe fn hash_h(output: *mut u8, ek_kem: *const u8) {
        unsafe { super::hqc3::hash_h(output, ek_kem) }
    }
    #[inline]
    unsafe fn hash_i(output: *mut u8, seed: *const u8) {
        unsafe { super::hqc3::hash_i(output, seed) }
    }
    #[inline]
    unsafe fn hash_j(output: *mut u8, hash_ek_kem: *const u8, sigma: *const u8, c_kem: *const u64,) {
        unsafe { super::hqc3::hash_j(output, hash_ek_kem, sigma, c_kem) }
    }
    #[inline]
    unsafe fn hqc_c_kem_from_string(c_pke: *mut u64, salt: *mut u8, ct: *const u8) {
        unsafe { super::hqc3::hqc_c_kem_from_string(c_pke, salt, ct) }
    }
    #[inline]
    unsafe fn hqc_c_kem_to_string(ct: *mut u8, c_kem: *const u64) {
        unsafe { super::hqc3::hqc_c_kem_to_string(ct, c_kem) }
    }
    #[inline]
    unsafe fn hqc_dk_pke_from_string(y: *mut u64, dk_pke: *const u8) {
        unsafe { super::hqc3::hqc_dk_pke_from_string(y, dk_pke) }
    }
    #[inline]
    unsafe fn hqc_ek_pke_from_string(h: *mut u64, s: *mut u64, ek_pke: *const u8) {
        unsafe { super::hqc3::hqc_ek_pke_from_string(h, s, ek_pke) }
    }
    #[inline]
    unsafe fn hqc_pke_decrypt(m: *mut u64, dk_pke: *const u8, c_pke: *const u64) {
        unsafe { super::hqc3::hqc_pke_decrypt(m, dk_pke, c_pke) }
    }
    #[inline]
    unsafe fn hqc_pke_encrypt(c_pke: *mut u64, ek_pke: *const u8, m: *const u64, theta: *const u8,) {
        unsafe { super::hqc3::hqc_pke_encrypt(c_pke, ek_pke, m, theta) }
    }
    #[inline]
    unsafe fn hqc_pke_keygen(ek_pke: *mut u8, dk_pke: *mut u8, seed: *mut u8) {
        unsafe { super::hqc3::hqc_pke_keygen(ek_pke, dk_pke, seed) }
    }
    #[inline]
    unsafe fn prng_init(entropy_input: *mut u8, personalization_string: *mut u8, enlen: u32, perlen: u32) {
        unsafe { super::hqc3::prng_init(entropy_input, personalization_string, enlen, perlen) }
    }
    #[inline]
    unsafe fn radix(f0: *mut u16, f1: *mut u16, f: *const u16, m_f: u32) {
        unsafe { super::hqc3::radix(f0, f1, f, m_f) }
    }
    #[inline]
    unsafe fn radix_big(f0: *mut u16, f1: *mut u16, f: *const u16, m_f: u32) {
        unsafe { super::hqc3::radix_big(f0, f1, f, m_f) }
    }
    #[inline]
    unsafe fn reed_muller_decode(msg: *mut u64, cdw: *const u64) {
        unsafe { super::hqc3::reed_muller_decode(msg, cdw) }
    }
    #[inline]
    unsafe fn reed_muller_encode(cdw: *mut u64, msg: *const u64) {
        unsafe { super::hqc3::reed_muller_encode(cdw, msg) }
    }
    #[inline]
    unsafe fn reed_solomon_decode(msg: *mut u64, cdw: *mut u64) {
        unsafe { super::hqc3::reed_solomon_decode(msg, cdw) }
    }
    #[inline]
    unsafe fn reed_solomon_encode(cdw: *mut u64, msg: *const u64) {
        unsafe { super::hqc3::reed_solomon_encode(cdw, msg) }
    }
    #[inline]
    unsafe fn schoolbook_mul(r: *mut u64, a: *const u64, b: *const u64, n: usize) {
        unsafe { super::hqc3::schoolbook_mul(r, a, b, n) }
    }
    #[inline]
    unsafe fn shake256_inc_squeeze(output: *mut u8, output_size: u32, xof_ctx: *mut Shake256IncCtx) {
        unsafe { super::hqc3::shake256_inc_squeeze(output, output_size, xof_ctx) }
    }
    #[inline]
    unsafe fn vect_add(o: *mut u64, v1: *const u64, v2: *const u64, size: u32) {
        unsafe { super::hqc3::vect_add(o, v1, v2, size) }
    }
    #[inline]
    unsafe fn vect_compare(v1: *const u8, v2: *const u8, size: u32) -> u8 {
        unsafe { super::hqc3::vect_compare(v1, v2, size) }
    }
    #[inline]
    unsafe fn vect_generate_random_support1(ctx: *mut Shake256IncCtx, support: *mut u32, weight: u16) {
        unsafe { super::hqc3::vect_generate_random_support1(ctx, support, weight) }
    }
    #[inline]
    unsafe fn vect_generate_random_support2(ctx: *mut Shake256IncCtx, support: *mut u32, weight: u16) {
        unsafe { super::hqc3::vect_generate_random_support2(ctx, support, weight) }
    }
    #[inline]
    unsafe fn vect_mul(o: *mut u64, a1: *const u64, a2: *const u64) {
        unsafe { super::hqc3::vect_mul(o, a1, a2) }
    }
    #[inline]
    unsafe fn vect_sample_fixed_weight1(ctx: *mut Shake256IncCtx, v: *mut u64, weight: u16) {
        unsafe { super::hqc3::vect_sample_fixed_weight1(ctx, v, weight) }
    }
    #[inline]
    unsafe fn vect_sample_fixed_weight2(ctx: *mut Shake256IncCtx, v: *mut u64, weight: u16) {
        unsafe { super::hqc3::vect_sample_fixed_weight2(ctx, v, weight) }
    }
    #[inline]
    unsafe fn vect_set_random(ctx: *mut Shake256IncCtx, v: *mut u64) {
        unsafe { super::hqc3::vect_set_random(ctx, v) }
    }
    #[inline]
    unsafe fn vect_truncate(v: *mut u64) {
        unsafe { super::hqc3::vect_truncate(v) }
    }
    #[inline]
    unsafe fn vect_write_support_to_vector(v: *mut u64, support: *const u32, weight: u16) {
        unsafe { super::hqc3::vect_write_support_to_vector(v, support, weight) }
    }
    #[inline]
    unsafe fn xof_get_bytes(xof_ctx: *mut Shake256IncCtx, output: *mut u8, output_size: u32) {
        unsafe { super::hqc3::xof_get_bytes(xof_ctx, output, output_size) }
    }
    #[inline]
    unsafe fn xof_init(xof_ctx: *mut Shake256IncCtx, seed: *const u8, seed_size: u32) {
        unsafe { super::hqc3::xof_init(xof_ctx, seed, seed_size) }
    }
}

/// The HQC-5 archive.
pub struct Ref5;

impl RefImpl for Ref5 {
    const SET: HqcParameterSet = HqcParameterSet::Hqc5;

    #[inline]
    unsafe fn code_decode(m: *mut u64, em: *const u64) {
        unsafe { super::hqc5::code_decode(m, em) }
    }
    #[inline]
    unsafe fn code_encode(em: *mut u64, m: *const u64) {
        unsafe { super::hqc5::code_encode(em, m) }
    }
    #[inline]
    unsafe fn compute_elp(sigma: *mut u16, syndromes: *const u16) -> u16 {
        unsafe { super::hqc5::compute_elp(sigma, syndromes) }
    }
    #[inline]
    unsafe fn compute_error_values(error_values: *mut u16, z: *const u16, error: *const u8) {
        unsafe { super::hqc5::compute_error_values(error_values, z, error) }
    }
    #[inline]
    unsafe fn compute_fft_betas(betas: *mut u16) {
        unsafe { super::hqc5::compute_fft_betas(betas) }
    }
    #[inline]
    unsafe fn compute_roots(error: *mut u8, sigma: *mut u16) {
        unsafe { super::hqc5::compute_roots(error, sigma) }
    }
    #[inline]
    unsafe fn compute_subset_sums(subset_sums: *mut u16, set: *const u16, set_size: u16) {
        unsafe { super::hqc5::compute_subset_sums(subset_sums, set, set_size) }
    }
    #[inline]
    unsafe fn compute_syndromes(syndromes: *mut u16, cdw: *mut u8) {
        unsafe { super::hqc5::compute_syndromes(syndromes, cdw) }
    }
    #[inline]
    unsafe fn compute_z_poly(z: *mut u16, sigma: *const u16, degree: u16, syndromes: *const u16) {
        unsafe { super::hqc5::compute_z_poly(z, sigma, degree, syndromes) }
    }
    #[inline]
    unsafe fn correct_errors(cdw: *mut u8, error_values: *const u16) {
        unsafe { super::hqc5::correct_errors(cdw, error_values) }
    }
    #[inline]
    unsafe fn crypto_kem_dec(k_prime: *mut u8, c_kem: *const u8, dk_kem: *const u8) -> i32 {
        unsafe { super::hqc5::crypto_kem_dec(k_prime, c_kem, dk_kem) }
    }
    #[inline]
    unsafe fn crypto_kem_enc(c_kem: *mut u8, k: *mut u8, ek_kem: *const u8) -> i32 {
        unsafe { super::hqc5::crypto_kem_enc(c_kem, k, ek_kem) }
    }
    #[inline]
    unsafe fn crypto_kem_keypair(ek_kem: *mut u8, dk_kem: *mut u8) -> i32 {
        unsafe { super::hqc5::crypto_kem_keypair(ek_kem, dk_kem) }
    }
    #[inline]
    unsafe fn encode(word: *mut RmCodeword, message: i32) {
        unsafe { super::hqc5::encode(word, message) }
    }
    #[inline]
    unsafe fn expand_and_sum(dest: *mut RmExpandedCdw, src: *const RmCodeword) {
        unsafe { super::hqc5::expand_and_sum(dest, src) }
    }
    #[inline]
    unsafe fn fft(w: *mut u16, f: *const u16, f_coeffs: usize) {
        unsafe { super::hqc5::fft(w, f, f_coeffs) }
    }
    #[inline]
    unsafe fn fft_retrieve_error_poly(error: *mut u8, w: *const u16) {
        unsafe { super::hqc5::fft_retrieve_error_poly(error, w) }
    }
    #[inline]
    unsafe fn find_peaks(transform: *mut RmExpandedCdw) -> i32 {
        unsafe { super::hqc5::find_peaks(transform) }
    }
    #[inline]
    unsafe fn gf_carryless_mul(c: *mut u8, a: u8, b: u8) {
        unsafe { super::hqc5::gf_carryless_mul(c, a, b) }
    }
    #[inline]
    unsafe fn gf_generate(exp: *mut u16, log: *mut u16, m: i16) {
        unsafe { super::hqc5::gf_generate(exp, log, m) }
    }
    #[inline]
    unsafe fn gf_inverse(a: u16) -> u16 {
        unsafe { super::hqc5::gf_inverse(a) }
    }
    #[inline]
    unsafe fn gf_mod_c(i: u16, modulus: u16) -> u16 {
        unsafe { super::hqc5::gf_mod_c(i, modulus) }
    }
    #[inline]
    unsafe fn gf_mul(a: u16, b: u16) -> u16 {
        unsafe { super::hqc5::gf_mul(a, b) }
    }
    #[inline]
    unsafe fn gf_reduce(x: u16) -> u16 {
        unsafe { super::hqc5::gf_reduce(x) }
    }
    #[inline]
    unsafe fn gf_square(a: u16) -> u16 {
        unsafe { super::hqc5::gf_square(a) }
    }
    #[inline]
    unsafe fn hadamard(src: *mut RmExpandedCdw, dst: *mut RmExpandedCdw) {
        unsafe { super::hqc5::hadamard(src, dst) }
    }
    #[inline]
    unsafe fn hash_g(output: *mut u8, hash_ek_kem: *const u8, m: *const u8, salt: *const u8) {
        unsafe { super::hqc5::hash_g(output, hash_ek_kem, m, salt) }
    }
    #[inline]
    unsafe fn hash_h(output: *mut u8, ek_kem: *const u8) {
        unsafe { super::hqc5::hash_h(output, ek_kem) }
    }
    #[inline]
    unsafe fn hash_i(output: *mut u8, seed: *const u8) {
        unsafe { super::hqc5::hash_i(output, seed) }
    }
    #[inline]
    unsafe fn hash_j(output: *mut u8, hash_ek_kem: *const u8, sigma: *const u8, c_kem: *const u64,) {
        unsafe { super::hqc5::hash_j(output, hash_ek_kem, sigma, c_kem) }
    }
    #[inline]
    unsafe fn hqc_c_kem_from_string(c_pke: *mut u64, salt: *mut u8, ct: *const u8) {
        unsafe { super::hqc5::hqc_c_kem_from_string(c_pke, salt, ct) }
    }
    #[inline]
    unsafe fn hqc_c_kem_to_string(ct: *mut u8, c_kem: *const u64) {
        unsafe { super::hqc5::hqc_c_kem_to_string(ct, c_kem) }
    }
    #[inline]
    unsafe fn hqc_dk_pke_from_string(y: *mut u64, dk_pke: *const u8) {
        unsafe { super::hqc5::hqc_dk_pke_from_string(y, dk_pke) }
    }
    #[inline]
    unsafe fn hqc_ek_pke_from_string(h: *mut u64, s: *mut u64, ek_pke: *const u8) {
        unsafe { super::hqc5::hqc_ek_pke_from_string(h, s, ek_pke) }
    }
    #[inline]
    unsafe fn hqc_pke_decrypt(m: *mut u64, dk_pke: *const u8, c_pke: *const u64) {
        unsafe { super::hqc5::hqc_pke_decrypt(m, dk_pke, c_pke) }
    }
    #[inline]
    unsafe fn hqc_pke_encrypt(c_pke: *mut u64, ek_pke: *const u8, m: *const u64, theta: *const u8,) {
        unsafe { super::hqc5::hqc_pke_encrypt(c_pke, ek_pke, m, theta) }
    }
    #[inline]
    unsafe fn hqc_pke_keygen(ek_pke: *mut u8, dk_pke: *mut u8, seed: *mut u8) {
        unsafe { super::hqc5::hqc_pke_keygen(ek_pke, dk_pke, seed) }
    }
    #[inline]
    unsafe fn prng_init(entropy_input: *mut u8, personalization_string: *mut u8, enlen: u32, perlen: u32) {
        unsafe { super::hqc5::prng_init(entropy_input, personalization_string, enlen, perlen) }
    }
    #[inline]
    unsafe fn radix(f0: *mut u16, f1: *mut u16, f: *const u16, m_f: u32) {
        unsafe { super::hqc5::radix(f0, f1, f, m_f) }
    }
    #[inline]
    unsafe fn radix_big(f0: *mut u16, f1: *mut u16, f: *const u16, m_f: u32) {
        unsafe { super::hqc5::radix_big(f0, f1, f, m_f) }
    }
    #[inline]
    unsafe fn reed_muller_decode(msg: *mut u64, cdw: *const u64) {
        unsafe { super::hqc5::reed_muller_decode(msg, cdw) }
    }
    #[inline]
    unsafe fn reed_muller_encode(cdw: *mut u64, msg: *const u64) {
        unsafe { super::hqc5::reed_muller_encode(cdw, msg) }
    }
    #[inline]
    unsafe fn reed_solomon_decode(msg: *mut u64, cdw: *mut u64) {
        unsafe { super::hqc5::reed_solomon_decode(msg, cdw) }
    }
    #[inline]
    unsafe fn reed_solomon_encode(cdw: *mut u64, msg: *const u64) {
        unsafe { super::hqc5::reed_solomon_encode(cdw, msg) }
    }
    #[inline]
    unsafe fn schoolbook_mul(r: *mut u64, a: *const u64, b: *const u64, n: usize) {
        unsafe { super::hqc5::schoolbook_mul(r, a, b, n) }
    }
    #[inline]
    unsafe fn shake256_inc_squeeze(output: *mut u8, output_size: u32, xof_ctx: *mut Shake256IncCtx) {
        unsafe { super::hqc5::shake256_inc_squeeze(output, output_size, xof_ctx) }
    }
    #[inline]
    unsafe fn vect_add(o: *mut u64, v1: *const u64, v2: *const u64, size: u32) {
        unsafe { super::hqc5::vect_add(o, v1, v2, size) }
    }
    #[inline]
    unsafe fn vect_compare(v1: *const u8, v2: *const u8, size: u32) -> u8 {
        unsafe { super::hqc5::vect_compare(v1, v2, size) }
    }
    #[inline]
    unsafe fn vect_generate_random_support1(ctx: *mut Shake256IncCtx, support: *mut u32, weight: u16) {
        unsafe { super::hqc5::vect_generate_random_support1(ctx, support, weight) }
    }
    #[inline]
    unsafe fn vect_generate_random_support2(ctx: *mut Shake256IncCtx, support: *mut u32, weight: u16) {
        unsafe { super::hqc5::vect_generate_random_support2(ctx, support, weight) }
    }
    #[inline]
    unsafe fn vect_mul(o: *mut u64, a1: *const u64, a2: *const u64) {
        unsafe { super::hqc5::vect_mul(o, a1, a2) }
    }
    #[inline]
    unsafe fn vect_sample_fixed_weight1(ctx: *mut Shake256IncCtx, v: *mut u64, weight: u16) {
        unsafe { super::hqc5::vect_sample_fixed_weight1(ctx, v, weight) }
    }
    #[inline]
    unsafe fn vect_sample_fixed_weight2(ctx: *mut Shake256IncCtx, v: *mut u64, weight: u16) {
        unsafe { super::hqc5::vect_sample_fixed_weight2(ctx, v, weight) }
    }
    #[inline]
    unsafe fn vect_set_random(ctx: *mut Shake256IncCtx, v: *mut u64) {
        unsafe { super::hqc5::vect_set_random(ctx, v) }
    }
    #[inline]
    unsafe fn vect_truncate(v: *mut u64) {
        unsafe { super::hqc5::vect_truncate(v) }
    }
    #[inline]
    unsafe fn vect_write_support_to_vector(v: *mut u64, support: *const u32, weight: u16) {
        unsafe { super::hqc5::vect_write_support_to_vector(v, support, weight) }
    }
    #[inline]
    unsafe fn xof_get_bytes(xof_ctx: *mut Shake256IncCtx, output: *mut u8, output_size: u32) {
        unsafe { super::hqc5::xof_get_bytes(xof_ctx, output, output_size) }
    }
    #[inline]
    unsafe fn xof_init(xof_ctx: *mut Shake256IncCtx, seed: *const u8, seed_size: u32) {
        unsafe { super::hqc5::xof_init(xof_ctx, seed, seed_size) }
    }
}
