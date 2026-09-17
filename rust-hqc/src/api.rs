//! The public HQC-KEM API.
//!
//! This is the surface a binding — Botan in particular — is expected to use.
//! It differs from the internal `kem` module in three ways that matter at an
//! FFI boundary:
//!
//! - every operation returns [`Result`] rather than panicking;
//! - the caller provides the output buffers, matching `std::span` on the
//!   Botan side, so nothing is allocated and returned across the boundary;
//! - sizes are queried from the instance, so a caller can allocate correctly
//!   without duplicating the parameter table.
//!
//! The previous hardcoded `CRYPTO_*BYTES` constants are gone: they described
//! HQC-1 only and were wrong for any other parameter set.

use crate::error::{check_len, HqcError, Result};
use crate::kem;
use crate::parameters::{HqcParameterSet, HqcParameters};
use sha3::digest::XofReader;

/// An HQC-KEM instance bound to one parameter set.
///
/// One pointer wide: [`HqcParameters`] instances are `'static`, so this is
/// free to copy and there is nothing to own or free. That is what lets the C
/// ABI stay stateless — a binding can pass a parameter-set discriminant on
/// every call instead of managing a handle lifetime.
#[derive(Clone, Copy, Debug)]
pub struct Hqc {
    p: &'static HqcParameters,
}

impl Hqc {
    /// Creates an instance for `set`.
    pub const fn new(set: HqcParameterSet) -> Self {
        Self { p: set.params() }
    }

    /// The parameter set in use.
    pub const fn parameter_set(&self) -> HqcParameterSet {
        self.p.set
    }

    /// The underlying parameters.
    pub const fn parameters(&self) -> &'static HqcParameters {
        self.p
    }

    /// Canonical name, e.g. `"HQC-1"`.
    pub const fn name(&self) -> &'static str {
        self.p.set.name()
    }

    /// Encapsulation key length in bytes. Botan: `Public_Key::key_length`.
    pub const fn encapsulation_key_len(&self) -> usize {
        self.p.ek_bytes
    }

    /// Decapsulation key length in bytes.
    pub const fn decapsulation_key_len(&self) -> usize {
        self.p.dk_bytes
    }

    /// Ciphertext length in bytes. Botan: `encapsulated_key_length`.
    pub const fn ciphertext_len(&self) -> usize {
        self.p.ct_bytes
    }

    /// Shared secret length in bytes. Botan: `shared_key_length`.
    pub const fn shared_secret_len(&self) -> usize {
        self.p.ss_bytes
    }

    /// Generates a keypair into caller-provided buffers.
    ///
    /// # Errors
    /// [`HqcError::BufferLength`] if either buffer is the wrong size.
    pub fn keypair(
        &self,
        ek: &mut [u8],
        dk: &mut [u8],
        rng: &mut impl XofReader,
    ) -> Result<()> {
        check_len("encapsulation key", ek, self.p.ek_bytes)?;
        check_len("decapsulation key", dk, self.p.dk_bytes)?;

        let (ek_v, dk_v) = kem::crypto_kem_keypair(self.p, rng);
        if ek_v.len() != ek.len() || dk_v.len() != dk.len() {
            return Err(HqcError::Internal);
        }
        ek.copy_from_slice(&ek_v);
        dk.copy_from_slice(&dk_v);
        Ok(())
    }

    /// Encapsulates to `ek`, writing the ciphertext and shared secret.
    ///
    /// # Errors
    /// [`HqcError::BufferLength`] on a wrong-sized output buffer,
    /// [`HqcError::InvalidKey`] if `ek` is not the right length for this set.
    pub fn encapsulate(
        &self,
        ct: &mut [u8],
        ss: &mut [u8],
        ek: &[u8],
        rng: &mut impl XofReader,
    ) -> Result<()> {
        check_len("ciphertext", ct, self.p.ct_bytes)?;
        check_len("shared secret", ss, self.p.ss_bytes)?;
        if ek.len() != self.p.ek_bytes {
            return Err(HqcError::InvalidKey);
        }

        let (ct_v, ss_v) = kem::crypto_kem_enc(self.p, rng, ek);
        if ct_v.len() != ct.len() || ss_v.len() != ss.len() {
            return Err(HqcError::Internal);
        }
        ct.copy_from_slice(&ct_v);
        ss.copy_from_slice(&ss_v);
        Ok(())
    }

    /// Decapsulates `ct` with `dk`, writing the shared secret.
    ///
    /// Never reports a decryption failure. HQC uses the Fujisaki-Okamoto
    /// transform with implicit rejection, so a ciphertext that does not
    /// re-encrypt yields a pseudo-random shared secret derived from the
    /// rejection key. Returning a distinguishable error here would hand an
    /// attacker exactly the oracle that construction removes.
    ///
    /// # Errors
    /// [`HqcError::BufferLength`], [`HqcError::InvalidCiphertext`] or
    /// [`HqcError::InvalidKey`] — all structural, none content-dependent.
    pub fn decapsulate(&self, ss: &mut [u8], ct: &[u8], dk: &[u8]) -> Result<()> {
        check_len("shared secret", ss, self.p.ss_bytes)?;
        if ct.len() != self.p.ct_bytes {
            return Err(HqcError::InvalidCiphertext);
        }
        if dk.len() != self.p.dk_bytes {
            return Err(HqcError::InvalidKey);
        }

        let ss_v = kem::crypto_kem_dec(self.p, ct, dk);
        if ss_v.len() != ss.len() {
            return Err(HqcError::Internal);
        }
        ss.copy_from_slice(&ss_v);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::prng_init;

    #[test]
    fn sizes_match_the_specification() {
        // Table 6 of hqc_specifications_2025_08_22.pdf.
        for (set, ek, dk, ct) in [
            (HqcParameterSet::Hqc1, 2241, 2321, 4433),
            (HqcParameterSet::Hqc3, 4514, 4602, 8978),
            (HqcParameterSet::Hqc5, 7237, 7333, 14421),
        ] {
            let h = Hqc::new(set);
            assert_eq!(h.encapsulation_key_len(), ek);
            assert_eq!(h.decapsulation_key_len(), dk);
            assert_eq!(h.ciphertext_len(), ct);
            assert_eq!(h.shared_secret_len(), 32);
        }
    }

    #[test]
    fn roundtrip_for_every_parameter_set() {
        for set in HqcParameterSet::ALL {
            let h = Hqc::new(set);
            let mut rng = prng_init(&[7u8; 48], &[]);

            let mut ek = vec![0u8; h.encapsulation_key_len()];
            let mut dk = vec![0u8; h.decapsulation_key_len()];
            h.keypair(&mut ek, &mut dk, &mut rng).unwrap();

            let mut ct = vec![0u8; h.ciphertext_len()];
            let mut ss = vec![0u8; h.shared_secret_len()];
            h.encapsulate(&mut ct, &mut ss, &ek, &mut rng).unwrap();

            let mut ss2 = vec![0u8; h.shared_secret_len()];
            h.decapsulate(&mut ss2, &ct, &dk).unwrap();

            assert_eq!(ss, ss2, "{}", h.name());
        }
    }

    #[test]
    fn wrong_buffer_lengths_are_errors_not_panics() {
        let h = Hqc::new(HqcParameterSet::Hqc1);
        let mut rng = prng_init(&[1u8; 48], &[]);

        let mut short = vec![0u8; 8];
        let mut dk = vec![0u8; h.decapsulation_key_len()];
        assert!(matches!(
            h.keypair(&mut short, &mut dk, &mut rng),
            Err(HqcError::BufferLength { .. })
        ));

        let mut ss = vec![0u8; h.shared_secret_len()];
        assert_eq!(
            h.decapsulate(&mut ss, &[0u8; 10], &vec![0u8; h.decapsulation_key_len()]),
            Err(HqcError::InvalidCiphertext)
        );
    }

    /// A ciphertext from one parameter set must be rejected by another,
    /// structurally, before any secret-dependent work happens.
    #[test]
    fn cross_parameter_set_inputs_are_rejected() {
        let h1 = Hqc::new(HqcParameterSet::Hqc1);
        let h5 = Hqc::new(HqcParameterSet::Hqc5);
        let mut ss = vec![0u8; h5.shared_secret_len()];
        let ct1 = vec![0u8; h1.ciphertext_len()];
        let dk5 = vec![0u8; h5.decapsulation_key_len()];
        assert_eq!(
            h5.decapsulate(&mut ss, &ct1, &dk5),
            Err(HqcError::InvalidCiphertext)
        );
    }
}
