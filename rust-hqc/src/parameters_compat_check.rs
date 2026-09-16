//! TEMPORARY: asserts the COMPAT-derived legacy constants still equal
//! the literal values from the pre-refactor parameters.rs.
#[cfg(test)]
mod compat_audit {
    use crate::parameters::*;

    #[test]
    fn legacy_constants_unchanged() {
        assert_eq!(PARAM_N, 17669, "PARAM_N");
        assert_eq!(PARAM_N1, 46, "PARAM_N1");
        assert_eq!(PARAM_N2, 384, "PARAM_N2");
        assert_eq!(PARAM_N1N2, 17664, "PARAM_N1N2");
        assert_eq!(PARAM_OMEGA, 66, "PARAM_OMEGA");
        assert_eq!(PARAM_OMEGA_E, 75, "PARAM_OMEGA_E");
        assert_eq!(PARAM_OMEGA_R, 75, "PARAM_OMEGA_R");
        assert_eq!(PARAM_SECURITY, 128, "PARAM_SECURITY");
        assert_eq!(PARAM_SECURITY_BYTES, 16, "PARAM_SECURITY_BYTES");
        assert_eq!(PARAM_DFR_EXP, 128, "PARAM_DFR_EXP");
        assert_eq!(PARAM_DELTA, 15, "PARAM_DELTA");
        assert_eq!(PARAM_M, 8, "PARAM_M");
        assert_eq!(PARAM_GF_MUL_ORDER, 255, "PARAM_GF_MUL_ORDER");
        assert_eq!(PARAM_K, 16, "PARAM_K");
        assert_eq!(PARAM_G, 31, "PARAM_G");
        assert_eq!(PARAM_FFT, 4, "PARAM_FFT");
        assert_eq!(SEED_BYTES, 32, "SEED_BYTES");
        assert_eq!(SALT_BYTES, 16, "SALT_BYTES");
        assert_eq!(PARAM_N_MU, 243079, "PARAM_N_MU");
        assert_eq!(UTILS_REJECTION_THRESHOLD, 16767881, "UTILS_REJECTION_THRESHOLD");
    }
}
