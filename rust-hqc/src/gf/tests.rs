use crate::parameters::PARAM_M;

unsafe extern "C" {
    fn gf_generate(exp: *mut u16, log: *mut u16, m: i16);
}

/// Safe wrapper around the C `gf_generate` function.
pub fn gf_generate_ref(m: u16) -> (Vec<u16>, Vec<u16>) {
    let field_size = 1usize << m;
    let mut exp = vec![0u16; field_size + 2];
    let mut log = vec![0u16; field_size];
    unsafe {
        gf_generate(exp.as_mut_ptr(), log.as_mut_ptr(), m as i16);
    }
    (exp, log)
}

#[test]
fn test_gf_generate() {
    let (exp, log) = crate::gf::gf_generate(PARAM_M as u16);
    let (exp_ref, log_ref) = gf_generate_ref(PARAM_M as u16);

    assert_eq!(exp, exp_ref, "Rust and C exp tables must be identical");
    assert_eq!(log, log_ref, "Rust and C log tables must be identical");
}
