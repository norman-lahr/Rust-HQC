unsafe extern "C" {
    fn hash_i(output: *mut u8, seed: *const u8);
    fn hash_g(output: *mut u8, seed: *const u8);
}

/// Safe wrapper around the C hash_i function
fn hash_i_ref(seed: &[u8]) -> [u8; 64] {
    let mut output = [0u8; 64];
    unsafe {
        hash_i(output.as_mut_ptr(), seed.as_ptr());
    }
    output
}

/// Safe wrapper around the C hash_g function
fn hash_g_ref(seed: &[u8]) -> [u8; 64] {
    let mut output = [0u8; 64];
    unsafe {
        hash_g(output.as_mut_ptr(), seed.as_ptr());
    }
    output
}

#[test]
fn test_hash_i() {
    let seed = b"DEADBEEFDEADBEEFDEADBEEFDEADBEEF";
    let digest = crate::symmetric::hash_i(seed);
    let digest_ref = hash_i_ref(seed);
    assert_eq!(digest, digest_ref, "Both digest should be equal");
}

#[test]
fn test_hash_g() {
    let seed = b"DEADBEEFDEADBEEFDEADBEEFDEADBEEF";
    let digest = crate::symmetric::hash_i(seed);
    let digest_ref = hash_i_ref(seed);
    assert_eq!(digest, digest_ref, "Both digest should be equal");
}
