use std::os::raw::c_uint; // u8 maps directly in Rust

unsafe extern "C" {
    fn hash_i(output: *mut u8, seed: *const u8);
}

/// Safe wrapper around the C hash_i function
pub fn hash_i_ref(seed: &[u8]) -> [u8; 64] {
    let mut output = [0u8; 64];
    unsafe {
        hash_i(output.as_mut_ptr(), seed.as_ptr());
    }
    output
}

fn main() {
    use rust_hqc::symmetric::hash_i;

    let seed = b"DEADBEEFDEADBEEFDEADBEEFDEADBEEF";
    let digest = hash_i(seed);
    let digest_ref = hash_i_ref(seed);
    println!("{:x?}", digest);
    println!("{:x?}", digest_ref);

    use rust_hqc::parameters::PARAM_N;
    use rust_hqc::vector::barrett_reduce;

    let x = 10287698u32;
    let res = barrett_reduce(x);
    let res_ref = x % PARAM_N as u32;
    println!("{} == {} -> {}", res, res_ref, res == res_ref);
}
