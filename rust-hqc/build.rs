// Linking to the C reference implementation
fn main() {
    let lib_path_hqc_ref = "/home/nlahr/Projects/hqc/build-ref/src";
    let lib_path_keccak = "/home/nlahr/Projects/hqc/build-ref/lib";

    println!("cargo:rustc-link-search={}", lib_path_hqc_ref);
    println!("cargo:rustc-link-lib=static=hqc_1_ref");
    println!("cargo:rustc-link-search={}", lib_path_keccak);
    println!("cargo:rustc-link-lib=static=fips202");
    println!("cargo:rerun-if-changed=build.rs");
}
