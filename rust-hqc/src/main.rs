use rust_hqc::symmetric::hash_i;

fn main() {
    println!("Hello, world!");
    let seed = b"DEADBEEFDEADBEEFDEADBEEFDEADBEEF";
    let digest = hash_i(seed);
    println!("{:x?}", digest);
}
