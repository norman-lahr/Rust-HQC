# Rust-HQC
A timing-constant Rust library implementation of HQC-KEM.

The HQC C Reference implementation is from https://gitlab.com/pqc-hqc/hqc.git

## Run Test Routines
```
> cd rust-hqc
> cargo test -j<NUM_THREADS>
```
With verbosity:
```
> RUST_BACKTRACE=1 cargo test -j<NUM_THREADS> -- --show-output
```
