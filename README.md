# Rust-HQC

A Rust implementation of **HQC**, the code-based key encapsulation mechanism
selected by NIST as a backup to ML-KEM. Ported from the [reference C
implementation](https://gitlab.com/pqc-hqc/hqc.git) and intended for integration
into [Botan](https://botan.randombit.net/). The Rust code follows the
constant-time requirement.

In contrast to the C reference implementation, tThe parameter set, HQC-1, HQC-3,
or HQC-5, is selected **at run time**. So, one binary library serves all three.

The rust port tracks the specification dated **2025-08-22** (v5.0.0), which uses
the salted Fujisaki–Okamoto transform with implicit rejection.

The `main`-branch has **no C dependency** and serves as the preparation for the
Botan integration. Differential tests against the C reference live on the
`ffi-testing` branch.

## HQC Parameter Sets

|       | NIST level  |      n |    ek |    dk |     ct | ss |
|-------|-------------|-------:|------:|------:|-------:|---:|
| HQC-1 | 1 (128-bit) | 17 669 | 2 241 | 2 321 |  4 433 | 32 |
| HQC-3 | 3 (192-bit) | 35 851 | 4 514 | 4 602 |  8 978 | 32 |
| HQC-5 | 5 (256-bit) | 57 637 | 7 237 | 7 333 | 14 421 | 32 |

Sizes in bytes, matching Table 6 of the specification. They are derived in
`parameters.rs` and pinned there by compile-time assertions.

## Modules

| Module        | Purpose                                                                                                                                                      |
|---------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `api`         | **Public API.** `Hqc` handle, caller-provided buffers, `Result` returns, length accessors. Start here.                                                       |
| `capi`        | **C ABI** for Botan. Stateless `extern "C"` entry points, `catch_unwind` on every one, integer error codes.                                                  |
| `error`       | `HqcError` and the crate's `Result` alias.                                                                                                                   |
| `nist`        | The NIST `api.h` constants (`CRYPTO_SECRETKEYBYTES` …), one module per parameter set, pinned against the reference.                                          |
| `parameters`  | `HqcParameterSet`, `HqcParameters`, and the three `const` instances. Everything parameter-dependent originates here, including the generated α-power tables. |
| `kem`         | HQC-KEM: keygen, encapsulation, decapsulation. The salted FO transform with implicit rejection.                                                              |
| `pke`         | HQC-PKE underneath the KEM: keygen, encrypt, decrypt.                                                                                                        |
| `code`        | The concatenated code: `reed_solomon` (external, over GF(256)) and `reed_muller` (internal, duplicated RM(1,7)).                                             |
| `gf`          | GF(2⁸) arithmetic. Parameter-independent — identical for all three sets.                                                                                     |
| `fft`         | Additive FFT used to find the roots of the error-locator polynomial.                                                                                         |
| `gf2x`        | Polynomial multiplication mod X<sup>n</sup>−1: Karatsuba plus reduction.                                                                                     |
| `vector`      | Fixed-weight and uniform vector sampling, constant-time vector operations.                                                                                   |
| `parsing`     | Serialisation of keys and ciphertexts to and from byte strings.                                                                                              |
| `symmetric`   | SHAKE256 XOF and the domain-separated hashes G, H, I, J.                                                                                                     |
| `testvectors` | *(test only)* Parser for the reference's `intermediates_values` traces.                                                                                      |

## Run the Tests

```sh
cd rust-hqc
cargo test -j<NUM_THREADS>
```

With verbosity:
```
> RUST_BACKTRACE=1 cargo test -j<NUM_THREADS> -- --show-output
```

What they cover:

| Suite                        | What it checks                                                                                                                                                    |
|------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `kem::tests_kat`             | The full 100-vector NIST KAT suite **for all three parameter sets**, against the vendored `.rsp` files. The strongest single check in the crate.                  |
| `testvectors::intermediates` | The reference's own trace of every internal value through keygen/encaps/decaps — `x`, `y`, `h`, `s`, `r1`, `r2`, `e`, `theta`, `c_kem`, `K` — for all three sets. |
| `parameters::tests`          | Regenerates the alpha-power tables from GF(2^8) arithmetic; checks ordering and RS generator polynomials.                                                              |
| `api::tests`                 | Round-trip per parameter set; buffer-length errors; cross-parameter-set rejection.                                                                                |
| `capi::tests`                | The C ABI round-trip and its error codes.                                                                                                                         |
| `nist::tests`                | Static `CRYPTO_*` constants against the runtime accessors.                                                                                                        |
| `vector::tests`              | `barrett_reduce` against `x % n` over the full 24-bit sampler domain, all three sets.                                                                             |

Useful subsets:

```sh
cargo test test_hqc_kem_kat_vectors   # KAT suite, all three sets
cargo test testvectors                # internal-value traces
cargo test --release                  # KATs are ~10x faster
```

## Using the Crate from Rust

```rust
use rust_hqc::api::Hqc;
use rust_hqc::parameters::HqcParameterSet;

let hqc = Hqc::new(HqcParameterSet::Hqc3);

let mut ek = vec![0u8; hqc.encapsulation_key_len()];
let mut dk = vec![0u8; hqc.decapsulation_key_len()];
hqc.keypair(&mut ek, &mut dk, &mut rng)?;

let mut ct = vec![0u8; hqc.ciphertext_len()];
let mut ss = vec![0u8; hqc.shared_secret_len()];
hqc.encapsulate(&mut ct, &mut ss, &ek, &mut rng)?;

let mut ss2 = vec![0u8; hqc.shared_secret_len()];
hqc.decapsulate(&mut ss2, &ct, &dk)?;
assert_eq!(ss, ss2);
```

## Integrating with Botan

### 1. Build a static library

```toml
[lib]
crate-type = ["lib", "staticlib"]
```

```sh
cargo build --release          # target/release/librust_hqc.a
```

### 2. The C ABI

Four functions, declared in `src/capi.rs`. **Stateless** — the parameter set is
a `uint8_t` discriminant (1, 3 or 5) passed on every call. There is no handle
to create or free, because `HqcParameters` instances are `'static`; a
`Botan::HQC_PublicKey` needs to hold nothing beyond the enum.

```c
int hqc_sizes  (uint8_t ps, size_t *ek, size_t *dk, size_t *ct, size_t *ss);
int hqc_keypair(uint8_t ps, uint8_t *ek, size_t ek_len,
                            uint8_t *dk, size_t dk_len,
                      const uint8_t *seed, size_t seed_len);
int hqc_encaps (uint8_t ps, uint8_t *ct, size_t ct_len,
                            uint8_t *ss, size_t ss_len,
                      const uint8_t *ek, size_t ek_len,
                      const uint8_t *seed, size_t seed_len);
int hqc_decaps (uint8_t ps, uint8_t *ss, size_t ss_len,
                      const uint8_t *ct, size_t ct_len,
                      const uint8_t *dk, size_t dk_len);
```

Return codes:

|      |                                           |
|------|-------------------------------------------|
| `0`  | success                                   |
| `-1` | buffer length wrong for the parameter set |
| `-2` | invalid key                               |
| `-3` | invalid ciphertext                        |
| `-4` | randomness failure                        |
| `-5` | internal error, or a caught panic         |
| `-6` | parameter set not 1, 3 or 5               |
| `-7` | null pointer                              |

### 3. Mapping onto Botan

| Botan                                             | Here               |
|---------------------------------------------------|--------------------|
| `Public_Key::key_length()`                        | `hqc_sizes` -> `ek` |
| `KEM_Encryption::encapsulated_key_length()`       | `hqc_sizes` -> `ct` |
| `KEM_Encryption::shared_key_length()`             | `hqc_sizes` -> `ss` |
| `KEM_Encryption::kem_encrypt(span, span, rng, …)` | `hqc_encaps`       |
| `KEM_Decryption::kem_decrypt(span, span, …)`      | `hqc_decaps`       |

Botan's `std::span` maps directly: `span.data()` and `span.size()` are the
pointer/length pairs above. Nothing is allocated on the Rust side and returned
across the boundary.

### 4. Two Properties to Preserve

**Never unwind into C++.** Every entry point already wraps its work in
`catch_unwind` and converts a panic to `-5`. Do not add an FFI function that
bypasses that.

**`hqc_decaps` never reports a decryption failure.** HQC uses the FO transform
with implicit rejection: an invalid ciphertext yields a pseudo-random shared
secret derived from the rejection key, and reporting it would hand an attacker
the oracle that construction exists to remove. A non-zero return means the
*inputs were structurally wrong* — wrong length, null pointer, bad parameter
set — never "decryption failed". Do not "improve" this by adding a
verification failure code.

### 5. Smoke Test

`rust-hqc/botan_abi_smoketest.c` links the static library and exercises all
three parameter sets — roughly what `HQC_KEM_Encryption`/`Decryption` will do:

```sh
gcc -O2 botan_abi_smoketest.c -o smoketest \
    -L target/release -lrust_hqc -lpthread -ldl -lm
./smoketest
```

```
HQC-1  ek=2241 dk=2321 ct=4433 ss=32  rc=0/0/0  shared secret MATCHES
HQC-3  ek=4514 dk=4602 ct=8978 ss=32  rc=0/0/0  shared secret MATCHES
HQC-5  ek=7237 dk=7333 ct=14421 ss=32  rc=0/0/0  shared secret MATCHES
```

### Still to do on the Botan side

`src/lib/pubkey/hqc/` following the Classic McEliece module layout,
`HQC_PublicKey`/`HQC_PrivateKey`, the `PK_Ops` subclasses, registration in
`pk_algs.cpp`, an OID in `src/build-data/oids.txt`, and `.vec` KAT files under
`src/tests/data/pubkey/`.

## Relationship to `ffi-testing`-branch

`ffi-testing` is this branch plus the C reference as a submodule and multiple
differential unit tests that compare every function against it.

**Develop here. Rebase `ffi-testing` forward. Never merge it back.** The FFI
branch adds files and modifies none, which is what keeps the rebase
conflict-free.

