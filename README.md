# Rust-HQC with FFI-Tests

This is the `main` branch plus the HQC **C reference implementation** as a
submodule, and the differential tests that compare the Rust port against it,
function by function.

Initialize the submodule and run the ffi-tests by:
```sh
git submodule update --init --recursive
cd rust-hqc && cargo test -j<NUM_THREADS> --features ref-ffi
```
## Prerequisites

The tests require **cmake >= 3.21**, a C compiler, and `nm` from binutils.

## How it differs from `main`

Because this branch never edits a line that `main` also edits, `git rebase main`
is reliably conflict-free.

| Added here                                    | Purpose                                                                                               |
|-----------------------------------------------|-------------------------------------------------------------------------------------------------------|
| `.gitmodules`, `third_party/hqc-next-release` | The C reference, pinned to a specific commit.                                                         |
| `build.rs`                                    | Builds the reference via its own CMake, applies the un-static rewrite, generates symbol prefixes.     |
| `src/ffi/mod.rs`                              | Shared FFI types; `Shake256IncCtx`.                                                                   |
| `src/ffi/variants.rs`                         | The `RefImpl` trait and `Ref1`/`Ref3`/`Ref5`, letting one test body run against all three C archives. |
| `src/ffi/hqc{1,3,5}.rs`                       | `extern "C"` declarations, one set per variant, each `#[link_name]`-bound to its prefixed symbol.     |
| `src/ffi/tests_variants.rs`                   | Tests generic over `R: RefImpl`.                                                                      |
| `src/*/tests_ffi.rs` (9)                      | Per-module differential tests.                                                                        |

`main` already carries the inert `#[cfg(all(test, feature = "ref-ffi"))] mod
tests_ffi;` declarations. **Do not remove them there**; a `cfg`'d-out `mod`
with no file is legal, and those lines are why the delta stays purely additive.

## What `build.rs` does

Driving the reference's own CMake rather than compiling the sources directly
means the build follows upstream automatically, including the AVX2 target.
Three things it must work around:

1. **Un-static rewrite.** Multiple functions the differential tests target are
   `static` in the C sources and absent from the archive symbol table. Sources
   are copied into `OUT_DIR` and rewritten there, so the submodule stays
   pristine and `cargo clean` fully resets. The build **fails loudly** if any
   target function is not found, which is the upstream-drift detector.
2. **`-Wno-error=missing-prototypes`.** The reference sets `-Werror` with
   `-Wmissing-prototypes`; `barrett_reduce` is `static inline` with no separate
   prototype, so un-staticing it otherwise breaks the build. Scoped to that one
   diagnostic — every other warning stays fatal.
3. **Symbol prefixing.** All three variants are built from identical sources
   and would otherwise define `crypto_kem_enc` three times. Each is compiled
   with a generated `-include` header renaming every exported symbol to
   `hqc1_`/`hqc3_`/`hqc5_`. The symbol list is derived with `nm` from a probe
   build, **not** hand-written: a list taken from the Rust declarations misses
   `compute_generator_poly` and the global `shake256_prng_ctx`.

Environment overrides:

| Variables          | Values                                           |
|--------------------|--------------------------------------------------|
| `HQC_REF_SRC`      | Use a reference checkout outside `third_party/`. |
| `HQC_REF_ARCH`     | `ref` (default) or `x86_64`.                     |
| `HQC_REF_X86_IMPL` | `avx256`, when `HQC_REF_ARCH=x86_64`.            |

## Tests

```sh
cd rust-hqc
cargo test -j<NUM_THREADS>
cargo test -j<NUM_THREADS> --features ref-ffi
```

There is one feature, `ref-ffi`. It builds all three archives and links them
into a single test binary; there is no per-variant feature.

Useful subsets:

```sh
cargo test -j<NUM_THREADS> --features ref-ffi tests_variants   # the all-three-archive tests
cargo test -j<NUM_THREADS> --features ref-ffi gf2x             # one module
cargo test -j<NUM_THREADS> --features ref-ffi -- --nocapture   # see the cycle counts
```

### Coverage

Of the differential tests, only the **parameter-independent** ones (`gf_mul`,
`gf_square`, `gf_inverse`) currently run against all three C archives via
`RefImpl`. The rest are still pinned to `Ref1`; they predate runtime parameter
selection. Converting them is tracked as open work.

Three-variant coverage today comes from the **C-free** side: `kem::tests_kat`
runs 100 KAT vectors per parameter set, and `testvectors::intermediates` checks
every internal value against the reference's own traces. Those run on `main`
too.

## Pinning the Reference

The pin is **not** in `.gitmodules`; that file holds only `path`, `url` and
`branch`. It is the **gitlink**, a tree entry of mode 160000:

```sh
git ls-files -s rust-hqc/third_party/hqc-next-release
# 160000 <sha> 0    rust-hqc/third_party/hqc-next-release
```

To move it:

```sh
git -C rust-hqc/third_party/hqc-next-release fetch origin
git -C rust-hqc/third_party/hqc-next-release checkout <sha>
cd rust-hqc && cargo test --features ref-ffi && cd ..    # BEFORE committing
git add rust-hqc/third_party/hqc-next-release
git commit -m "build: pin HQC C reference to <sha-short>"
```

**Any `git add` on that path re-pins it** to whatever is checked out. A stray
`git add -A` after poking around inside the submodule silently moves the
reference your tests run against, and `git status` shows only a bare `M` with
no diff body. Watch for it.

## Workflow

### The rule

**All library changes are made on `main`.** This branch only ever adds test
infrastructure. It is rebased forward and never merged back.

```sh
git checkout ffi-testing
git rebase main
git submodule update --init --recursive
cd rust-hqc && cargo test --features ref-ffi
```

### When a differential test finds a library bug

This is the case that looks like it needs a merge back. It does not.

**Do not fix it here.** A library fix committed on `ffi-testing` is a
modification to a file `main` owns, which destroys the additive property and
turns every future rebase into a conflict.

Instead:

```sh
# 1. reproduce on main if you can -- a C-free test is better than a differential one
git checkout main
$EDITOR rust-hqc/src/<module>/mod.rs
cd rust-hqc && cargo test && cd ..
git commit -am "fix: ..."

# 2. rebase and confirm against the C reference
git checkout ffi-testing
git rebase main
cd rust-hqc && cargo test --features ref-ffi
```

If you have already committed the fix here by accident:

```sh
git checkout main
git cherry-pick <sha>                 # move it to main
git checkout ffi-testing
git rebase main                       # git drops the duplicate; if not, `git rebase --skip`
```

Then check the additive property is intact, this is the health check for the
whole scheme:

```sh
git diff --name-status main ffi-testing | grep -c '^M'   # must be 0
git diff --name-status main ffi-testing | grep -c '^A'   # 18
```

If the first number is not 0, a library change is stranded on this branch.
Move it to `main` before it accumulates.
