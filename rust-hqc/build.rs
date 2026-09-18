//! Build script.
//!
//! Without the `ref-ffi` feature this does nothing, so the crate builds and
//! tests with no C toolchain, no CMake, and no C sources present. With
//! `ref-ffi` on, it builds the HQC C reference for differential testing using
//! the reference project's own CMake build.
//!
//! # Source discovery
//!
//! 1. `$HQC_REF_SRC`: a checkout of `hqc-next-release`.
//! 2. `third_party/hqc-next-release`: vendored copy or git submodule.
//!
//! # Why the tree is copied into OUT_DIR first
//!
//! Multiple functions the differential tests target are `static` in the C
//! sources and so absent from the library symbol table. The reference's own
//! unit tests do not link them; `tests/unit/test_vector.c` re-implements
//! `barrett_reduce` locally instead. Giving them external linkage means
//! editing the sources, which must not happen inside a git submodule: it would
//! dirty `git status` and make the build unreproducible. So the tree is staged
//! into `OUT_DIR` and rewritten there, and `cargo clean` fully resets it.
//!
//! # Why `-Wno-error=missing-prototypes`
//!
//! The reference sets `-Wall -Werror -Wextra -Wmissing-prototypes -Wpedantic
//! -Wredundant-decls` unconditionally. `barrett_reduce` is `static inline`
//! with no separate prototype, so once un-staticed it trips
//! `-Werror=missing-prototypes` and the build fails. The suppression is scoped
//! to that one diagnostic; every other warning stays fatal.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Functions that are `static` in the C sources and must be given external
/// linkage for the differential tests to link.
const UNSTATIC: &[&str] = &[
    "barrett_reduce",       // src/ref/vector.c
    "compute_elp",          // src/ref/reed_solomon.c
    "compute_error_values", // src/ref/reed_solomon.c
    "compute_fft_betas",    // src/common/fft.c
    "compute_roots",        // src/ref/reed_solomon.c
    "compute_subset_sums",  // src/common/fft.c
    "compute_syndromes",    // src/ref/reed_solomon.c
    "compute_z_poly",       // src/ref/reed_solomon.c
    "correct_errors",       // src/ref/reed_solomon.c
    "gf_reduce",            // src/ref/gf.c
    "radix",                // src/common/fft.c
    "radix_big",            // src/common/fft.c
];

const VARIANTS: &[&str] = &["hqc-1", "hqc-3", "hqc-5"];

/// Directories whose `*.c` files carry `static` definitions worth rewriting.
/// The CMake build decides what to compile; this list only bounds the rewrite.
const REWRITE_DIRS: &[&str] = &["src/common", "src/ref", "src/x86_64"];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    for v in ["HQC_REF_SRC", "HQC_REF_ARCH", "HQC_REF_X86_IMPL"] {
        println!("cargo:rerun-if-env-changed={v}");
    }

    if std::env::var_os("CARGO_FEATURE_REF_FFI").is_none() {
        return;
    }

    let src = locate_reference();
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // Watching the directories (not just the files) also catches a source
    // file being *added* upstream, which a per-file list cannot.
    for d in ["src", "lib", "CMakeLists.txt"] {
        println!("cargo:rerun-if-changed={}", src.join(d).display());
    }

    let arch = std::env::var("HQC_REF_ARCH").unwrap_or_else(|_| "ref".into());
    assert!(
        arch == "ref" || arch == "x86_64",
        "HQC_REF_ARCH must be `ref` or `x86_64`, got `{arch}`"
    );

    // Staged, rewritten copy. Never the vendored tree.
    let work = out.join("hqc-src");
    stage_tree(&src, &work);
    unstatic(&work);

    // All three variants are always built, each with its own symbol prefix.
    //
    // A single unprefixed variant is deliberately NOT offered. The C reference
    // bakes its parameter set into `parameters.h`, so the three archives export
    // identical symbol names; linking two does not reliably error — the linker
    // resolves from the first and skips the rest, silently testing the wrong
    // parameter set. Prefixing every build removes that failure mode, and means
    // `src/ffi` has one set of `#[link_name]` attributes rather than two
    // configurations that can drift.
    //
    // Per-variant prefixes cannot share one CMake tree: `src/CMakeLists.txt`
    // exposes no per-target compile-options hook, only
    // `target_include_directories`, and `CMAKE_C_FLAGS` is global. So each
    // prefix gets its own configure and build directory.
    let symbols = probe_symbols(&work, &out, &arch);
    for (i, variant) in VARIANTS.iter().enumerate() {
        let prefix = format!("hqc{}_", variant.trim_start_matches("hqc-"));
        let header = write_prefix_header(&out, &prefix, &symbols);
        let build = out.join(format!("build-{variant}"));
        cmake_build(
            &work,
            &build,
            &arch,
            &[variant],
            Some(&format!("-include{}", header.display())),
        );
        // fips202 only on the last one: it is emitted after every HQC archive
        // because cargo passes -l flags in emission order and static archive
        // resolution is order-dependent.
        emit_links(&build, &[variant], i + 1 == VARIANTS.len());
    }
}

/// Finds the reference checkout, or explains how to provide one.
fn locate_reference() -> PathBuf {
    let candidate = std::env::var("HQC_REF_SRC")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
                .join("third_party/hqc-next-release")
        });

    if candidate.join("CMakeLists.txt").is_file() && candidate.join("src/ref").is_dir() {
        return candidate;
    }

    panic!(
        "\n\
         feature `ref-ffi` is enabled but the HQC C reference was not found.\n\
         \n\
         Looked in: {}\n\
         \n\
         Provide it with either:\n  \
           HQC_REF_SRC=/path/to/hqc-next-release\n  \
           git submodule add <url> third_party/hqc-next-release\n\
         \n\
         Building it also requires cmake >= 3.21 and a C compiler.\n\
         Or drop `--features ref-ffi`: the crate builds and tests without it.\n",
        candidate.display()
    );
}

/// Copies the reference into `work`, skipping only VCS metadata.
///
/// The whole project is staged, not just the translation units that get
/// compiled. CMake configures every `add_subdirectory` regardless of which
/// targets are later built, and `tests/kats/CMakeLists.txt` fails outright on
/// an empty glob if the KAT corpus is pruned. This is a cost of driving the
/// reference through its own build system rather than compiling the sources
/// directly: roughly 25 MB is copied per `cargo clean`, of which about 13
/// files are actually needed.
fn stage_tree(src: &Path, work: &Path) {
    let _ = std::fs::remove_dir_all(work);
    copy_dir(src, work, &|rel| !rel.to_string_lossy().starts_with(".git"));
}

fn copy_dir(from: &Path, to: &Path, keep: &dyn Fn(&Path) -> bool) {
    fn walk(from: &Path, to: &Path, root: &Path, keep: &dyn Fn(&Path) -> bool) {
        let Ok(entries) = std::fs::read_dir(from) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            let rel = p.strip_prefix(root).unwrap();
            if !keep(rel) {
                continue;
            }
            let dst = to.join(rel);
            if p.is_dir() {
                std::fs::create_dir_all(&dst).unwrap();
                walk(&p, to, root, keep);
            } else {
                std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
                std::fs::copy(&p, &dst)
                    .unwrap_or_else(|e| panic!("staging {}: {e}", rel.display()));
            }
        }
    }
    std::fs::create_dir_all(to).unwrap();
    walk(from, to, from, keep);
}

/// Gives external linkage to the functions in [`UNSTATIC`].
///
/// Rewrites `static <type> name(` and `static inline <type> name(` at the start
/// of a line, covering both prototype and definition. `inline` is dropped along
/// with `static`: a C99 `inline` definition with no external definition would
/// not be emitted, so keeping it would not fix the link.
fn unstatic(work: &Path) {
    let mut counts = vec![0usize; UNSTATIC.len()];
    let mut files = Vec::new();
    for d in REWRITE_DIRS {
        collect_c(&work.join(d), &mut files);
    }

    for path in files {
        let text = std::fs::read_to_string(&path).unwrap();
        let mut out = String::with_capacity(text.len());
        let mut changed = false;

        for line in text.lines() {
            let mut line = line.to_string();
            let trimmed = line.trim_start();

            if let Some(rest) = trimmed.strip_prefix("static ") {
                let rest = rest.trim_start().strip_prefix("inline ").unwrap_or(rest);
                if let Some(open) = rest.find('(') {
                    let name = rest[..open]
                        .rsplit(|c: char| !(c.is_alphanumeric() || c == '_'))
                        .next()
                        .unwrap_or("");
                    if let Some(i) = UNSTATIC.iter().position(|t| *t == name) {
                        let indent = &line[..line.len() - trimmed.len()];
                        line = format!("{indent}{}", rest.trim_start());
                        counts[i] += 1;
                        changed = true;
                    }
                }
            }
            out.push_str(&line);
            out.push('\n');
        }

        if changed {
            std::fs::write(&path, out).unwrap();
        }
    }

    // Upstream drift detector: if a future release renames or un-statics one of
    // these, fail here rather than at link time inside a test.
    let missing: Vec<&str> = UNSTATIC
        .iter()
        .zip(&counts)
        .filter(|(_, n)| **n == 0)
        .map(|(t, _)| *t)
        .collect();
    assert!(
        missing.is_empty(),
        "no `static` definition found for {missing:?} in the reference sources.\n\
         The reference may have changed; update UNSTATIC in build.rs."
    );
}

fn collect_c(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_c(&p, out);
        } else if p.extension().is_some_and(|x| x == "c") {
            out.push(p);
        }
    }
}

/// Configures and builds the reference with its own CMake.
///
/// Only the requested library targets are built. The default target would also
/// build munit and every unit/api/kat/bench executable, which roughly triples
/// the time for artifacts nothing here links against.
fn cmake_build(
    work: &Path,
    build: &Path,
    arch: &str,
    variants: &[&str],
    extra_cflags: Option<&str>,
) {
    let mut cflags = String::from("-Wno-error=missing-prototypes");
    if let Some(extra) = extra_cflags {
        cflags.push(' ');
        cflags.push_str(extra);
    }

    let mut cfg = Command::new("cmake");
    cfg.arg("-S")
        .arg(work)
        .arg("-B")
        .arg(build)
        .arg(format!("-DHQC_ARCH={arch}"))
        // Release, not the cargo profile: this is a test dependency and the
        // reference's own CMakeLists drops to -O0 under Debug, which makes the
        // differential tests several times slower for no benefit.
        .arg("-DCMAKE_BUILD_TYPE=Release")
        .arg(format!("-DCMAKE_C_FLAGS={cflags}"));

    if arch == "x86_64" {
        let impl_ = std::env::var("HQC_REF_X86_IMPL").unwrap_or_else(|_| "avx256".into());
        cfg.arg(format!("-DHQC_X86_IMPL={impl_}"));
    }
    if let Ok(cc) = std::env::var("CC") {
        cfg.arg(format!("-DCMAKE_C_COMPILER={cc}"));
    }

    run(cfg, "cmake configure");

    let mut b = Command::new("cmake");
    b.arg("--build").arg(build).arg("--parallel");
    b.arg("--target").arg("fips202");
    for v in variants {
        b.arg(format!("{}_{arch}", v.replace('-', "_")));
    }
    run(b, "cmake build");
}

/// Emits the link directives for the archives CMake produced.
///
/// Order matters: `cargo` passes `-l` flags in emission order and static
/// archive resolution is order-dependent, so fips202 must come *after* every
/// HQC archive that references it. Emitting it first leaves every `shake256_*`
/// symbol undefined at link time.
fn emit_links(build: &Path, variants: &[&str], emit_fips202: bool) {
    let arch = std::env::var("HQC_REF_ARCH").unwrap_or_else(|_| "ref".into());
    println!(
        "cargo:rustc-link-search=native={}",
        build.join("src").display()
    );
    for v in variants {
        let lib = format!("{}_{arch}", v.replace('-', "_"));
        let path = build.join("src").join(format!("lib{lib}.a"));
        assert!(path.is_file(), "cmake did not produce {}", path.display());
        println!("cargo:rustc-link-lib=static={lib}");
    }
    if emit_fips202 {
        println!(
            "cargo:rustc-link-search=native={}",
            build.join("lib").display()
        );
        println!("cargo:rustc-link-lib=static=fips202");
    }
}

/// Builds one variant unprefixed in a scratch tree and reads back the symbols
/// it defines, which is exactly the set that must be renamed.
///
/// Derived rather than hand-listed on purpose: a list written from the Rust
/// `extern` declarations misses `compute_generator_poly` (a function no test
/// calls) and `shake256_prng_ctx` (a global variable, not a function), both of
/// which collide at link time.
fn probe_symbols(work: &Path, out: &Path, arch: &str) -> BTreeSet<String> {
    let build = out.join("build-probe");
    cmake_build(work, &build, arch, &["hqc-1"], None);

    let lib = build.join("src").join(format!("libhqc_1_{arch}.a"));
    let nm = Command::new("nm")
        .arg("--defined-only")
        .arg(&lib)
        .output()
        .expect("`nm` is required for multi-variant builds; it ships with binutils");
    assert!(nm.status.success(), "nm failed on {}", lib.display());

    let syms: BTreeSet<String> = String::from_utf8_lossy(&nm.stdout)
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let (kind, name) = match (it.next(), it.next(), it.next()) {
                (Some(_addr), Some(k), Some(n)) => (k, n),
                (Some(k), Some(n), None) => (k, n),
                _ => return None,
            };
            matches!(kind, "T" | "D" | "B" | "R" | "G" | "S").then(|| name.to_string())
        })
        .collect();

    assert!(
        syms.contains("crypto_kem_enc") && syms.contains("shake256_prng_ctx"),
        "symbol probe looks wrong: got {} symbols",
        syms.len()
    );
    syms
}

/// Writes `#define <sym> <prefix><sym>` for every symbol in the set.
fn write_prefix_header(out: &Path, prefix: &str, symbols: &BTreeSet<String>) -> PathBuf {
    let path = out.join(format!("prefix_{}h", prefix));
    let mut s = String::from("#pragma once\n");
    for sym in symbols {
        s.push_str(&format!("#define {sym} {prefix}{sym}\n"));
    }
    std::fs::write(&path, s).unwrap();
    path
}

fn run(mut cmd: Command, what: &str) {
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("{what}: failed to spawn ({e}). Is cmake >= 3.21 installed?"));
    assert!(status.success(), "{what} failed: {cmd:?}");
}
