//! Build script for netwatch-sdk.
//!
//! Three sources for the BPF object embedded into the userspace SDK via
//! `include_bytes!` in `src/ebpf/source.rs`, checked in priority order:
//!
//! 1. `target/bpf/netwatch_sdk_ebpf.o` — written by `scripts/build-ebpf.sh`
//!    from a local checkout. Preferred during SDK development so changes to
//!    the BPF crate are picked up immediately.
//! 2. `pre-built/netwatch_sdk_ebpf.o` — checked in to the SDK repo and
//!    shipped on crates.io so downstream `cargo install` consumers get
//!    working eBPF without needing the nightly + bpf-linker toolchain.
//!    Refreshed by `scripts/refresh-prebuilt.sh` (or hand: build on a Linux
//!    host with `scripts/build-ebpf.sh`, then copy from target/bpf/ to
//!    pre-built/).
//! 3. Empty file fallback — if neither exists (e.g. `ebpf` feature off, or
//!    something went wrong) the consumer's `EventSource::new` returns
//!    `BpfObjectMissing` cleanly rather than failing the build.
//!
//! This script does NOT invoke the BPF build itself. The BPF crate requires
//! a different toolchain (nightly + bpfel-unknown-none target); keeping it
//! as an explicit, scripted step means default `cargo build` on a stable
//! host works without any additional setup.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let target = out_dir.join("netwatch_sdk_ebpf.o");

    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set"));
    let local_build = manifest_dir.join("target/bpf/netwatch_sdk_ebpf.o");
    let prebuilt = manifest_dir.join("pre-built/netwatch_sdk_ebpf.o");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", local_build.display());
    println!("cargo:rerun-if-changed={}", prebuilt.display());

    let ebpf_feature = env::var("CARGO_FEATURE_EBPF").is_ok();

    let source = if !ebpf_feature {
        None
    } else if local_build.exists() && fs::metadata(&local_build).map(|m| m.len() > 0).unwrap_or(false) {
        Some(local_build.clone())
    } else if prebuilt.exists() && fs::metadata(&prebuilt).map(|m| m.len() > 0).unwrap_or(false) {
        Some(prebuilt.clone())
    } else {
        None
    };

    match source {
        Some(path) => {
            if let Err(e) = fs::copy(&path, &target) {
                eprintln!(
                    "warning: failed to copy {} → {}: {e}; writing empty placeholder",
                    path.display(),
                    target.display()
                );
                let _ = fs::write(&target, []);
            }
        }
        None => {
            // Either the feature is off, or no artifact is available.
            // Empty file lets `include_bytes!` compile; the consumer sees
            // `BpfObjectMissing` at runtime.
            let _ = fs::write(&target, []);
        }
    }
}
