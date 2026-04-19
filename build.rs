//! Build script for netwatch-sdk.
//!
//! Two responsibilities:
//!
//! 1. Always write a (possibly empty) `netwatch_sdk_ebpf.o` into `OUT_DIR`
//!    so `include_bytes!` in `src/ebpf/source.rs` always has a target,
//!    even when the user hasn't built the BPF programs. The userspace
//!    code interprets an empty file as "BPF object missing" and surfaces
//!    a friendly error via [`EbpfError::BpfObjectMissing`].
//!
//! 2. When the `ebpf` Cargo feature is enabled AND a pre-built BPF object
//!    exists at `target/bpf/netwatch_sdk_ebpf.o` (the location populated
//!    by `scripts/build-ebpf.sh`), copy it into `OUT_DIR` so it gets
//!    embedded.
//!
//! This script does NOT invoke the BPF build itself. The BPF crate
//! requires a different toolchain (nightly + bpfel-unknown-none target);
//! we keep that as an explicit, scripted step so the default `cargo build`
//! on a stable host works without any additional setup.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let target = out_dir.join("netwatch_sdk_ebpf.o");

    // Where the BPF artifact lands once `scripts/build-ebpf.sh` runs.
    // CARGO_MANIFEST_DIR is the netwatch-sdk crate root.
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set"));
    let prebuilt = manifest_dir.join("target/bpf/netwatch_sdk_ebpf.o");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", prebuilt.display());

    let ebpf_feature = env::var("CARGO_FEATURE_EBPF").is_ok();

    if ebpf_feature && prebuilt.exists() {
        // Copy the prebuilt object so include_bytes! picks it up.
        if let Err(e) = fs::copy(&prebuilt, &target) {
            // Don't fail the build — fall through to writing an empty
            // file so the consumer sees BpfObjectMissing instead of a
            // build error.
            eprintln!(
                "warning: failed to copy {} → {}: {e}; writing empty placeholder",
                prebuilt.display(),
                target.display()
            );
            let _ = fs::write(&target, []);
        }
    } else {
        // No BPF artifact (feature off, or scripts/build-ebpf.sh not run).
        // Write an empty file so include_bytes! still compiles.
        let _ = fs::write(&target, []);
    }
}
