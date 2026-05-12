#!/usr/bin/env bash
# Refresh the checked-in pre-built BPF object that ships with the
# netwatch-sdk crates.io package.
#
# Why this exists: the BPF crate needs nightly Rust + bpf-linker + LLVM 18,
# which `cargo install` consumers don't generally have. By committing the
# compiled artifact at `pre-built/netwatch_sdk_ebpf.o` and shipping it in
# the crate, downstream consumers (e.g. `cargo install netwatch-tui`) get
# working eBPF without any extra toolchain on their side.
#
# Refresh whenever crates/ebpf-programs/src/main.rs changes. Run on a Linux
# host with the BPF toolchain. Verifies the result is non-empty and an
# eBPF ELF before staging it.

set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v bpf-linker >/dev/null; then
    echo "error: bpf-linker not on PATH (cargo install bpf-linker --locked)" >&2
    exit 1
fi

bash scripts/build-ebpf.sh

src="target/bpf/netwatch_sdk_ebpf.o"
dst="pre-built/netwatch_sdk_ebpf.o"

[ -s "$src" ] || { echo "error: $src missing or empty"; exit 1; }
file "$src" | grep -q "eBPF" || { echo "error: $src is not eBPF"; exit 1; }

mkdir -p pre-built
cp -f "$src" "$dst"
echo "==> staged $dst ($(stat -c %s "$dst" 2>/dev/null || stat -f %z "$dst") bytes)"
echo
echo "Commit the new pre-built/netwatch_sdk_ebpf.o and bump the SDK version."
