#!/usr/bin/env bash
# Build the netwatch-sdk eBPF programs and stage the artifact where the
# main crate's build.rs picks it up.
#
# Usage:
#   scripts/build-ebpf.sh           # release build (default)
#   scripts/build-ebpf.sh --debug   # opt-level=0, faster compile
#
# Prerequisites (one-time):
#   - rustup (the BPF crate uses a pinned nightly via rust-toolchain.toml)
#   - bpf-linker:   cargo install bpf-linker
#   - LLVM 18+ on PATH (bpf-linker links against it)
#
# Output:
#   target/bpf/netwatch_sdk_ebpf.o  ← consumed by build.rs at the SDK root

set -euo pipefail

cd "$(dirname "$0")/.."

PROFILE="release"
PROFILE_FLAG="--release"
if [[ "${1:-}" == "--debug" ]]; then
    PROFILE="debug"
    PROFILE_FLAG=""
fi

if ! command -v rustup >/dev/null 2>&1; then
    echo "error: rustup is required to build the BPF programs (the BPF crate" >&2
    echo "       uses a pinned nightly via rust-toolchain.toml)." >&2
    exit 1
fi

if ! command -v bpf-linker >/dev/null 2>&1; then
    echo "error: bpf-linker not found on PATH." >&2
    echo "       install with: cargo install bpf-linker" >&2
    exit 1
fi

echo "==> Building netwatch-sdk-ebpf-programs (profile=$PROFILE)"
(
    cd crates/ebpf-programs
    # rust-toolchain.toml in this directory pins the nightly + components.
    cargo build $PROFILE_FLAG
)

SRC="crates/ebpf-programs/target/bpfel-unknown-none/${PROFILE}/netwatch_sdk_ebpf"
DST_DIR="target/bpf"
DST="${DST_DIR}/netwatch_sdk_ebpf.o"

if [[ ! -f "$SRC" ]]; then
    echo "error: expected BPF artifact at $SRC but it doesn't exist." >&2
    echo "       check the cargo build output above." >&2
    exit 1
fi

mkdir -p "$DST_DIR"
cp "$SRC" "$DST"

echo "==> Staged $DST ($(stat -f%z "$DST" 2>/dev/null || stat -c%s "$DST") bytes)"
echo
echo "Now rebuild the main crate with:"
echo "    cargo build --features ebpf"
