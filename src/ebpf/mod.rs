//! eBPF event source.
//!
//! This module is the userspace half of the netwatch-sdk eBPF integration.
//! It loads the BPF object compiled from `crates/ebpf-programs`, attaches
//! the kprobes, and surfaces a channel of decoded events.
//!
//! Status: Phase 1 of the [eBPF roadmap](../../docs/plans/ebpf.md). Today
//! this provides the public API surface and the userspace ring-buffer
//! reader for `tcp_v4_connect`. The kprobe itself is committed in
//! `crates/ebpf-programs/src/main.rs` and is built via
//! `scripts/build-ebpf.sh`.
//!
//! # Availability
//!
//! - **Linux only.** On other targets, the `ebpf` Cargo feature still
//!   compiles (so cross-platform builds don't break) but
//!   [`EventSource::new`] returns `Err(EbpfError::UnsupportedPlatform)`.
//! - **Kernel ≥ 5.10.** Older kernels lack reliable BTF and `CAP_BPF`.
//! - Requires `CAP_BPF` + `CAP_PERFMON` (or root). The agent crate gates
//!   the call site on the running uid; `EventSource::new` itself returns
//!   a clear error rather than panicking when permissions are missing.

mod event;
mod source;

pub use event::{ConnectEvent, EbpfEvent};
pub use source::{EbpfError, EventSource};
