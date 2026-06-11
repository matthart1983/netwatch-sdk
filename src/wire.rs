//! Wire-format event types written by netwatch-sdk's BPF programs and
//! consumed by the userspace ring-buffer reader.
//!
//! Each event is `#[repr(C)]` and `Copy` so it can be written into a BPF
//! ring buffer from kernel space and reinterpreted from a `&[u8]` on the
//! userspace side without a serialization layer. **Field layout MUST stay
//! byte-for-byte identical to the BPF-side copy** in
//! `crates/ebpf-programs/src/wire.rs`. When changing this file, change
//! that file too and bump the SDK version.
//!
//! Previously these types lived in a sibling crate (`netwatch-sdk-common`)
//! shared between the SDK and the BPF crate. The SDK absorbed them so it
//! could be published to crates.io without an inter-crate dep that wasn't
//! itself published; the BPF crate keeps its own `no_std`-clean copy.
//!
//! Userspace consumers should generally use the decoded `EbpfEvent`
//! variants from `crate::ebpf::event`, not these raw types.

use serde::{Deserialize, Serialize};

/// 16 bytes of process command (matches `task_struct->comm` length).
pub const COMM_LEN: usize = 16;

/// One event type per kprobe/tracepoint we attach. Userspace iterates a
/// channel of these; BPF programs write the matching variant.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    /// `tcp_v4_connect` kprobe fired.
    TcpV4Connect = 1,
    /// `tcp_v6_connect` kprobe fired.
    TcpV6Connect = 2,
    /// `inet_csk_accept` kprobe fired.
    InetCskAccept = 3,
    /// `inet_sock_set_state` tracepoint, reporting close.
    SockClose = 4,
}

/// IPv4 connect event. Written by the `tcp_v4_connect` kprobe.
///
/// Address fields are network-byte-order `u32` / `u16` exactly as the
/// kernel stores them in `struct sock`. Userspace converts to host order
/// during decode (see `EventDecoder` in `crate::ebpf::event`).
#[repr(C)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct ConnectV4Event {
    /// `EventKind::TcpV4Connect` discriminant, written first so the
    /// userspace ring-buffer reader can dispatch on it before decoding the
    /// rest of the payload.
    pub kind: EventKind,
    /// 3 bytes of padding so the following `u32`s are naturally aligned.
    pub _pad0: [u8; 3],

    /// Process group id of the calling task.
    pub tgid: u32,
    /// Thread id (`task->pid`) of the calling task.
    pub pid: u32,
    /// Source IPv4 address, network byte order.
    pub saddr: u32,
    /// Destination IPv4 address, network byte order.
    pub daddr: u32,
    /// Source port, network byte order.
    pub sport: u16,
    /// Destination port, network byte order.
    pub dport: u16,
    /// `task_struct->comm`, NUL-padded.
    pub comm: [u8; COMM_LEN],
    /// Capture timestamp, kernel boot-time nanoseconds (`bpf_ktime_get_ns()`).
    pub timestamp_ns: u64,
}

impl ConnectV4Event {
    /// Construct a zero-initialised event with the kind tag set, ready for
    /// the BPF program to populate.
    #[inline]
    pub const fn empty() -> Self {
        Self {
            kind: EventKind::TcpV4Connect,
            _pad0: [0; 3],
            tgid: 0,
            pid: 0,
            saddr: 0,
            daddr: 0,
            sport: 0,
            dport: 0,
            comm: [0; COMM_LEN],
            timestamp_ns: 0,
        }
    }
}

/// IPv6 connect event. Written by the `tcp_v6_connect` kprobe (Phase 2).
///
/// Address fields are the 16 raw bytes of `struct in6_addr` in network
/// (IP-octet) order. Note a dual-stack socket connecting to an IPv4 peer
/// also goes through `tcp_v6_connect` with a v4-mapped destination
/// (`::ffff:a.b.c.d`); the decoder canonicalises those back to IPv4.
#[repr(C)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct ConnectV6Event {
    /// `EventKind::TcpV6Connect` discriminant, written first so the
    /// userspace ring-buffer reader can dispatch on it before decoding the
    /// rest of the payload.
    pub kind: EventKind,
    /// 3 bytes of padding so the following `u32`s are naturally aligned.
    pub _pad0: [u8; 3],

    /// Process group id of the calling task.
    pub tgid: u32,
    /// Thread id (`task->pid`) of the calling task.
    pub pid: u32,
    /// Source IPv6 address bytes. All-zero in Phase 2 — like the v4 path,
    /// the source isn't assigned at connect-entry where the kprobe fires.
    pub saddr: [u8; 16],
    /// Destination IPv6 address bytes (`sin6_addr` from the `uaddr` arg).
    pub daddr: [u8; 16],
    /// Source port, network byte order. 0 in Phase 2 (see `saddr`).
    pub sport: u16,
    /// Destination port, network byte order.
    pub dport: u16,
    /// `task_struct->comm`, NUL-padded.
    pub comm: [u8; COMM_LEN],
    /// Capture timestamp, kernel boot-time nanoseconds (`bpf_ktime_get_ns()`).
    pub timestamp_ns: u64,
}

impl ConnectV6Event {
    /// Construct a zero-initialised event with the kind tag set, ready for
    /// the BPF program to populate.
    #[inline]
    pub const fn empty() -> Self {
        Self {
            kind: EventKind::TcpV6Connect,
            _pad0: [0; 3],
            tgid: 0,
            pid: 0,
            saddr: [0; 16],
            daddr: [0; 16],
            sport: 0,
            dport: 0,
            comm: [0; COMM_LEN],
            timestamp_ns: 0,
        }
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;

    /// The BPF-side copy in `crates/common` and this file must stay
    /// byte-for-byte identical. Sizes are the cheapest tripwire: if a
    /// field is added/reordered on one side only, these fail.
    #[test]
    fn wire_struct_sizes_are_stable() {
        assert_eq!(core::mem::size_of::<ConnectV4Event>(), 48);
        assert_eq!(core::mem::size_of::<ConnectV6Event>(), 72);
    }

    /// `timestamp_ns` must land on an 8-byte boundary with no implicit
    /// padding before it; `read_unaligned` in the ring-buffer reader
    /// assumes the layouts match exactly.
    #[test]
    fn v6_field_offsets_match_bpf_side() {
        assert_eq!(core::mem::offset_of!(ConnectV6Event, tgid), 4);
        assert_eq!(core::mem::offset_of!(ConnectV6Event, saddr), 12);
        assert_eq!(core::mem::offset_of!(ConnectV6Event, daddr), 28);
        assert_eq!(core::mem::offset_of!(ConnectV6Event, sport), 44);
        assert_eq!(core::mem::offset_of!(ConnectV6Event, dport), 46);
        assert_eq!(core::mem::offset_of!(ConnectV6Event, comm), 48);
        assert_eq!(core::mem::offset_of!(ConnectV6Event, timestamp_ns), 64);
    }
}
