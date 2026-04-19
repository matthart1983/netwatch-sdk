//! Shared event types for `netwatch-sdk` eBPF programs and userspace
//! consumers.
//!
//! Each event is `#[repr(C)]` and `Copy` so it can be written into a BPF
//! ring buffer from kernel space and reinterpreted from a `&[u8]` on the
//! userspace side without a serialization layer. Field layout MUST stay
//! stable across BPF and userspace builds; bump the workspace version
//! together when changing this file.
//!
//! `no_std` by default so the BPF crate (`#![no_std] #![no_main]`) can
//! depend on us without pulling in `std`. The `user` feature enables
//! `serde` derives for userspace consumers.

#![no_std]

#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};

/// 16 bytes of process command (matches `task_struct->comm` length).
pub const COMM_LEN: usize = 16;

/// One event type per kprobe/tracepoint we attach. Userspace iterates a
/// channel of these; BPF programs write the matching variant.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
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
/// during decode (see `EventDecoder` in the userspace crate).
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
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
