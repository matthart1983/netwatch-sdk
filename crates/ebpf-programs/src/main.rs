//! netwatch-sdk eBPF programs.
//!
//! Phase 1 shipped a kprobe on `tcp_v4_connect` emitting `ConnectV4Event`s
//! into a ring buffer. Phase 2 adds the IPv6 twin: a kprobe on
//! `tcp_v6_connect` emitting `ConnectV6Event`s into the same ring buffer.
//!
//! Build with the nightly toolchain pinned in `rust-toolchain.toml`:
//!
//! ```sh
//! scripts/build-ebpf.sh
//! ```
//!
//! The compiled object lands in `crates/ebpf-programs/target/bpfel-unknown-none/release/netwatch_sdk_ebpf`
//! and is copied into `target/bpf/netwatch_sdk_ebpf.o` so the userspace
//! crate can `include_bytes!` it.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{kprobe, map},
    maps::RingBuf,
    programs::ProbeContext,
};
use netwatch_sdk_common::{ConnectV4Event, ConnectV6Event, EventKind, COMM_LEN};

/// BPF programs that call GPL-only kernel helpers (bpf_probe_read_kernel,
/// bpf_ktime_get_ns, etc.) must declare a GPL-compatible license. The
/// kernel reads this from the `license` ELF section at program load; aya
/// also checks for it before attach. Missing it causes the load to fail
/// with a misleading "Invalid ELF header" error.
#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";

/// 256 KiB ring buffer. Sized to absorb burst rates of ~5k connect/sec
/// without dropping if userspace stalls for a few hundred ms. Tunable
/// once we have real workload data.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// `int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)`
///
/// Reads the calling task's pid/tgid/comm and the socket's
/// (saddr, daddr, sport, dport). All address fields stay in network byte
/// order — userspace converts on decode.
#[kprobe]
pub fn tcp_v4_connect(ctx: ProbeContext) -> u32 {
    match try_v4_connect(ctx, EventKind::TcpV4Connect) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

/// `int ip4_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)`
///
/// Connected-UDP twin of `tcp_v4_connect`: a process `connect()`ing a UDP
/// socket (the QUIC client pattern) routes through here. Same signature,
/// and the syscall layer has already copied `uaddr` into kernel memory, so
/// the destination read is identical — only the emitted `EventKind` differs.
#[kprobe]
pub fn ip4_datagram_connect(ctx: ProbeContext) -> u32 {
    match try_v4_connect(ctx, EventKind::UdpV4Connect) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

/// Inner worker `__ip4_datagram_connect(sk, uaddr, addr_len)`. Some kernel
/// builds set `udp_prot.connect` to the inner (or inline the wrapper), so
/// the outer `ip4_datagram_connect` kprobe never fires; others inline the
/// inner and only the outer exists. We attach both best-effort — same
/// signature, same `(proto, daddr, dport)` key, so a double-fire just
/// overwrites idempotently and a missing symbol is skipped.
#[kprobe]
pub fn __ip4_datagram_connect(ctx: ProbeContext) -> u32 {
    match try_v4_connect(ctx, EventKind::UdpV4Connect) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_v4_connect(ctx: ProbeContext, kind: EventKind) -> Result<(), i64> {
    use aya_ebpf::helpers::bpf_probe_read_kernel;

    // Pull every field we need BEFORE reserving the ring-buffer entry.
    // Reserving creates a resource the BPF verifier insists we release
    // on every exit path (`submit` or `discard`). If we reserve up front
    // and then bail on a read failure, the verifier rejects the program
    // with "Unreleased reference … BPF_EXIT would lead to reference leak".
    // `uaddr` (arg 1) is the destination `struct sockaddr_in *`. The syscall
    // layer copies the user-supplied address into kernel memory before
    // tcp_v4_connect runs, so bpf_probe_read_kernel is correct here.
    //
    // Crucially the destination is valid at function ENTRY. The socket's own
    // sock_common fields (skc_daddr @0x00, skc_rcv_saddr @0x04, skc_dport
    // @0x0C) are NOT — the kernel only populates them later inside
    // tcp_v4_connect. The previous version read them at entry and got all
    // zeros, so every event was discarded downstream and eBPF attribution
    // never worked (issue #38). Read the destination from uaddr instead.
    let uaddr: *const u8 = ctx.arg(1).ok_or(1i64)?;

    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // struct sockaddr_in { sin_family @0x00 (u16); sin_port @0x02 (u16, net
    // order); sin_addr @0x04 (u32, net order); ... }. Addresses stay in
    // network byte order — userspace converts on decode. The source address
    // isn't assigned until routing later in connect(), so it's reported as 0
    // and userspace keys attribution on (daddr, dport).
    //
    // SAFETY: aya-ebpf wraps these as bpf_probe_read_kernel calls.
    let dport =
        unsafe { bpf_probe_read_kernel::<u16>(uaddr.add(0x02) as *const u16).unwrap_or(0) };
    let daddr =
        unsafe { bpf_probe_read_kernel::<u32>(uaddr.add(0x04) as *const u32).unwrap_or(0) };
    let saddr: u32 = 0;
    let sport: u16 = 0;

    // Now reserve. After this point there are no early returns: we either
    // submit or discard on every path, satisfying the verifier's
    // reference-accounting rules.
    let Some(mut entry) = EVENTS.reserve::<ConnectV4Event>(0) else {
        return Err(0);
    };

    let event = ConnectV4Event {
        kind,
        _pad0: [0; 3],
        tgid,
        pid,
        saddr,
        daddr,
        sport,
        dport,
        comm,
        timestamp_ns,
    };

    // Commit. 0 flag = "wake up userspace if poll'd"; BPF_RB_NO_WAKEUP
    // would trade latency for throughput once we know the consumer pattern.
    entry.write(event);
    entry.submit(0);

    Ok(())
}

/// `int tcp_v6_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)`
///
/// IPv6 twin of `tcp_v4_connect` above; same shape, same caveats. Note
/// that dual-stack sockets connecting to IPv4 peers also come through
/// here with a v4-mapped destination (`::ffff:a.b.c.d`) — userspace
/// canonicalises those back to IPv4 on decode, so v4 traffic over
/// AF_INET6 sockets is attributed too.
#[kprobe]
pub fn tcp_v6_connect(ctx: ProbeContext) -> u32 {
    match try_v6_connect(ctx, EventKind::TcpV6Connect) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

/// `int ip6_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)`
///
/// Connected-UDP twin of `tcp_v6_connect` (QUIC over IPv6). Same signature
/// and the same kernel-copied `uaddr`, so the destination read matches —
/// only the emitted `EventKind` differs.
#[kprobe]
pub fn ip6_datagram_connect(ctx: ProbeContext) -> u32 {
    match try_v6_connect(ctx, EventKind::UdpV6Connect) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

/// Inner worker `__ip6_datagram_connect(sk, uaddr, addr_len)` — IPv6 twin of
/// `__ip4_datagram_connect`. On the test kernel (6.17) this is the symbol
/// actually on the UDP connect path; the outer `ip6_datagram_connect` is
/// never entered. Attached best-effort alongside the wrapper.
#[kprobe]
pub fn __ip6_datagram_connect(ctx: ProbeContext) -> u32 {
    match try_v6_connect(ctx, EventKind::UdpV6Connect) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_v6_connect(ctx: ProbeContext, kind: EventKind) -> Result<(), i64> {
    use aya_ebpf::helpers::bpf_probe_read_kernel;

    // Same ordering discipline as the v4 probe: read everything BEFORE
    // reserving the ring-buffer entry so every exit path satisfies the
    // verifier's reference accounting.
    //
    // `uaddr` (arg 1) is the destination `struct sockaddr_in6 *`, already
    // copied into kernel memory by the syscall layer and valid at function
    // ENTRY — unlike the socket's own sock_common fields, which the kernel
    // only populates later inside tcp_v6_connect (same trap as issue #38
    // on the v4 side).
    let uaddr: *const u8 = ctx.arg(1).ok_or(1i64)?;

    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // struct sockaddr_in6 { sin6_family @0x00 (u16); sin6_port @0x02 (u16,
    // net order); sin6_flowinfo @0x04 (u32); sin6_addr @0x08 ([u8; 16]);
    // sin6_scope_id @0x18 (u32) }. Address bytes are already in IP-octet
    // order — userspace consumes them as-is. The source address isn't
    // assigned until routing later in connect(), so it's reported as zero
    // and userspace keys attribution on (daddr, dport).
    //
    // SAFETY: aya-ebpf wraps these as bpf_probe_read_kernel calls.
    let dport =
        unsafe { bpf_probe_read_kernel::<u16>(uaddr.add(0x02) as *const u16).unwrap_or(0) };
    let daddr = unsafe {
        bpf_probe_read_kernel::<[u8; 16]>(uaddr.add(0x08) as *const [u8; 16]).unwrap_or([0; 16])
    };
    let saddr = [0u8; 16];
    let sport: u16 = 0;

    // Now reserve. No early returns past this point: we either submit or
    // discard on every path, satisfying the verifier's reference-accounting
    // rules.
    let Some(mut entry) = EVENTS.reserve::<ConnectV6Event>(0) else {
        return Err(0);
    };

    let event = ConnectV6Event {
        kind,
        _pad0: [0; 3],
        tgid,
        pid,
        saddr,
        daddr,
        sport,
        dport,
        comm,
        timestamp_ns,
    };

    entry.write(event);
    entry.submit(0);

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
