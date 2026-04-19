//! netwatch-sdk eBPF programs.
//!
//! Phase 1 ships a single program: a kprobe on `tcp_v4_connect` that emits
//! a `ConnectV4Event` into a ring buffer for userspace consumption.
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
use netwatch_sdk_common::{ConnectV4Event, EventKind, COMM_LEN};

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
    match try_tcp_v4_connect(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_tcp_v4_connect(ctx: ProbeContext) -> Result<(), i64> {
    // Reserve space in the ring buffer for one event.
    let mut entry = EVENTS.reserve::<ConnectV4Event>(0).ok_or(0i64)?;

    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;

    let comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // Pull the `struct sock *` first arg.
    //
    // Layout-wise, what we want is on the kernel struct `inet_sock`:
    //   - inet->inet_saddr  (network byte order u32)
    //   - inet->inet_daddr  (network byte order u32, populated from uaddr
    //     before tcp_v4_connect proper, depending on kernel version)
    //   - inet->inet_sport  (network byte order u16)
    //   - inet->inet_dport  (network byte order u16)
    //
    // For simplicity in this first program we read what we know is
    // available from `struct sock` (sk_rcv_saddr / sk_daddr / sk_num /
    // sk_dport via the embedded `__sk_common`). The destination address
    // and port are populated by the caller before tcp_v4_connect is
    // invoked, so we can read them here.
    let sk: *const u8 = ctx.arg(0).ok_or(1i64)?;

    // Offsets into struct sock.__sk_common on a CO-RE-tracked 5.10+ kernel.
    // These are obtained from BTF when CO-RE relocations land; for the
    // initial implementation we rely on the BTF-based bpf_core_read which
    // aya provides. To keep this file simple we use raw offsets that match
    // a 5.15 reference kernel layout — they will be replaced with CO-RE
    // reads in the next iteration.
    //
    // SAFETY: aya-ebpf wraps these in bpf_probe_read_kernel under the
    // hood. The offsets are kernel-version-sensitive (TODO: switch to
    // CO-RE).
    use aya_ebpf::helpers::bpf_probe_read_kernel;

    // struct sock_common __sk_common layout (kernel 5.15):
    //   skc_daddr        @ 0x00 (u32, BE)
    //   skc_rcv_saddr    @ 0x04 (u32, BE)
    //   skc_dport        @ 0x0C (u16, BE)
    //   skc_num          @ 0x0E (u16, host order — NOT what we want for sport)
    //
    // For the source port in network byte order we read inet_sock->inet_sport
    // which sits at a different offset. As a placeholder until CO-RE lands,
    // we report sport = 0 and document the limitation.
    let daddr = unsafe { bpf_probe_read_kernel::<u32>(sk as *const u32).unwrap_or(0) };
    let saddr =
        unsafe { bpf_probe_read_kernel::<u32>(sk.add(4) as *const u32).unwrap_or(0) };
    let dport =
        unsafe { bpf_probe_read_kernel::<u16>(sk.add(0x0C) as *const u16).unwrap_or(0) };
    let sport: u16 = 0; // TODO: CO-RE-relocated read of inet_sport

    let event = ConnectV4Event {
        kind: EventKind::TcpV4Connect,
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

    // Commit the entry into the ring buffer. The 0 flag means "wake up
    // userspace if poll'd"; pass BPF_RB_NO_WAKEUP to trade latency for
    // throughput once we know the consumer pattern.
    entry.write(event);
    entry.submit(0);

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
