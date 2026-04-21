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
    match try_tcp_v4_connect(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_tcp_v4_connect(ctx: ProbeContext) -> Result<(), i64> {
    use aya_ebpf::helpers::bpf_probe_read_kernel;

    // Pull every field we need BEFORE reserving the ring-buffer entry.
    // Reserving creates a resource the BPF verifier insists we release
    // on every exit path (`submit` or `discard`). If we reserve up front
    // and then bail on a read failure, the verifier rejects the program
    // with "Unreleased reference … BPF_EXIT would lead to reference leak".
    let sk: *const u8 = ctx.arg(0).ok_or(1i64)?;

    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // struct sock_common (__sk_common) layout on a 5.15 reference kernel:
    //   skc_daddr      @ 0x00 (u32, network byte order)
    //   skc_rcv_saddr  @ 0x04 (u32, network byte order)
    //   skc_dport      @ 0x0C (u16, network byte order)
    //   skc_num        @ 0x0E (u16, host byte order — not what we want)
    //
    // These offsets will move to aya's CO-RE `bpf_core_read!` in a later
    // iteration; for the first landed kprobe we accept the kernel-version
    // sensitivity. sport lives on inet_sock, not sock_common, and needs
    // CO-RE to read cleanly — Phase 1 reports it as 0.
    //
    // SAFETY: aya-ebpf wraps these as bpf_probe_read_kernel calls.
    let daddr =
        unsafe { bpf_probe_read_kernel::<u32>(sk as *const u32).unwrap_or(0) };
    let saddr =
        unsafe { bpf_probe_read_kernel::<u32>(sk.add(4) as *const u32).unwrap_or(0) };
    let dport =
        unsafe { bpf_probe_read_kernel::<u16>(sk.add(0x0C) as *const u16).unwrap_or(0) };
    let sport: u16 = 0;

    // Now reserve. After this point there are no early returns: we either
    // submit or discard on every path, satisfying the verifier's
    // reference-accounting rules.
    let Some(mut entry) = EVENTS.reserve::<ConnectV4Event>(0) else {
        return Err(0);
    };

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

    // Commit. 0 flag = "wake up userspace if poll'd"; BPF_RB_NO_WAKEUP
    // would trade latency for throughput once we know the consumer pattern.
    entry.write(event);
    entry.submit(0);

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
