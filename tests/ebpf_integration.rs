//! Integration test that actually attaches the `tcp_v4_connect` kprobe
//! in the host kernel and asserts an event round-trips to userspace.
//!
//! Runs only on Linux, only with the `ebpf` feature, and only when the
//! process has the capabilities needed to load a BPF program (CAP_BPF +
//! CAP_PERFMON, which practically means running as root). The CI
//! `ebpf-integration` job satisfies this by re-running the built test
//! binary under `sudo`.
//!
//! If the prerequisites aren't met, the test prints a skip message and
//! returns success — we never want this test to fail when the harness
//! can't satisfy the setup, only when the behaviour is wrong.

#![cfg(all(target_os = "linux", feature = "ebpf"))]

use netwatch_sdk::ebpf::{EbpfError, EbpfEvent, EventSource};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

#[test]
fn tcp_v4_connect_kprobe_round_trip() {
    let (source, rx) = match EventSource::new() {
        Ok(pair) => pair,
        Err(EbpfError::BpfObjectMissing) => {
            eprintln!(
                "BPF object not embedded — run scripts/build-ebpf.sh before \
                 building the test binary. Skipping."
            );
            return;
        }
        Err(EbpfError::UnsupportedPlatform) => {
            eprintln!("eBPF is Linux-only; skipping on this platform.");
            return;
        }
        Err(e) => {
            // This path fires on genuine kernel-side failures: verifier
            // rejection, missing CAP_BPF, malformed BPF object. Fail hard
            // with the reason so CI logs capture the real cause.
            panic!("EventSource::new failed: {e:?}");
        }
    };

    // Bind a TCP listener on an ephemeral loopback port. The kprobe fires
    // on the client's `tcp_v4_connect` kcall, so we just need *somewhere*
    // to connect to. We never call accept — the connect syscall still
    // reaches tcp_v4_connect in the kernel before any accept races, and
    // leaving the listener socket alone removes the previous harness's
    // classic deadlock chain (server thread blocks on stream.read, which
    // blocks on client close, which blocks on end-of-scope drop).
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let port = listener.local_addr().unwrap().port();

    // Small delay so the kprobe attach completes before the connect fires.
    std::thread::sleep(Duration::from_millis(50));

    let conn = TcpStream::connect(("127.0.0.1", port)).expect("connect to listener");

    // Drain events for up to 2 seconds looking for our connect.
    //
    // Match on *pid* rather than dport. pid comes from
    // bpf_get_current_pid_tgid(), which is version-stable across kernels.
    // The dport/daddr fields in Phase 1 are read at hard-coded offsets
    // into struct sock and WILL be wrong on kernels whose layout differs
    // from the 5.15 reference — that's a known limitation until the
    // CO-RE follow-up lands (see docs/plans/ebpf.md).
    let our_pid = std::process::id();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut observed = false;
    let mut seen: Vec<(u32, u32, String)> = Vec::new();
    while Instant::now() < deadline {
        if let Ok(EbpfEvent::Connect(c)) = rx.recv_timeout(Duration::from_millis(100)) {
            seen.push((c.pid, c.tgid, c.comm.clone()));
            // Match on either pid or tgid — BPF's pid_tgid split is
            // (tgid << 32) | pid, and the userspace side reports them
            // symmetrically. std::process::id() returns the tgid.
            if c.pid == our_pid || c.tgid == our_pid {
                observed = true;
                eprintln!(
                    "observed our connect: pid={} tgid={} comm={:?} dport={} (dport may be 0 pre-CO-RE)",
                    c.pid, c.tgid, c.comm, c.dport
                );
                break;
            }
        }
    }
    eprintln!("diagnostic: looking for pid/tgid={our_pid}");
    eprintln!("diagnostic: saw {} connect events total:", seen.len());
    for (pid, tgid, comm) in &seen {
        eprintln!("  pid={pid} tgid={tgid} comm={comm:?}");
    }

    // Close the connection and tear down the BPF source before asserting.
    // Ordering matters so the reader thread has nothing left to process
    // and EventSource::Drop doesn't race with `conn`'s close.
    drop(conn);
    drop(listener);
    drop(source);

    assert!(
        observed,
        "no Connect event observed for our pid/tgid ({our_pid}) within 2s"
    );
}

/// IPv6 twin of the round-trip above, exercising the Phase 2
/// `tcp_v6_connect` kprobe via a loopback `::1` connect.
///
/// Unlike the v4 test this also asserts the destination: Phase 2 reads
/// (daddr, dport) from the `uaddr` syscall argument — a fixed UAPI
/// `sockaddr_in6` layout, not version-sensitive struct-sock offsets — so
/// the values are reliable across kernels.
#[test]
fn tcp_v6_connect_kprobe_round_trip() {
    use std::net::{IpAddr, Ipv6Addr};

    let (source, rx) = match EventSource::new() {
        Ok(pair) => pair,
        Err(EbpfError::BpfObjectMissing) => {
            eprintln!(
                "BPF object not embedded — run scripts/build-ebpf.sh before \
                 building the test binary. Skipping."
            );
            return;
        }
        Err(EbpfError::UnsupportedPlatform) => {
            eprintln!("eBPF is Linux-only; skipping on this platform.");
            return;
        }
        Err(e) => {
            panic!("EventSource::new failed: {e:?}");
        }
    };

    let listener = TcpListener::bind("[::1]:0").expect("bind IPv6 loopback listener");
    let port = listener.local_addr().unwrap().port();

    std::thread::sleep(Duration::from_millis(50));

    let conn = TcpStream::connect((Ipv6Addr::LOCALHOST, port)).expect("connect to ::1 listener");

    // Drain events for up to 2 seconds looking for our v6 connect: our
    // pid/tgid AND a `::1` destination. The dual filter keeps this test
    // independent from the v4 test's loopback connect, which runs in the
    // same process (cargo runs tests in parallel threads) and is also
    // delivered to this EventSource's ring buffer.
    let our_pid = std::process::id();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut observed = false;
    let mut seen: Vec<(u32, u32, String, IpAddr, u16)> = Vec::new();
    while Instant::now() < deadline {
        if let Ok(EbpfEvent::Connect(c)) = rx.recv_timeout(Duration::from_millis(100)) {
            seen.push((c.pid, c.tgid, c.comm.clone(), c.daddr, c.dport));
            if (c.pid == our_pid || c.tgid == our_pid)
                && c.daddr == IpAddr::V6(Ipv6Addr::LOCALHOST)
            {
                assert_eq!(
                    c.dport, port,
                    "uaddr-derived dport should match the listener port"
                );
                observed = true;
                eprintln!(
                    "observed our v6 connect: pid={} tgid={} comm={:?} daddr={} dport={}",
                    c.pid, c.tgid, c.comm, c.daddr, c.dport
                );
                break;
            }
        }
    }
    eprintln!("diagnostic: looking for pid/tgid={our_pid} daddr=::1");
    eprintln!("diagnostic: saw {} connect events total:", seen.len());
    for (pid, tgid, comm, daddr, dport) in &seen {
        eprintln!("  pid={pid} tgid={tgid} comm={comm:?} daddr={daddr} dport={dport}");
    }

    drop(conn);
    drop(listener);
    drop(source);

    assert!(
        observed,
        "no v6 Connect event observed for our pid/tgid ({our_pid}) to ::1 within 2s"
    );
}

/// Dual-stack case: an AF_INET6 socket connecting to an IPv4 peer goes
/// through `tcp_v6_connect` with a v4-mapped destination
/// (`::ffff:a.b.c.d`). The decoder must canonicalise that back to
/// `IpAddr::V4`, or attribution silently misses every dual-stack app
/// (Go/Java/anything using happy-eyeballs) — their cache keys would be
/// V6 while lsof/ss report the same connection as V4.
#[test]
fn tcp_v6_connect_canonicalises_v4_mapped_destination() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

    let (source, rx) = match EventSource::new() {
        Ok(pair) => pair,
        Err(EbpfError::BpfObjectMissing) | Err(EbpfError::UnsupportedPlatform) => {
            eprintln!("eBPF source unavailable; skipping (see sibling tests).");
            return;
        }
        Err(e) => panic!("EventSource::new failed: {e:?}"),
    };

    // A plain v4 loopback listener; the *client* side is what selects the
    // v4-mapped path by connecting through an AF_INET6 address.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind v4 loopback listener");
    let port = listener.local_addr().unwrap().port();

    std::thread::sleep(Duration::from_millis(50));

    let mapped: Ipv6Addr = "::ffff:127.0.0.1".parse().unwrap();
    let conn = TcpStream::connect(SocketAddr::V6(SocketAddrV6::new(mapped, port, 0, 0)))
        .expect("connect to v4-mapped loopback");

    // Our event must come back as canonical V4. Filter on pid + the exact
    // listener port — the sibling v4/v6 tests run in this same process
    // and also generate loopback connects, but on different ports.
    let our_pid = std::process::id();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut observed = false;
    let mut seen: Vec<(u32, IpAddr, u16)> = Vec::new();
    while Instant::now() < deadline {
        if let Ok(EbpfEvent::Connect(c)) = rx.recv_timeout(Duration::from_millis(100)) {
            seen.push((c.pid, c.daddr, c.dport));
            if (c.pid == our_pid || c.tgid == our_pid) && c.dport == port {
                assert_eq!(
                    c.daddr,
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    "v4-mapped destination should decode as canonical IPv4"
                );
                observed = true;
                eprintln!(
                    "observed v4-mapped connect canonicalised: daddr={} dport={}",
                    c.daddr, c.dport
                );
                break;
            }
        }
    }
    eprintln!("diagnostic: looking for pid/tgid={our_pid} dport={port}");
    for (pid, daddr, dport) in &seen {
        eprintln!("  pid={pid} daddr={daddr} dport={dport}");
    }

    drop(conn);
    drop(listener);
    drop(source);

    assert!(
        observed,
        "no Connect event observed for the v4-mapped connect (port {port}) within 2s"
    );
}
