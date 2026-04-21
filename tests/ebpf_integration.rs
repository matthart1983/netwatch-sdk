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
    let mut observed_pid = false;
    let mut event_count = 0;
    while Instant::now() < deadline {
        if let Ok(EbpfEvent::Connect(c)) = rx.recv_timeout(Duration::from_millis(100)) {
            event_count += 1;
            if c.pid == our_pid {
                observed_pid = true;
                eprintln!(
                    "observed our connect: pid={} tgid={} comm={:?} dport={} (dport may be 0 pre-CO-RE)",
                    c.pid, c.tgid, c.comm, c.dport
                );
                break;
            }
        }
    }
    eprintln!(
        "diagnostic: saw {event_count} connect events total in 2s window",
    );

    // Close the connection and tear down the BPF source before asserting.
    // Ordering matters so the reader thread has nothing left to process
    // and EventSource::Drop doesn't race with `conn`'s close.
    drop(conn);
    drop(listener);
    drop(source);

    assert!(
        observed_pid,
        "no Connect event observed for our pid ({our_pid}) within 2s"
    );
}
