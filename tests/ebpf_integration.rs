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
use std::io::Read;
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
    // to connect to.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let port = listener.local_addr().unwrap().port();

    // Accept in a helper thread so `connect` doesn't hang the test.
    let server = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf);
        }
    });

    // Small delay so the kprobe attach completes before the connect fires
    // — otherwise we race the attach and the event can land before the
    // userspace reader is set up to observe it.
    std::thread::sleep(Duration::from_millis(50));

    let _conn = TcpStream::connect(("127.0.0.1", port)).expect("connect to listener");

    // Drain events for up to 2 seconds looking for our connect.
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut observed: Option<u16> = None;
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(EbpfEvent::Connect(c)) => {
                // The kprobe fires on every outbound connect on the host,
                // not just ours. Match on dport to find our event.
                if c.dport == port {
                    observed = Some(c.dport);
                    break;
                }
            }
            Err(_) => continue,
        }
    }

    // Tear down before asserting so a failure doesn't leave a hanging
    // reader thread behind.
    drop(source);
    server.join().ok();

    assert_eq!(
        observed,
        Some(port),
        "no Connect event observed for dport={port} within 2s"
    );
}
