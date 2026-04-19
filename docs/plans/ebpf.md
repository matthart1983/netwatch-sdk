# Plan — Full eBPF support

> Status: proposal, not started.
> Owner: TBD.
> Scope: SDK only. Cloud and dashboard changes are tracked separately.

## Why

The current collectors poll `/proc`, `ss`, `lsof`, and `nettop` on a 5–30 s cadence. That's enough for "what is this host doing right now" dashboards and the four built-in detectors, but it leaves a few real questions unanswerable:

- **Short-lived flows** — a connection that opens and closes between two `ss` polls is invisible. Beaconing detection misses sub-cycle patterns; port-scan detection only sees what's still open at sample time.
- **Process attribution at the source** — `ss → /proc/<pid>` is racy. By the time we read `/proc/<pid>/comm`, the PID may have exited or been recycled.
- **Pre-encryption visibility** — TLS hides everything below the cleartext SNI. We can't see HTTP method, host, or user-agent without MITM.
- **Kernel-side drops** — packets the kernel drops at the qdisc never appear in pcap or `ss`.
- **Syscall context** — DNS lookups via `getaddrinfo`, `connect()` failures, `accept()` storms — none of this is reachable from userspace polling.

eBPF closes all of those gaps on Linux. The plan below adds it as an **opt-in** capability so the existing pure-Rust collectors keep working unchanged on hosts (and platforms) where eBPF isn't viable.

## Non-goals

- macOS support. Apple's `Endpoint Security` framework covers some equivalent ground but the API and the model are wholly different — that's a separate plan.
- Replacing the existing collectors. eBPF augments them; it doesn't deprecate them. Hosts on RHEL 7 / Debian 10 / kernels < 5.4 will keep the legacy path indefinitely.
- "Best-in-class" runtime BPF compilation. We use ahead-of-time-compiled BPF objects (CO-RE) shipped in the agent binary; we don't bring `clang` to the host.

## Recommended stack

**[`aya`](https://github.com/aya-rs/aya)** is the right choice. Reasons:

- Pure Rust loader and userspace API. No `libbpf` C dependency, no `bindgen` at consumer build time. Simpler `cargo install` story for an open-source SDK.
- BTF / CO-RE first-class. Compiles on a build machine; runs on any kernel ≥ 5.4 with BTF (Ubuntu 20.04+, RHEL 9+, modern Debian/Fedora).
- Active maintenance and a healthy ecosystem (`aya-log`, `aya-tool`).
- Workspace ergonomics: one Cargo workspace can hold the BPF programs (`#![no_std]` crate compiled to BPF target) and the userspace SDK side-by-side.

The alternative — `libbpf-rs` — is more battle-tested in production and has slightly fuller feature support, but the C dependency complicates packaging and `cargo install` from a fresh box.

## Capability matrix

What lights up when eBPF is enabled:

| Today (poll-based)                                  | eBPF-enabled                                                                |
| --------------------------------------------------- | --------------------------------------------------------------------------- |
| `connections::collect_connections()` every 10–30 s  | Real-time stream of `connect`/`accept`/`close` events with PID and cgroup   |
| `process_bandwidth` proportional from connection counts | Real bytes-per-PID from `tcp_sendmsg`/`tcp_recvmsg` kprobes                 |
| TCP states from `/proc/net/tcp` snapshots           | TCP retransmits, RTT, congestion-window from `tcp_retransmit_skb` tracepoint |
| DNS analytics fed by external pcap stream           | DNS queries + responses via `udp_send`/`udp_recv` uprobes on `getaddrinfo`  |
| No visibility on dropped packets                    | `kfree_skb` / `tracepoint:skb:kfree_skb` for kernel drops                   |
| No SNI / no app-layer info                          | uprobes on `SSL_write` for TLS SNI before encryption                        |

The detectors in `network_intel` already speak in events (`on_conn_attempt`, `on_dns_query`, …). eBPF becomes a **second event source** feeding the same sinks, so detector code is untouched.

## Architecture sketch

```
┌────────────────────────────────────────────────────────────┐
│  netwatch-sdk (existing crate)                             │
│  ├── collectors/* (unchanged, stays the polling path)      │
│  └── ebpf::EventSource (new, behind `ebpf` cargo feature)  │
│        │                                                   │
│        ├── connect/accept/close events                     │
│        ├── tcp_sendmsg/recvmsg byte counts per pid         │
│        ├── DNS query/response w/ pid                       │
│        └── kernel drops, retransmits                       │
│                                                            │
│  Same Snapshot / Alert / DnsAnalytics types — no new       │
│  wire-format additions in phase 1.                         │
└────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────────┐
│  netwatch-sdk-ebpf (new sibling crate)                     │
│  - #![no_std] BPF programs compiled to BPF target          │
│  - Built once at SDK build time, .o files embedded via     │
│    include_bytes! into the userspace crate                 │
└────────────────────────────────────────────────────────────┘
```

The agent decides at startup whether to enable the eBPF source: kernel ≥ 5.4 + BTF present + capability check. On failure (old kernel, locked-down host, no `CAP_BPF`/root), it logs once and falls back to polling. Same crate, same binary.

## Phasing

### Phase 0 — design freeze (1 week)

- Lock the public API of `ebpf::EventSource`: which events, what fields, how the user iterates / consumes them (channel? async stream? trait callback?).
- Decide whether to use a single ring buffer for all events or one per program (recommended: one per program for backpressure isolation).
- Pick the kernel-version floor (recommended: ≥ 5.10, which gives us `CAP_BPF` instead of full root and reliable BTF).

### Phase 1 — connection events (2–3 weeks)

The simplest concrete win, and the one that immediately improves four downstream things (per-PID bandwidth, beacon detection precision, port-scan windowing, short-lived flow visibility).

- Workspace restructure: `Cargo.toml` becomes a workspace; add `crates/ebpf-programs` as a `cdylib` BPF target and `crates/sdk` as the existing crate.
- Programs:
  - `kprobe:tcp_v4_connect` / `kprobe:tcp_v6_connect` → `ConnectEvent { pid, comm, src, dst, ts }`
  - `kprobe:inet_csk_accept` → `AcceptEvent { … }`
  - `tracepoint:sock:inet_sock_set_state` → catches close + state transitions
- Userspace:
  - `EventSource::new()` loads the BPF object, sets up ring buffer, returns a `Receiver<EbpfEvent>`.
  - Wire into `network_intel`'s existing `on_conn_attempt` so detectors immediately benefit.
  - Mirror to `connections::collect_connections()` consumers via a new `connections::stream()` opt-in.
- Build system:
  - `build.rs` in the SDK crate calls `bpf-linker` (aya supplies it) to produce a stable `.o` blob, embedded via `include_bytes!`.
  - Cross-compile target: `bpfel-unknown-none`. Document the toolchain prerequisites in `docs/extending.md`.

Tests for phase 1:
- BPF programs themselves are exercised by a new integration test that runs in a privileged Linux container (GitHub Actions `ubuntu-latest` works with `--privileged` via Docker), opens a TCP socket to localhost, and asserts the event fires with the right PID.
- Fixture-based tests for the userspace side use a fake ring buffer producer.

### Phase 2 — bytes per PID + retransmits (2 weeks)

- `kprobe:tcp_sendmsg` / `kprobe:tcp_recvmsg` → per-PID byte counters in a BPF map.
- `tracepoint:tcp:tcp_retransmit_skb` → retransmit events with `(src, dst, sport, dport)`.
- New `Snapshot` field: `processes_realtime: Option<Vec<ProcessBandwidth>>`. The existing `processes` field stays for the polling path; consumers prefer `*_realtime` if present (fully forward-compatible).
- Network intel gains a "high retransmit rate" detector that uses the new event stream.

### Phase 3 — DNS + drops (2 weeks)

- uprobes on `getaddrinfo` (libc) and `SSL_do_handshake` for SNI extraction.
- `tracepoint:skb:kfree_skb` for kernel drops, attributed to ifindex.
- Feeds existing `on_dns_query` / `on_dns_response`. Adds new `Alert` variant for "kernel-side drops on `<iface>`".

### Phase 4 — cgroup / container attribution (1 week)

- Read `task->css_set->cgrp` at event time, resolve to container ID via cgroup path → embed in events.
- New optional `container_id: Option<String>` field on the relevant payloads (forward-compatible additive change).

## Risks and constraints

| Risk                                                        | Mitigation                                                                                  |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Kernel version fragmentation on customer hosts              | Hard floor at 5.10. Below that, eBPF is silently disabled and we polling-collect as today.  |
| Locked-down kernels (`kernel.unprivileged_bpf_disabled`)    | Detect at load time, log once, fall back. Same binary, no second build.                     |
| BPF verifier rejecting programs after a kernel update       | `cargo test` + the privileged-container integration suite catch this on every PR.           |
| Build-time dependency on `bpf-linker` and `nightly` Rust    | Document. Pin a known-good Rust nightly via `rust-toolchain.toml` for the BPF crate only.   |
| Crate size growth from embedded BPF objects                 | Each `.o` is ~5–20 KB; full set ≤ 200 KB on the binary. Negligible.                         |
| BPF verifier's stack/loop limits                            | Keep programs small; do aggregation in userspace, not in BPF.                               |
| Differentiated behaviour depending on container runtime     | Document. Provide a smoke test for Docker / Podman / containerd / nspawn.                   |

## Cargo feature shape

```toml
[features]
default = []
ebpf = ["dep:aya", "dep:aya-log"]
```

Consumers opt in:

```toml
netwatch-sdk = { version = "0.2", features = ["ebpf"] }
```

`netwatch-agent` flips the feature on by default; third-party SDK consumers (researchers, custom dashboards) get the polling path with no Linux-kernel headers in their build.

## Decision log (to be updated as we make choices)

- _Loader library:_ `aya` (preferred) vs `libbpf-rs`. Open.
- _Kernel floor:_ 5.10 (preferred for `CAP_BPF`). Open.
- _Ring buffer model:_ one per program (preferred) vs shared. Open.
- _Workspace layout:_ single workspace with sibling BPF crate (preferred). Open.

## Sequencing relative to other work

Phase 1 is the only phase that's a hard prerequisite for the others. After phase 1 ships and the polling fallback is proven against the same hosts, phases 2–4 can ship independently in any order. Coordinate with the agent and cloud teams on the optional `_realtime` fields when phase 2 lands.
