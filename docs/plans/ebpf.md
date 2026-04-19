# Plan — Full eBPF support

> Status: **Phase 1 scaffolding shipped**; real BPF compilation pending a Linux session.
> Owner: TBD.
> Scope: SDK only. Cloud and dashboard changes are tracked separately.

## Locked decisions

| Decision        | Choice                                                                |
| --------------- | --------------------------------------------------------------------- |
| Loader          | **`aya`** (pure-Rust, CO-RE/BTF, no `libbpf` C dep)                   |
| Kernel floor    | **≥ 5.10** (reliable BTF and `CAP_BPF`)                               |
| Event delivery  | **`std::sync::mpsc::Receiver<EbpfEvent>`** (sync, single reader)      |
| Workspace       | **Two extra crates** under `crates/`: `common` (shared no_std types) and `ebpf-programs` (BPF target, excluded from default workspace) |
| Cargo feature   | **`ebpf`** — opt-in, target-gates `aya` to Linux so cross-platform builds stay clean |
| BPF artifact    | Built by `scripts/build-ebpf.sh` into `target/bpf/`, embedded by `build.rs` via `include_bytes!` |

## What shipped (this session)

- `crates/common/` — `netwatch-sdk-common` crate. `#![no_std]` event types (`ConnectV4Event`, `EventKind`) shared by BPF and userspace. `repr(C)` + `Copy` so the BPF program can write directly into a ring buffer and userspace can `read_unaligned` it back.
- `crates/ebpf-programs/` — `netwatch-sdk-ebpf-programs` crate. `#![no_std] #![no_main]` with a real `tcp_v4_connect` kprobe (aya-ebpf). Pinned nightly toolchain via `rust-toolchain.toml`, BPF target via `.cargo/config.toml`. Excluded from the parent workspace so a stable `cargo build` at the repo root never touches it.
- `src/ebpf/` — userspace `EventSource` API, gated by `#[cfg(feature = "ebpf")]`.
  - `mod.rs` — public re-exports.
  - `event.rs` — `EbpfEvent` enum, `ConnectEvent` struct (host-byte-order address/port, decoded `comm`), pure decoder with portable endianness handling and a fixture test.
  - `source.rs` — `EventSource::new()` returning `(Self, Receiver<EbpfEvent>)`. Linux implementation loads the embedded BPF object, attaches the kprobe, takes ownership of the `EVENTS` ring buffer, and spawns a reader thread that pushes decoded events. Non-Linux returns `EbpfError::UnsupportedPlatform`.
- `build.rs` — always writes `$OUT_DIR/netwatch_sdk_ebpf.o` (empty if `target/bpf/` is empty); `include_bytes!` therefore always compiles, and an empty file becomes `EbpfError::BpfObjectMissing` at runtime.
- `scripts/build-ebpf.sh` — drives `cargo +nightly build --target bpfel-unknown-none --release` in the BPF crate, copies the artifact into `target/bpf/`. Checks for `rustup` and `bpf-linker` upfront with helpful errors.
- `Cargo.toml` — workspace converted; `aya` and `aya-log` declared under `[target.'cfg(target_os = "linux")'.dependencies]` so `--features ebpf` builds on macOS/Windows without dragging in unbuildable Linux-only deps.

**Verification on macOS:** `cargo test` (default) → 73 pass. `cargo test --features ebpf` → 78 pass (5 new ebpf tests). The actual BPF program hasn't been compiled yet (needs Linux + nightly + `bpf-linker`), so `EventSource::new()` would return `BpfObjectMissing` at runtime today.

## Known limitations / next-session work

- **CO-RE not yet wired in the kprobe.** The kprobe reads `struct sock` fields at hard-coded offsets that match a 5.15 reference kernel. This works for the proof of concept but won't be portable across kernels until we switch to aya's CO-RE relocations.
- **Source port is always 0.** It lives at a different offset (`inet_sock->inet_sport`) than the destination (`__sk_common.skc_dport`) and reading it cleanly needs CO-RE.
- **Reader thread is a busy-poll loop with a 5 ms sleep.** Replace with `epoll`-based wakeup once Phase 2 is on the board.
- **No CI for the BPF build.** Add a `--privileged` Docker step or a self-hosted Linux runner that installs `bpf-linker`, runs `scripts/build-ebpf.sh`, and runs the integration test inside an Ubuntu 22.04 container with `--cap-add BPF --cap-add PERFMON`.

## Non-goals

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

## Decision log

- _Loader library:_ **aya** (locked, in code).
- _Kernel floor:_ **5.10** (locked).
- _Ring buffer model:_ **one per program** — Phase 1 only has one BPF program so this is moot today. When phase 2 lands a second program, give it its own ring buffer.
- _Workspace layout:_ **two extra crates** under `crates/` (`common`, `ebpf-programs`). The BPF crate is intentionally NOT a workspace member because it requires a different toolchain.

## Sequencing relative to other work

Phase 1 is the only phase that's a hard prerequisite for the others. After phase 1 ships and the polling fallback is proven against the same hosts, phases 2–4 can ship independently in any order. Coordinate with the agent and cloud teams on the optional `_realtime` fields when phase 2 lands.
