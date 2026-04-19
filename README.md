# netwatch-sdk

[![crates.io](https://img.shields.io/crates/v/netwatch-sdk.svg)](https://crates.io/crates/netwatch-sdk)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS-blue)](docs/platform-support.md)

The shared Rust SDK behind [NetWatch Cloud](https://github.com/matthart1983/netwatch-cloud) — wire-format types and host-side collectors used by both [`netwatch-agent`](https://github.com/matthart1983/netwatch-agent) (runs on customer hosts) and the NetWatch Cloud SaaS backend.

This crate is the **contract** between agent and server. If you're writing an agent plugin, building a custom ingest pipeline, or wiring up a third-party client that should look like a NetWatch agent on the wire, this is the crate you depend on.

## Install

```toml
[dependencies]
netwatch-sdk = "0.1"
```

## Minimal example

```rust
use netwatch_sdk::collectors::{connections, system, traffic};

fn main() -> anyhow::Result<()> {
    let mut tracker = traffic::InterfaceRateTracker::new();

    // First call seeds the tracker with cumulative counters.
    let _ = traffic::sample(&mut tracker)?;
    std::thread::sleep(std::time::Duration::from_secs(1));
    // Second call onward yields meaningful per-interface rates.
    let interfaces = traffic::sample(&mut tracker)?;

    let conns = connections::collect_connections();
    let cpu = system::measure_cpu_usage();

    println!(
        "{} interfaces, {} connections, CPU {:?}%",
        interfaces.len(),
        conns.len(),
        cpu
    );
    Ok(())
}
```

See [`docs/architecture.md`](docs/architecture.md) for the full collection cycle, [`docs/wire-format.md`](docs/wire-format.md) for the JSON payloads, and [`docs/collectors.md`](docs/collectors.md) for every public function.

## What's in the box

- **Wire format** — `IngestRequest`, `Snapshot`, `HostInfo`, `InterfaceMetric`, `HealthMetric`, `SystemMetric`, plus collector-specific payloads. All `serde`-derived, JSON-compatible, and forward-compatible: optional fields are `#[serde(skip_serializing_if = "Option::is_none")]` so old agents talk to new servers and vice versa.
- **Collectors** — pure-Rust + targeted shell-outs for:
  - `traffic` — per-interface byte/packet counters with rolling rate history (stateful)
  - `connections` — TCP/UDP socket enumeration via `ss` (Linux) / `lsof` + `nettop` (macOS), with kernel-measured RTT
  - `process_bandwidth` — per-process bandwidth attribution from connection counts
  - `network_intel` — port-scan, beacon, DNS-tunnel, and bandwidth-threshold detectors plus DNS analytics (stateful)
  - `health` — gateway/DNS ICMP probing with rolling RTT history
  - `disk`, `system`, `config` — disk IO/usage, CPU/memory/load, gateway/DNS detection
- **Platform shim** — uniform `collect_interface_stats()` across Linux (`/sys/class/net`) and macOS (`netstat -ibn`); soft fallback on other Unix-likes.

## Documentation

- [**Architecture**](docs/architecture.md) — how a snapshot gets built, stateful vs stateless collectors, agent/SDK/cloud topology.
- [**Wire format**](docs/wire-format.md) — every public type in `types.rs` with field-by-field semantics.
- [**Collectors reference**](docs/collectors.md) — every public function across all collector modules.
- [**Platform support**](docs/platform-support.md) — what works where and how things degrade.
- [**Extending**](docs/extending.md) — adding a new collector, a new alert detector, or a new platform.
- [**Testing**](docs/testing.md) — running the suite and what's actually covered.
- [**Publishing**](docs/publishing.md) — version bump, crates.io release.
- **Roadmap** — [eBPF integration plan](docs/plans/ebpf.md) · [test-coverage plan](docs/plans/test-coverage.md)

## Platform support

| Platform | Status                                                              |
| -------- | ------------------------------------------------------------------- |
| Linux    | First-class — every collector implemented natively                  |
| macOS    | First-class — uses `lsof` / `nettop` / `vm_stat` / `sysctl`         |
| Windows  | Not yet (collectors return empty / `None`; types remain compatible) |

Detail in [`docs/platform-support.md`](docs/platform-support.md).

## Relationship to other NetWatch projects

```
┌──────────────────────────┐   ┌───────────────────────┐
│ netwatch-agent (public)  │   │ netwatch-cloud server │
│  https://github.com/     │   │      (private)        │
│  matthart1983/           │◀─▶│                       │
│  netwatch-agent          │   │                       │
└────────┬─────────────────┘   └──────────┬────────────┘
         │    both depend on this crate   │
         ▼                                ▼
        ┌─────────────────────────────────────┐
        │  netwatch-sdk  (this crate)         │
        │  wire format + collectors           │
        └─────────────────────────────────────┘
```

- [**netwatch**](https://github.com/matthart1983/netwatch) — the original OSS TUI. Unrelated code, similar purpose, kept separate intentionally.
- [**netwatch-agent**](https://github.com/matthart1983/netwatch-agent) — compiled binary you install on hosts; depends on this crate.
- [**netwatch-dashboard**](https://github.com/matthart1983/netwatch-dashboard) — Next.js web UI for NetWatch Cloud.
- [**netwatch-cloud**](https://github.com/matthart1983/netwatch-cloud) — hosted SaaS backend (closed source).

## License

MIT © 2025–2026 Matt Hartley
