# netwatch-sdk

The shared Rust SDK behind [NetWatch Cloud](https://github.com/matthart1983/netwatch-cloud) — wire-format types and host collectors used by both [`netwatch-agent`](https://github.com/matthart1983/netwatch-agent) (runs on your servers) and the NetWatch Cloud SaaS backend (hosted).

This crate is the **contract** between agent and server. If you're building a NetWatch agent plugin, a custom ingest pipeline, or a compatible third-party client, this is the crate you need.

## What's in the box

- **Wire format** — `Snapshot`, `IngestRequest`, `HostInfo`, `InterfaceMetric`, `HealthMetric`, and their siblings. All `serde`-derived, JSON-compatible, designed for forward/backward compatibility via `#[serde(skip_serializing_if = "Option::is_none")]`.
- **Collectors** — pure-Rust + shell-out implementations of:
  - `traffic`: per-interface rx/tx rates and rolling history, from platform counters
  - `connections`: TCP/UDP socket enumeration via `ss` (Linux) and `lsof` (macOS), with kernel-measured RTT
  - `process_bandwidth`: per-process bandwidth attribution by ESTABLISHED connection count
  - `network_intel`: port-scan, beaconing, DNS-tunnel, and bandwidth-threshold detectors; DNS analytics aggregator
  - `health`: gateway/DNS ICMP probing with rolling RTT history
  - `disk`, `system`, `config`: disk IO/usage, CPU/memory/load, gateway/DNS detection

## Install

```toml
[dependencies]
netwatch-sdk = "0.1"
```

## Minimum example

```rust
use netwatch_sdk::collectors::{traffic, connections, system};

fn main() -> anyhow::Result<()> {
    let mut rate_tracker = traffic::InterfaceRateTracker::new();
    let interfaces = traffic::sample(&mut rate_tracker)?;

    let conns = connections::collect_connections();
    let cpu = system::measure_cpu_usage();

    println!("{} interfaces, {} connections, CPU {:?}%",
             interfaces.len(), conns.len(), cpu);
    Ok(())
}
```

## Platform support

| Platform | Status |
|---|---|
| Linux | First-class (all collectors) |
| macOS | First-class (uses `lsof`, `nettop`; some features degrade gracefully) |
| Windows | Not yet |

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

MIT © 2025-2026 Matt Hartley
