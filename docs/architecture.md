# Architecture

`netwatch-sdk` is a passive library, not a daemon. It exposes building blocks an agent assembles into a collection cycle and ships to a server.

## The collection cycle

A NetWatch agent typically follows this loop:

```
┌── once at startup ──────────────────────────────────────┐
│  HostInfo { host_id, hostname, os, kernel, cpu_*, mem } │
└─────────────────────────────────────────────────────────┘

┌── every N seconds ─────────────────────────────────────────────────┐
│  1. platform::collect_interface_stats()    → InterfaceStats map    │
│  2. tracker.sample(map)                    → InterfaceMetric vec   │
│  3. connections::collect_tcp_states()      → TcpStates             │
│  4. connections::collect_connections()     → ConnectionDetail vec  │
│  5. process_bandwidth::attribute(c, i, n)  → ProcessBandwidth vec  │
│  6. system::measure_cpu_usage(),           → SystemMetric          │
│     read_memory(), read_load_avg()…                                │
│  7. disk::collect_disk_usage(),                                    │
│     disk::collect_disk_io()                → Disk* payloads        │
│  8. health::run_ping(gw), run_ping(dns)    → HealthMetric          │
│  9. intel.tick(); intel.active_alerts();                           │
│     intel.dns_analytics()                  → Alerts + DnsAnalytics │
│ 10. assemble Snapshot {…}                                          │
│ 11. push Snapshot onto a buffered IngestRequest                    │
└────────────────────────────────────────────────────────────────────┘

┌── every M seconds (M ≥ N) ─────────────────────────────────────────┐
│  POST IngestRequest { agent_version, host, snapshots: [..] }       │
│  → IngestResponse { accepted, rejected, results }                  │
└────────────────────────────────────────────────────────────────────┘
```

Steps 1–10 are cheap enough to run every 1–5 seconds on a small host. Heavier collectors (connections, ping, disk IO) can be sampled less often by skipping steps in some cycles.

## Stateful vs stateless collectors

The SDK splits cleanly along this boundary, and the boundary determines how callers wire each piece into their loop.

### Stateful (require `&mut`, must outlive the loop)

| Type                            | Why it's stateful                                                                                        |
| ------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `traffic::InterfaceRateTracker` | Holds the last sample's cumulative counters and timestamp so the next call can compute deltas and rates. |
| `network_intel::NetworkIntelCollector` | Maintains tracking maps for port-scan windows, beacon timing, DNS-tunnel domains, and bandwidth alert state across calls. Must call `tick()` periodically to prune stale entries. |
| `health::RttHistory`            | Rolling window of up to 60 RTT samples; `push()` is the mutating call.                                   |

Construct each at agent startup, store on the agent struct, pass `&mut` into the cycle.

### Stateless (free functions or pure transforms)

`connections::*`, `process_bandwidth::attribute`, `disk::*`, `system::*`, `config::*`, and `health::run_ping` all take a snapshot of the world and return data. They can be called from any task, on any cadence, in any order.

This split is important when adding a new collector: if you need cross-call state, copy the `InterfaceRateTracker` pattern. Otherwise prefer a free function — it composes better.

## Module boundaries

```
src/
├── lib.rs          re-exports collectors / platform / types
├── types.rs        Snapshot, IngestRequest, payload structs
├── platform/
│   ├── mod.rs      cfg-gated re-export of collect_interface_stats()
│   ├── linux.rs    /sys/class/net implementation
│   └── macos.rs    netstat -ibn + ifconfig implementation
└── collectors/
    ├── traffic.rs            InterfaceRateTracker
    ├── connections.rs        ss / lsof / nettop parsing
    ├── process_bandwidth.rs  proportional attribution
    ├── network_intel.rs      detectors + DnsAnalytics
    ├── health.rs             ping + RttHistory
    ├── disk.rs               statvfs + /proc/diskstats
    ├── system.rs             cpu/memory/load/swap (per-OS)
    └── config.rs             gateway/DNS detection
```

Two simple rules govern this layout:

1. **Anything that touches the OS lives in `collectors/` or `platform/`.** The wire format (`types.rs`) never reads the system; it only describes what crosses the network.
2. **Platform differences are quarantined to `platform/` and to `#[cfg]`-gated functions inside individual collectors.** Most collectors are written so that the dispatch happens once at the top of the function (`#[cfg(target_os = "linux")] { … } #[cfg(target_os = "macos")] { … }`).

## Forward and backward compatibility

The wire format is designed for additive evolution:

- Every optional field on `Snapshot` and `InterfaceMetric` carries `#[serde(default, skip_serializing_if = "Option::is_none")]`, which means:
  - **Old agent → new server:** unknown new fields aren't sent; server sees `None` and degrades gracefully.
  - **New agent → old server:** new fields are sent but the old `serde` `deny_unknown_fields = false` (default) ignores them.
- New required fields are an explicit breaking change. Bump the major version in `Cargo.toml` if you add one.

When in doubt: add new payload as `Option<…>` and gate any consumer logic on `Some(_)`.

## Where each NetWatch project sits

```
agents on hosts                                      cloud
─────────────────                              ───────────────────
                  HTTP POST /v1/ingest
netwatch-agent ───────────────────────────────► netwatch-cloud
   uses                                            uses
   netwatch-sdk ◄───── same crate ─────────────► netwatch-sdk
   (collectors                                    (types only —
    + types)                                       deserializes
                                                   IngestRequest)
```

The cloud server pins the same `netwatch-sdk` version as the agent it accepts. When the SDK's wire format changes, both sides upgrade together.
