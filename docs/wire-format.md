# Wire format

Every type defined in [`src/types.rs`](../src/types.rs) is `serde`-derived JSON. Optional fields use `#[serde(skip_serializing_if = "Option::is_none")]` so payloads stay small and the schema can grow without breaking existing peers.

## `IngestRequest`

The top-level payload an agent POSTs to the cloud.

```rust
struct IngestRequest {
    agent_version: String,
    host: HostInfo,
    snapshots: Vec<Snapshot>,
}
```

- `agent_version` — the `CARGO_PKG_VERSION` of the agent binary (not the SDK). Servers may use it for compatibility decisions.
- `host` — the static metadata for this machine, sent on every request even though it rarely changes (the cloud uses it to upsert the host record).
- `snapshots` — one or more `Snapshot` entries, in chronological order. Agents typically buffer 1–10 snapshots before sending, trading freshness for fewer round-trips.

## `HostInfo`

Identifies and describes the machine.

```rust
struct HostInfo {
    host_id: Uuid,
    hostname: String,
    os: Option<String>,
    kernel: Option<String>,
    uptime_secs: Option<u64>,
    cpu_model: Option<String>,
    cpu_cores: Option<u32>,
    memory_total_bytes: Option<u64>,
}
```

- `host_id` — assigned once, persisted by the agent (e.g., to `/var/lib/netwatch-agent/host_id`). Stable across restarts. The cloud uses this as the primary key.
- `hostname` — what the agent reports today; OK if it changes between requests.
- `os` / `kernel` — informational. Format isn't enforced (e.g., `"Ubuntu 24.04"`, `"6.8.0-31-generic"`).
- `cpu_model` / `cpu_cores` / `memory_total_bytes` — populated from `system::detect_cpu_info()` and `system::detect_memory_total()` at agent startup.

## `Snapshot`

A point-in-time slice of host state. The big one.

```rust
struct Snapshot {
    timestamp:        DateTime<Utc>,
    interfaces:       Vec<InterfaceMetric>,
    health:           Option<HealthMetric>,
    connection_count: Option<u32>,
    system:           Option<SystemMetric>,
    disk_usage:       Option<Vec<DiskUsage>>,
    disk_io:          Option<DiskIo>,
    tcp_time_wait:    Option<u32>,
    tcp_close_wait:   Option<u32>,
    processes:        Option<Vec<ProcessBandwidth>>,
    connections:      Option<Vec<ConnectionDetail>>,
    alerts:           Option<Vec<Alert>>,
    dns_analytics:    Option<DnsAnalytics>,
}
```

- `timestamp` — UTC. Use `Utc::now()` at the start of the cycle, not at send time.
- `interfaces` — always present, even if empty. `InterfaceMetric` is the only required collector payload because rates are the SDK's reason to exist.
- Everything else is `Option`. Agents collect heavyweight data (full `connections`, `processes`) less frequently than every snapshot; intermediate snapshots leave them `None`.

## `InterfaceMetric`

Per-interface counters and derived rates.

```rust
struct InterfaceMetric {
    name:            String,
    is_up:           bool,
    rx_bytes:        u64,
    tx_bytes:        u64,
    rx_bytes_delta:  u64,
    tx_bytes_delta:  u64,
    rx_packets:      u64,
    tx_packets:      u64,
    rx_errors:       u64,
    tx_errors:       u64,
    rx_drops:        u64,
    tx_drops:        u64,
    rx_rate:         Option<f64>,    // bytes/sec
    tx_rate:         Option<f64>,    // bytes/sec
    rx_history:      Option<Vec<u64>>, // up to 60 samples
    tx_history:      Option<Vec<u64>>, // up to 60 samples
}
```

- Cumulative counters (`rx_bytes`, `tx_packets`, …) come straight from `/sys/class/net` or `netstat -ibn`. They wrap on 32-bit kernels — the SDK promotes to `u64` and trusts the kernel-reported width.
- `*_delta` and `*_rate` are populated by `traffic::InterfaceRateTracker::sample()`. **First-call rates are `0.0` and history is `None`** because deltas aren't computable without a prior sample.
- `rx_history` / `tx_history` are the last 60 rate samples (~1 minute at 1 Hz). Older samples drop off the front.

## `HealthMetric`

Gateway and DNS reachability.

```rust
struct HealthMetric {
    gateway_ip:           Option<String>,
    gateway_rtt_ms:       Option<f64>,
    gateway_loss_pct:     Option<f64>,
    dns_ip:               Option<String>,
    dns_rtt_ms:           Option<f64>,
    dns_loss_pct:         Option<f64>,
    gateway_rtt_history:  Option<Vec<Option<f64>>>,
    dns_rtt_history:      Option<Vec<Option<f64>>>,
}
```

- `*_rtt_ms` is the average RTT from a 3-packet ping (`ping -c 3 -W 1`). `*_loss_pct` is the loss as reported by `ping`.
- History entries are `Option<f64>` because individual probes can fail — the slot is preserved as `None` so consumers can render gaps in the time series correctly.

## `SystemMetric`

```rust
struct SystemMetric {
    cpu_usage_pct:           Option<f64>,
    memory_total_bytes:      Option<u64>,
    memory_used_bytes:       Option<u64>,
    memory_available_bytes:  Option<u64>,
    load_avg_1m:             Option<f64>,
    load_avg_5m:             Option<f64>,
    load_avg_15m:            Option<f64>,
    swap_total_bytes:        Option<u64>,
    swap_used_bytes:         Option<u64>,
    cpu_per_core:            Option<Vec<f64>>,
}
```

- `cpu_usage_pct` is rounded to one decimal. **Measuring it sleeps for ~200 ms** inside `system::measure_cpu_usage()` — call it on a dedicated tick, not in tight loops.
- `memory_available_bytes` matches the kernel's `MemAvailable` on Linux and `free + inactive + speculative` from `vm_stat` on macOS.
- `cpu_per_core` is populated on Linux only; `None` on macOS.

## `IngestResponse`

What the cloud sends back.

```rust
struct IngestResponse {
    accepted: u32,
    rejected: u32,
    host_id:  Uuid,
    results:  Vec<SnapshotResult>,
}

struct SnapshotResult {
    index:   usize, // index into the request's snapshots[]
    status:  u16,   // HTTP-like (200, 400, 422, …)
    message: String,
}
```

Agents that batch should retry only the rejected snapshots, identified by `index`.

## Forward-compatibility checklist

When you add a new field:

- New optional field on an existing struct → safe; mark `#[serde(default, skip_serializing_if = "Option::is_none")]`.
- New required field on an existing struct → **breaking**. Major-version bump.
- New enum variant on a public enum → **breaking** unless the enum is `#[non_exhaustive]`. Both `AlertSeverity` and `AlertCategory` are not currently `#[non_exhaustive]`; add the attribute before extending if you want a non-breaking growth path.
- New public struct → safe; just add it.
