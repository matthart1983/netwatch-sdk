# Collectors reference

Eight collector modules under [`src/collectors/`](../src/collectors/). Each section below covers public surface, source of truth, platform behavior, and the call cadence to expect.

> **Stateful** = needs `&mut`, must be retained across calls.
> **Stateless** = free function, call any time.

---

## `traffic` — interface rates

[`src/collectors/traffic.rs`](../src/collectors/traffic.rs)

```rust
const RATE_HISTORY_LEN: usize = 60;

pub struct InterfaceRateTracker { /* private */ }
impl InterfaceRateTracker {
    pub fn new() -> Self;
    pub fn sample(&mut self, current: &HashMap<String, InterfaceStats>)
        -> Vec<InterfaceMetric>;
}

pub fn sample(tracker: &mut InterfaceRateTracker)
    -> anyhow::Result<Vec<InterfaceMetric>>;
```

- **Stateful.** Construct once at startup; share via `&mut` into your collection cycle.
- **Source:** `platform::collect_interface_stats()` — see [platform-support](platform-support.md).
- **First-call behavior:** rates are `0.0`, history is `None`. The second call onward populates them with bytes/sec and a rolling 60-sample window.
- **Eviction:** interfaces that disappear between samples are dropped from the tracker's internal map.
- **Cadence:** every 1–5 seconds. Cheaper than every other collector — drives the snapshot timeline.

---

## `connections` — sockets and TCP states

[`src/collectors/connections.rs`](../src/collectors/connections.rs)

```rust
pub struct TcpStates { pub established: u32, pub time_wait: u32, pub close_wait: u32 }
pub struct ConnectionDetail {
    pub protocol:       String,           // "TCP" | "UDP"
    pub local_addr:     String,           // "10.0.0.1:443" or "[::1]:443"
    pub remote_addr:    String,
    pub state:          String,           // normalized: "ESTABLISHED", "TIME_WAIT", …
    pub pid:            Option<u32>,
    pub process_name:   Option<String>,
    pub kernel_rtt_us:  Option<f64>,      // microseconds
}

pub fn count_established_connections() -> u32;
pub fn collect_tcp_states() -> TcpStates;
pub fn collect_connections() -> Vec<ConnectionDetail>;
pub fn top_connections(conns: Vec<ConnectionDetail>, max: usize)
    -> Vec<ConnectionDetail>;

// Pure parsers exposed for testing and reuse:
pub fn parse_ss_output(text: &str)     -> Vec<ConnectionDetail>;
pub fn parse_nettop_output(text: &str) -> HashMap<(String, String), f64>;
```

- **Stateless.**
- **Source:**
  - **Linux:** `/proc/net/tcp(6)` for state counts; `ss -tunapi` for full details (gives kernel RTT in the `rtt:N/M` field).
  - **macOS:** `netstat -an -p tcp` for state counts; `lsof -i -n -P -F pcPtTn` for sockets + PIDs; `nettop -x -n -m tcp -l 1` to enrich with kernel RTT (tcp4 only — tcp6 RTT is skipped pending IPv6 syntax normalization).
- **Failure modes:** missing tools or unreadable `/proc` → empty/zero result, never panics.
- **Cadence:** every 10–30 seconds. `lsof` and `nettop` are slow enough that you don't want them on every snapshot.

---

## `process_bandwidth` — per-process attribution

[`src/collectors/process_bandwidth.rs`](../src/collectors/process_bandwidth.rs)

```rust
pub struct ProcessBandwidth {
    pub process_name:     String,
    pub pid:              Option<u32>,
    pub rx_bytes:         u64,
    pub tx_bytes:         u64,
    pub rx_rate:          f64,
    pub tx_rate:          f64,
    pub connection_count: u32,
}

pub fn attribute(
    connections: &[ConnectionDetail],
    interfaces:  &[InterfaceMetric],
    max:         usize,
) -> Vec<ProcessBandwidth>;
```

- **Stateless.** Pure transform — feed it the latest `connections` and `interfaces` and it returns the top `max` processes by `rx_rate + tx_rate`.
- **Method:** counts ESTABLISHED connections per PID, divides total interface bandwidth across them proportionally. Not packet-accurate; close-enough heuristic that doesn't require eBPF or kernel tracing.
- **Edge cases:** zero ESTABLISHED total → empty `Vec`.

---

## `network_intel` — detectors and DNS analytics

[`src/collectors/network_intel.rs`](../src/collectors/network_intel.rs)

The most complex collector — event-driven, with four built-in detectors plus a DNS analytics aggregator.

```rust
pub struct NetworkIntelCollector { /* private */ }
impl NetworkIntelCollector {
    pub fn new() -> Self;

    // queries
    pub fn active_alerts(&self)      -> Vec<Alert>;
    pub fn active_alert_count(&self) -> usize;
    pub fn alert_history(&self)      -> &VecDeque<Alert>; // last 100
    pub fn dns_analytics(&self)      -> DnsAnalytics;

    // configuration
    pub fn set_bandwidth_threshold(&mut self, bytes_per_sec: u64);

    // periodic maintenance — call ~every 30s
    pub fn tick(&mut self);

    // event sinks — call as events arrive
    pub fn on_conn_attempt(&mut self,   ev: ConnAttemptEvent);
    pub fn on_dns_query(&mut self,      ev: DnsQueryEvent);
    pub fn on_dns_response(&mut self,   ev: DnsResponseEvent);
    pub fn on_interface_rate(&mut self, ev: InterfaceRateEvent);
}

pub enum AlertSeverity { Warning, Critical }
pub enum AlertCategory { PortScan, Beaconing, DnsTunnel, Bandwidth }
pub struct Alert {
    pub severity:  AlertSeverity,
    pub category:  AlertCategory,
    pub message:   String,
    pub detail:    String,
    pub timestamp: DateTime<Utc>,
}

pub struct DnsAnalytics {
    pub total_queries:    u64,
    pub total_responses:  u64,
    pub nxdomain_count:   u64,
    pub latency_buckets:  [u64; 8], // <5, <10, <25, <50, <100, <250, <500, ≥500 ms
    pub top_domains:      Vec<(String, u32)>, // top 20
}

pub fn split_host_port(addr: &str) -> Option<(String, u16)>;
```

- **Stateful.**
- **Detectors and their thresholds** (constants live near the top of the module if you need to tune them):

  | Detector       | Trigger                                                                                       |
  | -------------- | --------------------------------------------------------------------------------------------- |
  | Port scan      | ≥ 20 unique destination ports from a single source IP within a 30 s window                    |
  | Beaconing      | ≥ 5 connection attempts to the same `(src, dst, port)` with < 15 % jitter on inter-arrival    |
  | DNS tunnel     | A query name > 80 bytes, OR > 50 queries/min to one parent domain with > 30 unique subdomains |
  | Bandwidth      | RX or TX on an interface exceeds the configured threshold for 2 consecutive samples           |

- **`tick()` does the cleanup work** — pruning stale port-scan windows, expiring outstanding DNS transactions (5 s timeout), aging out alerts (60 s active TTL). **Without `tick()` you leak memory.**
- **Event sources** are up to the agent. The bundled agent feeds these from a packet-sniffer thread; a third-party agent could feed them from eBPF, log streams, or a sFlow collector.
- **`split_host_port`** normalises `"10.0.0.1:443"` and `"[::1]:443"` to `(host, port)` — useful when matching events from different sources that format addresses differently.

---

## `health` — gateway / DNS probing

[`src/collectors/health.rs`](../src/collectors/health.rs)

```rust
const RTT_HISTORY_LEN: usize = 60;

pub struct PingResult { pub rtt_ms: Option<f64>, pub loss_pct: f64 }
pub struct RttHistory { /* private */ }
impl RttHistory {
    pub fn new()                     -> Self;
    pub fn push(&mut self, rtt: Option<f64>);
    pub fn snapshot(&self)           -> Vec<Option<f64>>;
    pub fn len(&self)                -> usize;
    pub fn is_empty(&self)           -> bool;
}

pub fn run_ping(target: &str) -> PingResult;
```

- **`run_ping` is stateless** — runs `ping -c 3 -W 1 <target>` and returns the average RTT and loss. **Blocks for up to ~3 seconds**; call from a dedicated task.
- **`RttHistory` is stateful.** A typical agent owns one for the gateway and one for DNS, pushes the latest `rtt_ms` (which is `Option<f64>` to preserve failed-probe gaps), and snapshots the window into the corresponding `*_rtt_history` field on `HealthMetric`.
- **Source:** the system `ping` binary on both Linux and macOS — no raw socket, no setuid required.

---

## `disk`

[`src/collectors/disk.rs`](../src/collectors/disk.rs)

```rust
pub struct DiskUsage {
    pub mount_point:     String,
    pub device:          String,
    pub total_bytes:     u64,
    pub used_bytes:      u64,
    pub available_bytes: u64,
    pub usage_pct:       f64, // 0..=100, one decimal
}
pub struct DiskIo { pub read_bytes: u64, pub write_bytes: u64 }

pub fn collect_disk_usage() -> Vec<DiskUsage>;
pub fn collect_disk_io()    -> Option<DiskIo>;
```

- **Stateless.**
- **`collect_disk_usage`:**
  - **Linux:** parses `/proc/mounts`, filters to real `/dev/*` devices (skips `tmpfs`, `proc`, `sysfs`, etc.), then `libc::statvfs()` for each.
  - **macOS:** runs `mount`, filters `/dev/*` (excluding APFS firmlinks under `/Volumes`, `/System/Volumes`, `/private`), then `libc::statvfs()`.
- **`collect_disk_io`:**
  - **Linux:** sums sectors read/written from `/proc/diskstats` (× 512 bytes) excluding `loop`, `ram`, `dm-*`.
  - **macOS:** returns `None`. (Full IOKit integration is a future enhancement.)

---

## `system` — CPU, memory, load, swap

[`src/collectors/system.rs`](../src/collectors/system.rs)

```rust
pub struct CpuInfo    { pub model: Option<String>, pub cores: Option<u32> }
pub struct MemoryInfo { pub total_bytes: u64, pub available_bytes: u64, pub used_bytes: u64 }
pub struct SwapInfo   { pub total_bytes: u64, pub used_bytes: u64 }
pub struct LoadAvg    { pub one: f64, pub five: f64, pub fifteen: f64 }

pub fn detect_cpu_info()     -> CpuInfo;
pub fn detect_memory_total() -> Option<u64>;
pub fn measure_cpu_usage()   -> Option<f64>;        // 0..=100, sleeps ~200ms
pub fn measure_cpu_per_core()-> Option<Vec<f64>>;   // Linux only
pub fn read_memory()         -> Option<MemoryInfo>;
pub fn read_load_avg()       -> Option<LoadAvg>;
pub fn read_swap()           -> Option<SwapInfo>;
```

- **Stateless.** All functions take no args.
- **`measure_cpu_usage` and `measure_cpu_per_core` block for ~200 ms** computing the diff between two `/proc/stat` snapshots (Linux) or between two `ps -A -o %cpu` snapshots (macOS). Don't call them inside hot paths — once per snapshot is fine.
- **Source matrix:**

  | Function                | Linux                         | macOS                                |
  | ----------------------- | ----------------------------- | ------------------------------------ |
  | `detect_cpu_info`       | `/proc/cpuinfo` + `lscpu`     | `sysctl -n machdep.cpu.brand_string` |
  | `detect_memory_total`   | `/proc/meminfo` (`MemTotal`)  | `sysctl -n hw.memsize`               |
  | `measure_cpu_usage`     | `/proc/stat` cpu line × 2     | `ps -A -o %cpu` × 2                  |
  | `measure_cpu_per_core`  | `/proc/stat` cpuN lines × 2   | _not implemented_                    |
  | `read_memory`           | `/proc/meminfo`               | `vm_stat`                            |
  | `read_load_avg`         | `/proc/loadavg`               | `libc::getloadavg`                   |
  | `read_swap`             | `/proc/meminfo` (`SwapTotal`) | `sysctl -n vm.swapusage`             |

---

## `config` — gateway and DNS detection

[`src/collectors/config.rs`](../src/collectors/config.rs)

```rust
pub fn detect_gateway() -> Option<String>;
pub fn detect_dns()     -> Option<String>;
```

- **Stateless.**
- **`detect_gateway`:** parses `ip route` (Linux) or `netstat -rn` (macOS) for the `default via …` row.
- **`detect_dns`:** reads the first `nameserver` line from `/etc/resolv.conf`.
- **Cadence:** these answers rarely change. Run once at startup and on network change events; don't poll in the hot loop.

---

## Putting it together

A minimal end-to-end agent loop using everything above:

```rust
use netwatch_sdk::collectors::{
    config, connections, disk, health, network_intel, process_bandwidth, system, traffic,
};
use netwatch_sdk::types::*;
use chrono::Utc;
use std::time::Duration;

fn main() -> anyhow::Result<()> {
    let mut tracker = traffic::InterfaceRateTracker::new();
    let mut intel   = network_intel::NetworkIntelCollector::new();
    let mut gw_rtt  = health::RttHistory::new();
    let mut dns_rtt = health::RttHistory::new();

    let gateway = config::detect_gateway();
    let dns_ip  = config::detect_dns();

    loop {
        let interfaces = traffic::sample(&mut tracker)?;

        let tcp = connections::collect_tcp_states();
        let conns = connections::collect_connections();
        let processes = process_bandwidth::attribute(&conns, &interfaces, 10);

        let gw_ping  = gateway.as_deref().map(health::run_ping);
        let dns_ping = dns_ip.as_deref().map(health::run_ping);
        gw_rtt.push(gw_ping.as_ref().and_then(|p| p.rtt_ms));
        dns_rtt.push(dns_ping.as_ref().and_then(|p| p.rtt_ms));

        intel.tick();

        let snapshot = Snapshot {
            timestamp: Utc::now(),
            interfaces,
            health: Some(HealthMetric {
                gateway_ip:           gateway.clone(),
                gateway_rtt_ms:       gw_ping.as_ref().and_then(|p| p.rtt_ms),
                gateway_loss_pct:     gw_ping.as_ref().map(|p| p.loss_pct),
                dns_ip:               dns_ip.clone(),
                dns_rtt_ms:           dns_ping.as_ref().and_then(|p| p.rtt_ms),
                dns_loss_pct:         dns_ping.as_ref().map(|p| p.loss_pct),
                gateway_rtt_history:  Some(gw_rtt.snapshot()),
                dns_rtt_history:      Some(dns_rtt.snapshot()),
            }),
            connection_count: Some(tcp.established),
            system: Some(SystemMetric {
                cpu_usage_pct: system::measure_cpu_usage(),
                /* …populate from system::read_memory(), read_load_avg(), read_swap()… */
                ..Default::default()
            }),
            disk_usage: Some(disk::collect_disk_usage()),
            disk_io:    disk::collect_disk_io(),
            tcp_time_wait:  Some(tcp.time_wait),
            tcp_close_wait: Some(tcp.close_wait),
            processes:      Some(processes),
            connections:    Some(conns),
            alerts:         Some(intel.active_alerts()),
            dns_analytics:  Some(intel.dns_analytics()),
        };

        // …push snapshot onto an outbound batch, send periodically.

        std::thread::sleep(Duration::from_secs(5));
    }
}
```
