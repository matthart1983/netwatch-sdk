use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

use super::connections::ConnectionDetail;
use crate::types::InterfaceMetric;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessBandwidth {
    pub process_name: String,
    pub pid: Option<u32>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_rate: f64,
    pub tx_rate: f64,
    pub connection_count: u32,
}

/// Attribute interface-level bandwidth to processes proportionally by the
/// number of ESTABLISHED connections each process holds. This is an
/// approximation — the kernel does not expose per-process byte accounting
/// cheaply on most platforms — but it mirrors what the TUI reports.
///
/// Returns the top `max` processes sorted by combined rx+tx rate.
pub fn attribute(
    connections: &[ConnectionDetail],
    interfaces: &[InterfaceMetric],
    max: usize,
) -> Vec<ProcessBandwidth> {
    let total_rx_rate: f64 = interfaces.iter().filter_map(|i| i.rx_rate).sum();
    let total_tx_rate: f64 = interfaces.iter().filter_map(|i| i.tx_rate).sum();
    let total_rx_bytes: u64 = interfaces.iter().map(|i| i.rx_bytes).sum();
    let total_tx_bytes: u64 = interfaces.iter().map(|i| i.tx_bytes).sum();

    let mut process_conns: HashMap<(String, Option<u32>), u32> = HashMap::new();
    let mut total_established: u32 = 0;

    for conn in connections {
        if conn.state != "ESTABLISHED" {
            continue;
        }
        let name = conn
            .process_name
            .clone()
            .unwrap_or_else(|| format!("pid:{}", conn.pid.map_or(0, |p| p)));
        let key = (name, conn.pid);
        *process_conns.entry(key).or_insert(0) += 1;
        total_established += 1;
    }

    if total_established == 0 {
        return Vec::new();
    }

    let mut ranked: Vec<ProcessBandwidth> = process_conns
        .into_iter()
        .map(|((process_name, pid), count)| {
            let fraction = count as f64 / total_established as f64;
            ProcessBandwidth {
                process_name,
                pid,
                rx_bytes: (total_rx_bytes as f64 * fraction) as u64,
                tx_bytes: (total_tx_bytes as f64 * fraction) as u64,
                rx_rate: total_rx_rate * fraction,
                tx_rate: total_tx_rate * fraction,
                connection_count: count,
            }
        })
        .collect();

    ranked.sort_by(|a, b| {
        let bw_b = b.rx_rate + b.tx_rate;
        let bw_a = a.rx_rate + a.tx_rate;
        bw_b.partial_cmp(&bw_a).unwrap_or(std::cmp::Ordering::Equal)
    });

    ranked.truncate(max);
    ranked
}

#[derive(Clone, Copy)]
struct SocketBytes {
    rx: u64,
    tx: u64,
}

/// Measures *real* per-process bandwidth from per-socket byte counters
/// (`bytes_received`/`bytes_sent` from `ss -i`), rated by delta over time —
/// the same stateful pattern as `InterfaceRateTracker`. This supersedes the
/// proportional `attribute()` heuristic: two single-connection processes no
/// longer report identical traffic, because each socket's actual bytes are
/// diffed against the previous sample.
///
/// Sockets are keyed by their `local_addr|remote_addr` tuple. A socket seen for
/// the first time contributes 0 this interval (no baseline yet); sockets without
/// kernel byte counters (UDP, listening sockets) contribute to `connection_count`
/// but not to the rate.
#[derive(Default)]
pub struct ProcessBandwidthTracker {
    prev: HashMap<String, SocketBytes>,
    prev_time: Option<Instant>,
}

impl ProcessBandwidthTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sample current connections and return the top `max` processes by measured
    /// rx+tx rate. The first call after construction yields rates of 0 (no prior
    /// sample to diff against), exactly like the interface tracker.
    pub fn sample(&mut self, connections: &[ConnectionDetail], max: usize) -> Vec<ProcessBandwidth> {
        let now = Instant::now();
        let elapsed = self
            .prev_time
            .map(|t| now.duration_since(t).as_secs_f64())
            .unwrap_or(0.0);

        struct Agg {
            pid: Option<u32>,
            rx_bytes: u64,
            tx_bytes: u64,
            rx_rate: f64,
            tx_rate: f64,
            conns: u32,
        }

        let mut per_proc: HashMap<(String, Option<u32>), Agg> = HashMap::new();
        let mut next_prev: HashMap<String, SocketBytes> = HashMap::new();

        for conn in connections {
            if conn.state != "ESTABLISHED" {
                continue;
            }
            let name = conn
                .process_name
                .clone()
                .unwrap_or_else(|| format!("pid:{}", conn.pid.map_or(0, |p| p)));
            let entry = per_proc.entry((name, conn.pid)).or_insert_with(|| Agg {
                pid: conn.pid,
                rx_bytes: 0,
                tx_bytes: 0,
                rx_rate: 0.0,
                tx_rate: 0.0,
                conns: 0,
            });
            entry.conns += 1;

            // Per-socket byte accounting (TCP only — UDP/listen sockets lack
            // these counters and so contribute connections but no measured bytes).
            let (Some(rx), Some(tx)) = (conn.rx_bytes, conn.tx_bytes) else {
                continue;
            };
            let key = format!("{}|{}", conn.local_addr, conn.remote_addr);
            let (rx_delta, tx_delta) = match self.prev.get(&key) {
                Some(prev) => (rx.saturating_sub(prev.rx), tx.saturating_sub(prev.tx)),
                None => (0, 0), // first sighting: no baseline, count from next interval
            };
            next_prev.insert(key, SocketBytes { rx, tx });

            entry.rx_bytes += rx_delta;
            entry.tx_bytes += tx_delta;
            if elapsed > 0.0 {
                entry.rx_rate += rx_delta as f64 / elapsed;
                entry.tx_rate += tx_delta as f64 / elapsed;
            }
        }

        self.prev = next_prev;
        self.prev_time = Some(now);

        let mut ranked: Vec<ProcessBandwidth> = per_proc
            .into_iter()
            .map(|((process_name, _), a)| ProcessBandwidth {
                process_name,
                pid: a.pid,
                rx_bytes: a.rx_bytes,
                tx_bytes: a.tx_bytes,
                rx_rate: a.rx_rate,
                tx_rate: a.tx_rate,
                connection_count: a.conns,
            })
            .collect();

        ranked.sort_by(|a, b| {
            let bw_b = b.rx_rate + b.tx_rate;
            let bw_a = a.rx_rate + a.tx_rate;
            bw_b.partial_cmp(&bw_a).unwrap_or(std::cmp::Ordering::Equal)
        });
        ranked.truncate(max);
        ranked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(name: &str, pid: u32, state: &str) -> ConnectionDetail {
        ConnectionDetail {
            protocol: "TCP".into(),
            local_addr: "127.0.0.1:8080".into(),
            remote_addr: "10.0.0.1:443".into(),
            state: state.into(),
            pid: Some(pid),
            process_name: Some(name.into()),
            kernel_rtt_us: None,
            rx_bytes: None,
            tx_bytes: None,
        }
    }

    fn conn_bytes(name: &str, pid: u32, local: &str, rx: u64, tx: u64) -> ConnectionDetail {
        ConnectionDetail {
            protocol: "TCP".into(),
            local_addr: local.into(),
            remote_addr: "10.0.0.1:443".into(),
            state: "ESTABLISHED".into(),
            pid: Some(pid),
            process_name: Some(name.into()),
            kernel_rtt_us: None,
            rx_bytes: Some(rx),
            tx_bytes: Some(tx),
        }
    }

    #[test]
    fn tracker_first_sample_is_zero_rate() {
        let mut t = ProcessBandwidthTracker::new();
        let out = t.sample(&[conn_bytes("firefox", 1, "127.0.0.1:1", 1000, 500)], 10);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rx_rate, 0.0); // no baseline yet
        assert_eq!(out[0].connection_count, 1);
    }

    #[test]
    fn tracker_rates_by_real_socket_delta_not_connection_count() {
        let mut t = ProcessBandwidthTracker::new();
        // Baseline.
        t.sample(
            &[
                conn_bytes("firefox", 1, "127.0.0.1:1", 0, 0),
                conn_bytes("sshd", 2, "127.0.0.1:2", 0, 0),
            ],
            10,
        );
        // firefox moved 100KB rx, sshd moved 1KB rx — same connection count (1
        // each), but the proportional heuristic would have made them identical.
        let out = t.sample(
            &[
                conn_bytes("firefox", 1, "127.0.0.1:1", 100_000, 0),
                conn_bytes("sshd", 2, "127.0.0.1:2", 1_000, 0),
            ],
            10,
        );
        let firefox = out.iter().find(|p| p.process_name == "firefox").unwrap();
        let sshd = out.iter().find(|p| p.process_name == "sshd").unwrap();
        assert_eq!(firefox.connection_count, 1);
        assert_eq!(sshd.connection_count, 1);
        assert!(firefox.rx_rate > sshd.rx_rate * 50.0); // ~100x apart, not equal
        assert_eq!(firefox.rx_bytes, 100_000);
        assert_eq!(sshd.rx_bytes, 1_000);
    }

    #[test]
    fn tracker_ignores_non_established_and_sockets_without_bytes() {
        let mut t = ProcessBandwidthTracker::new();
        t.sample(&[conn_bytes("a", 1, "127.0.0.1:1", 0, 0)], 10);
        let out = t.sample(
            &[
                conn_bytes("a", 1, "127.0.0.1:1", 5_000, 0),
                conn("b", 2, "TIME_WAIT"), // wrong state → excluded entirely
                conn("c", 3, "ESTABLISHED"), // established but no byte counters
            ],
            10,
        );
        assert!(out.iter().any(|p| p.process_name == "a" && p.rx_bytes == 5_000));
        assert!(!out.iter().any(|p| p.process_name == "b"));
        // c is counted as a connection but contributes no measured bytes/rate.
        let c = out.iter().find(|p| p.process_name == "c").unwrap();
        assert_eq!(c.connection_count, 1);
        assert_eq!(c.rx_rate, 0.0);
    }

    fn iface(rx_rate: f64, tx_rate: f64) -> InterfaceMetric {
        InterfaceMetric {
            name: "en0".into(),
            is_up: true,
            rx_bytes: 1_000_000,
            tx_bytes: 500_000,
            rx_bytes_delta: 0,
            tx_bytes_delta: 0,
            rx_packets: 0,
            tx_packets: 0,
            rx_errors: 0,
            tx_errors: 0,
            rx_drops: 0,
            tx_drops: 0,
            rx_rate: Some(rx_rate),
            tx_rate: Some(tx_rate),
            rx_history: None,
            tx_history: None,
        }
    }

    #[test]
    fn empty_connections_produces_empty_ranking() {
        assert!(attribute(&[], &[iface(1000.0, 500.0)], 10).is_empty());
    }

    #[test]
    fn non_established_ignored() {
        let conns = vec![conn("firefox", 100, "TIME_WAIT")];
        assert!(attribute(&conns, &[iface(1000.0, 500.0)], 10).is_empty());
    }

    #[test]
    fn single_process_gets_all_bandwidth() {
        let conns = vec![conn("firefox", 100, "ESTABLISHED")];
        let ranked = attribute(&conns, &[iface(1000.0, 500.0)], 10);
        assert_eq!(ranked.len(), 1);
        assert!((ranked[0].rx_rate - 1000.0).abs() < 0.01);
        assert!((ranked[0].tx_rate - 500.0).abs() < 0.01);
    }

    #[test]
    fn bandwidth_split_proportionally() {
        let conns = vec![
            conn("firefox", 100, "ESTABLISHED"),
            conn("firefox", 100, "ESTABLISHED"),
            conn("firefox", 100, "ESTABLISHED"),
            conn("curl", 200, "ESTABLISHED"),
        ];
        let ranked = attribute(&conns, &[iface(1000.0, 500.0)], 10);
        let firefox = ranked.iter().find(|p| p.process_name == "firefox").unwrap();
        let curl = ranked.iter().find(|p| p.process_name == "curl").unwrap();
        assert_eq!(firefox.connection_count, 3);
        assert_eq!(curl.connection_count, 1);
        assert!((firefox.rx_rate - 750.0).abs() < 0.01);
        assert!((curl.rx_rate - 250.0).abs() < 0.01);
    }

    #[test]
    fn top_n_respects_max() {
        let conns: Vec<ConnectionDetail> = (0..20)
            .map(|i| conn(&format!("p{}", i), i as u32, "ESTABLISHED"))
            .collect();
        assert_eq!(attribute(&conns, &[iface(1000.0, 500.0)], 5).len(), 5);
    }
}
