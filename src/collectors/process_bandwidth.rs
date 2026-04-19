use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
        }
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
