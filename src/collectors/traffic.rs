use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use crate::platform::{self, InterfaceStats};
use crate::types::InterfaceMetric;

/// Rolling window size for per-interface rate history, in samples.
pub const RATE_HISTORY_LEN: usize = 60;

struct PrevSample {
    stats: InterfaceStats,
    rx_history: VecDeque<u64>,
    tx_history: VecDeque<u64>,
}

/// Stateful tracker that turns cumulative interface counters into per-interface
/// `InterfaceMetric`s with rates and a rolling history.
///
/// The first call after construction produces metrics with `rx_rate`/`tx_rate`
/// set to `Some(0.0)` and empty history — rates become meaningful on the second
/// call when an elapsed interval is available.
pub struct InterfaceRateTracker {
    prev: HashMap<String, PrevSample>,
    prev_time: Option<Instant>,
}

impl Default for InterfaceRateTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl InterfaceRateTracker {
    pub fn new() -> Self {
        Self {
            prev: HashMap::new(),
            prev_time: None,
        }
    }

    /// Consume a fresh interface stats map and emit `InterfaceMetric`s.
    pub fn sample(&mut self, current: &HashMap<String, InterfaceStats>) -> Vec<InterfaceMetric> {
        let now = Instant::now();
        let elapsed = self
            .prev_time
            .map(|t| now.duration_since(t).as_secs_f64())
            .unwrap_or(0.0);

        let mut metrics = Vec::with_capacity(current.len());

        for (name, cur) in current {
            let prev = self.prev.get(name);

            let (rx_delta, tx_delta, rx_rate, tx_rate) = if let Some(prev) = prev {
                let rx_delta = cur.rx_bytes.saturating_sub(prev.stats.rx_bytes);
                let tx_delta = cur.tx_bytes.saturating_sub(prev.stats.tx_bytes);
                let (rx_rate, tx_rate) = if elapsed > 0.0 {
                    (rx_delta as f64 / elapsed, tx_delta as f64 / elapsed)
                } else {
                    (0.0, 0.0)
                };
                (rx_delta, tx_delta, rx_rate, tx_rate)
            } else {
                (0, 0, 0.0, 0.0)
            };

            let mut rx_history = prev
                .map(|p| p.rx_history.clone())
                .unwrap_or_else(|| VecDeque::with_capacity(RATE_HISTORY_LEN));
            let mut tx_history = prev
                .map(|p| p.tx_history.clone())
                .unwrap_or_else(|| VecDeque::with_capacity(RATE_HISTORY_LEN));

            if self.prev_time.is_some() {
                rx_history.push_back(rx_rate as u64);
                tx_history.push_back(tx_rate as u64);
                if rx_history.len() > RATE_HISTORY_LEN {
                    rx_history.pop_front();
                }
                if tx_history.len() > RATE_HISTORY_LEN {
                    tx_history.pop_front();
                }
            }

            metrics.push(InterfaceMetric {
                name: name.clone(),
                is_up: cur.is_up,
                rx_bytes: cur.rx_bytes,
                tx_bytes: cur.tx_bytes,
                rx_bytes_delta: rx_delta,
                tx_bytes_delta: tx_delta,
                rx_packets: cur.rx_packets,
                tx_packets: cur.tx_packets,
                rx_errors: cur.rx_errors,
                tx_errors: cur.tx_errors,
                rx_drops: cur.rx_drops,
                tx_drops: cur.tx_drops,
                rx_rate: Some(rx_rate),
                tx_rate: Some(tx_rate),
                rx_history: if rx_history.is_empty() {
                    None
                } else {
                    Some(rx_history.iter().copied().collect())
                },
                tx_history: if tx_history.is_empty() {
                    None
                } else {
                    Some(tx_history.iter().copied().collect())
                },
            });

            self.prev.insert(
                name.clone(),
                PrevSample {
                    stats: cur.clone(),
                    rx_history,
                    tx_history,
                },
            );
        }

        // Drop interfaces that disappeared (renamed, unplugged, etc.).
        self.prev.retain(|name, _| current.contains_key(name));

        self.prev_time = Some(now);
        metrics.sort_by(|a, b| a.name.cmp(&b.name));
        metrics
    }
}

/// Convenience wrapper — pulls fresh stats from the platform backend and runs
/// them through the tracker.
pub fn sample(tracker: &mut InterfaceRateTracker) -> anyhow::Result<Vec<InterfaceMetric>> {
    let stats = platform::collect_interface_stats()?;
    Ok(tracker.sample(&stats))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(name: &str, rx: u64, tx: u64) -> (String, InterfaceStats) {
        (
            name.into(),
            InterfaceStats {
                name: name.into(),
                rx_bytes: rx,
                tx_bytes: tx,
                rx_packets: 0,
                tx_packets: 0,
                rx_errors: 0,
                tx_errors: 0,
                rx_drops: 0,
                tx_drops: 0,
                is_up: true,
            },
        )
    }

    #[test]
    fn first_sample_has_zero_rate_and_no_history() {
        let mut tracker = InterfaceRateTracker::new();
        let mut map = HashMap::new();
        let (n, s) = stat("en0", 100, 200);
        map.insert(n, s);
        let metrics = tracker.sample(&map);
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].rx_rate, Some(0.0));
        assert_eq!(metrics[0].rx_history, None);
    }

    #[test]
    fn second_sample_records_history() {
        let mut tracker = InterfaceRateTracker::new();
        let mut m1 = HashMap::new();
        let (n, s) = stat("en0", 0, 0);
        m1.insert(n, s);
        tracker.sample(&m1);
        std::thread::sleep(std::time::Duration::from_millis(20));
        let mut m2 = HashMap::new();
        let (n, s) = stat("en0", 1000, 2000);
        m2.insert(n, s);
        let metrics = tracker.sample(&m2);
        assert_eq!(metrics[0].rx_bytes_delta, 1000);
        assert_eq!(metrics[0].tx_bytes_delta, 2000);
        assert!(metrics[0].rx_rate.unwrap() > 0.0);
        assert_eq!(metrics[0].rx_history.as_ref().map(|v| v.len()), Some(1));
    }

    #[test]
    fn history_is_capped_at_window_length() {
        let mut tracker = InterfaceRateTracker::new();
        for i in 0..(RATE_HISTORY_LEN + 10) {
            let mut m = HashMap::new();
            let (n, s) = stat("en0", (i as u64) * 100, 0);
            m.insert(n, s);
            tracker.sample(&m);
        }
        // After the first sample we had no history; every subsequent sample
        // appends once. So we should be clamped to RATE_HISTORY_LEN.
        let mut m = HashMap::new();
        let (n, s) = stat("en0", 999_999, 0);
        m.insert(n, s);
        let metrics = tracker.sample(&m);
        assert_eq!(
            metrics[0].rx_history.as_ref().map(|v| v.len()),
            Some(RATE_HISTORY_LEN)
        );
    }

    #[test]
    fn disappearing_interface_is_evicted() {
        let mut tracker = InterfaceRateTracker::new();
        let mut m1 = HashMap::new();
        let (n, s) = stat("en0", 100, 200);
        m1.insert(n, s);
        tracker.sample(&m1);
        assert!(tracker.prev.contains_key("en0"));

        let mut m2 = HashMap::new();
        let (n, s) = stat("en1", 0, 0);
        m2.insert(n, s);
        tracker.sample(&m2);
        assert!(!tracker.prev.contains_key("en0"));
        assert!(tracker.prev.contains_key("en1"));
    }
}
