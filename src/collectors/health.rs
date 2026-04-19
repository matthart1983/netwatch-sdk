use std::collections::VecDeque;
use std::process::Command;

/// Rolling window size for gateway/DNS RTT history, in samples.
pub const RTT_HISTORY_LEN: usize = 60;

pub struct PingResult {
    pub rtt_ms: Option<f64>,
    pub loss_pct: f64,
}

/// Tracks a rolling window of RTT samples (None when a probe failed or was
/// skipped). Consumers push one sample per collection cycle and read back the
/// full window for wire serialization.
#[derive(Debug, Default)]
pub struct RttHistory {
    samples: VecDeque<Option<f64>>,
}

impl RttHistory {
    pub fn new() -> Self {
        Self {
            samples: VecDeque::with_capacity(RTT_HISTORY_LEN),
        }
    }

    pub fn push(&mut self, rtt_ms: Option<f64>) {
        self.samples.push_back(rtt_ms);
        if self.samples.len() > RTT_HISTORY_LEN {
            self.samples.pop_front();
        }
    }

    pub fn snapshot(&self) -> Vec<Option<f64>> {
        self.samples.iter().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }
}

pub fn run_ping(target: &str) -> PingResult {
    let output = match Command::new("ping")
        .args(["-c", "3", "-W", "1", target])
        .output()
    {
        Ok(o) => o,
        Err(_) => {
            return PingResult {
                rtt_ms: None,
                loss_pct: 100.0,
            }
        }
    };

    let text = String::from_utf8_lossy(&output.stdout);
    PingResult {
        rtt_ms: parse_avg_rtt(&text),
        loss_pct: parse_loss(&text),
    }
}

fn parse_loss(output: &str) -> f64 {
    for line in output.lines() {
        if line.contains("packet loss") || line.contains("% loss") {
            for part in line.split_whitespace() {
                if part.ends_with('%') {
                    if let Ok(val) = part.trim_end_matches('%').parse::<f64>() {
                        return val;
                    }
                }
            }
            for segment in line.split(',') {
                let trimmed = segment.trim();
                if trimmed.contains("% packet loss") || trimmed.contains("% loss") {
                    if let Some(pct_str) = trimmed.split('%').next() {
                        let pct_str = pct_str.trim();
                        if let Ok(val) = pct_str.parse::<f64>() {
                            return val;
                        }
                        if let Some(last_word) = pct_str.split_whitespace().last() {
                            let cleaned = last_word.trim_start_matches('(');
                            if let Ok(val) = cleaned.parse::<f64>() {
                                return val;
                            }
                        }
                    }
                }
            }
        }
    }
    100.0
}

fn parse_avg_rtt(output: &str) -> Option<f64> {
    for line in output.lines() {
        if line.contains("min/avg/max") || line.contains("rtt min/avg/max") {
            if let Some(stats) = line.split('=').nth(1) {
                let parts: Vec<&str> = stats.trim().split('/').collect();
                if parts.len() >= 2 {
                    return parts[1].trim().parse().ok();
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_loss_zero() {
        let output = "3 packets transmitted, 3 received, 0% packet loss, time 2003ms";
        assert_eq!(parse_loss(output), 0.0);
    }

    #[test]
    fn parse_loss_partial() {
        let output = "3 packets transmitted, 1 received, 66.7% packet loss, time 2003ms";
        assert_eq!(parse_loss(output), 66.7);
    }

    #[test]
    fn parse_loss_full() {
        let output = "3 packets transmitted, 0 received, 100% packet loss, time 2003ms";
        assert_eq!(parse_loss(output), 100.0);
    }

    #[test]
    fn parse_loss_empty() {
        assert_eq!(parse_loss(""), 100.0);
    }

    #[test]
    fn parse_avg_rtt_linux() {
        let output = "rtt min/avg/max/mdev = 0.123/0.456/0.789/0.111 ms";
        assert_eq!(parse_avg_rtt(output), Some(0.456));
    }

    #[test]
    fn parse_avg_rtt_empty() {
        assert_eq!(parse_avg_rtt(""), None);
    }

    #[test]
    fn rtt_history_caps_at_window() {
        let mut h = RttHistory::new();
        for i in 0..(RTT_HISTORY_LEN + 5) {
            h.push(Some(i as f64));
        }
        assert_eq!(h.len(), RTT_HISTORY_LEN);
        let snap = h.snapshot();
        // Oldest sample should have been evicted.
        assert_eq!(snap.first(), Some(&Some(5.0)));
    }

    #[test]
    fn rtt_history_preserves_none_samples() {
        let mut h = RttHistory::new();
        h.push(Some(10.0));
        h.push(None);
        h.push(Some(20.0));
        assert_eq!(h.snapshot(), vec![Some(10.0), None, Some(20.0)]);
    }
}
