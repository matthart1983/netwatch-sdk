use serde::{Deserialize, Serialize};

/// Count established TCP connections from /proc/net/tcp and /proc/net/tcp6.
/// State 01 = ESTABLISHED in the hex-encoded state field.
#[cfg(target_os = "linux")]
pub fn count_established_connections() -> u32 {
    let count_file = |path: &str| -> u32 {
        let Ok(contents) = std::fs::read_to_string(path) else {
            return 0;
        };
        contents
            .lines()
            .skip(1) // header
            .filter(|line| {
                line.split_whitespace()
                    .nth(3)
                    .map(|st| st == "01")
                    .unwrap_or(false)
            })
            .count() as u32
    };

    count_file("/proc/net/tcp") + count_file("/proc/net/tcp6")
}

#[cfg(target_os = "macos")]
pub fn count_established_connections() -> u32 {
    let output = std::process::Command::new("netstat")
        .args(["-an", "-p", "tcp"])
        .output();
    let Ok(output) = output else { return 0 };
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .filter(|l| l.contains("ESTABLISHED"))
        .count() as u32
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn count_established_connections() -> u32 {
    0
}

#[derive(Debug, Clone)]
pub struct TcpStates {
    pub established: u32,
    pub time_wait: u32,
    pub close_wait: u32,
}

#[cfg(target_os = "linux")]
pub fn collect_tcp_states() -> TcpStates {
    let count_states = |path: &str| -> (u32, u32, u32) {
        let Ok(contents) = std::fs::read_to_string(path) else {
            return (0, 0, 0);
        };
        let mut established = 0u32;
        let mut time_wait = 0u32;
        let mut close_wait = 0u32;
        for line in contents.lines().skip(1) {
            if let Some(st) = line.split_whitespace().nth(3) {
                match st {
                    "01" => established += 1,
                    "06" => time_wait += 1,
                    "08" => close_wait += 1,
                    _ => {}
                }
            }
        }
        (established, time_wait, close_wait)
    };

    let (e4, tw4, cw4) = count_states("/proc/net/tcp");
    let (e6, tw6, cw6) = count_states("/proc/net/tcp6");

    TcpStates {
        established: e4 + e6,
        time_wait: tw4 + tw6,
        close_wait: cw4 + cw6,
    }
}

#[cfg(target_os = "macos")]
pub fn collect_tcp_states() -> TcpStates {
    let output = std::process::Command::new("netstat")
        .args(["-an", "-p", "tcp"])
        .output();
    let Ok(output) = output else {
        return TcpStates {
            established: 0,
            time_wait: 0,
            close_wait: 0,
        };
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut established = 0u32;
    let mut time_wait = 0u32;
    let mut close_wait = 0u32;
    for line in text.lines() {
        if line.contains("ESTABLISHED") {
            established += 1;
        } else if line.contains("TIME_WAIT") {
            time_wait += 1;
        } else if line.contains("CLOSE_WAIT") {
            close_wait += 1;
        }
    }
    TcpStates {
        established,
        time_wait,
        close_wait,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn collect_tcp_states() -> TcpStates {
    TcpStates {
        established: 0,
        time_wait: 0,
        close_wait: 0,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionDetail {
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    /// Kernel-measured smoothed RTT in microseconds (from eBPF tcp_probe on Linux).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_rtt_us: Option<f64>,
}

/// Collect the full list of connections with process attribution.
/// Uses `ss` on Linux and `lsof` on macOS. Returns an empty Vec on unsupported
/// platforms or when the underlying command is missing.
pub fn collect_connections() -> Vec<ConnectionDetail> {
    #[cfg(target_os = "linux")]
    {
        parse_linux_connections()
    }
    #[cfg(target_os = "macos")]
    {
        let mut conns = parse_lsof();
        merge_macos_rtt(&mut conns);
        conns
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Vec::new()
    }
}

#[cfg(target_os = "macos")]
fn merge_macos_rtt(connections: &mut [ConnectionDetail]) {
    let Ok(output) = std::process::Command::new("nettop")
        .args(["-x", "-n", "-m", "tcp", "-l", "1"])
        .output()
    else {
        return;
    };
    let rtt_map = parse_nettop_output(&String::from_utf8_lossy(&output.stdout));
    for c in connections.iter_mut() {
        if let Some(rtt) = rtt_map.get(&(c.local_addr.clone(), c.remote_addr.clone())) {
            c.kernel_rtt_us = Some(*rtt);
        }
    }
}

/// Parse `nettop -x -n -m tcp -l 1` output. Returns a map keyed by
/// (local_addr, remote_addr) in the same string form lsof produces, with
/// RTT in microseconds.
///
/// Example row:
///   `    tcp4 127.0.0.1:65448<->127.0.0.1:55679   lo0   Established   4836   3844   0   0   0   1.22 ms   ...`
///
/// We only handle `tcp4` rows — IPv6 address syntax differs between nettop
/// (`fe80::xxx%scope.port`) and lsof and needs normalization we're skipping
/// for this MVP.
pub(crate) fn parse_nettop_output(text: &str) -> std::collections::HashMap<(String, String), f64> {
    use std::collections::HashMap;
    let mut map: HashMap<(String, String), f64> = HashMap::new();

    for raw in text.lines() {
        let tokens: Vec<&str> = raw.split_whitespace().collect();
        // `tcp4` can be the first token or appear after a leading timestamp
        // (nettop `-x` prefixes each row with `HH:MM:SS.ffffff`).
        let Some(idx) = tokens.iter().position(|&t| t == "tcp4") else {
            continue;
        };
        let Some(pair) = tokens.get(idx + 1) else {
            continue;
        };
        let Some((local, remote)) = pair.split_once("<->") else {
            continue;
        };
        if local.contains('*') || remote.contains('*') {
            // Listen sockets and wildcards — no RTT anyway.
            continue;
        }

        // Find `<number> ms` somewhere later on the line.
        let rtt_us = tokens[idx + 2..]
            .windows(2)
            .find_map(|w| {
                if w[1] == "ms" {
                    w[0].parse::<f64>().ok().filter(|&v| v > 0.0).map(|v| v * 1000.0)
                } else {
                    None
                }
            });

        if let Some(rtt_us) = rtt_us {
            map.insert((local.to_string(), remote.to_string()), rtt_us);
        }
    }

    map
}

#[cfg(target_os = "linux")]
fn parse_linux_connections() -> Vec<ConnectionDetail> {
    // `-i` emits a continuation line per connection with kernel TCP info
    // (rtt, cwnd, mss, …). We parse it to populate kernel_rtt_us.
    let Ok(output) = std::process::Command::new("ss").args(["-tunapi"]).output() else {
        return Vec::new();
    };
    parse_ss_output(&String::from_utf8_lossy(&output.stdout))
}

/// Parse the output of `ss -tunapi`. Pure function — no I/O, no platform
/// dependencies — so we can unit-test it on any host.
pub(crate) fn parse_ss_output(text: &str) -> Vec<ConnectionDetail> {
    let mut connections: Vec<ConnectionDetail> = Vec::new();

    for line in text.lines().skip(1) {
        // Continuation lines (kernel TCP info from `-i`) start with
        // whitespace and contain tokens like `rtt:X.X/Y.Y`.
        if line.starts_with(|c: char| c.is_whitespace()) {
            if let Some(rtt_us) = parse_ss_rtt_us(line) {
                if let Some(last) = connections.last_mut() {
                    last.kernel_rtt_us = Some(rtt_us);
                }
            }
            continue;
        }

        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 {
            continue;
        }

        let protocol = cols[0].to_uppercase();
        let state = match cols[1] {
            "ESTAB" => "ESTABLISHED".to_string(),
            other => other.to_string(),
        };
        let local_addr = cols[4].to_string();
        let remote_addr = cols[5].to_string();

        let (pid, process_name) = if cols.len() > 6 {
            parse_ss_process(cols[6])
        } else {
            (None, None)
        };

        connections.push(ConnectionDetail {
            protocol,
            local_addr,
            remote_addr,
            state,
            pid,
            process_name,
            kernel_rtt_us: None,
        });
    }

    connections
}

/// Extract `rtt:X.Y` (milliseconds) from an `ss -i` continuation line and
/// return it as microseconds. Returns None if not found or unparseable.
fn parse_ss_rtt_us(line: &str) -> Option<f64> {
    for token in line.split_whitespace() {
        if let Some(rest) = token.strip_prefix("rtt:") {
            // Format is `rtt:srtt_ms/mdev_ms` — we only want SRTT.
            let srtt_ms: f64 = rest.split('/').next()?.parse().ok()?;
            return Some(srtt_ms * 1000.0);
        }
    }
    None
}

fn parse_ss_process(field: &str) -> (Option<u32>, Option<String>) {
    // Format: users:(("process",pid=1234,fd=3))
    let name = field.split('"').nth(1).map(|s| s.to_string());
    let pid = field
        .split("pid=")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.parse().ok());
    (pid, name)
}

#[cfg(target_os = "macos")]
fn parse_lsof() -> Vec<ConnectionDetail> {
    let Ok(output) = std::process::Command::new("lsof")
        .args(["-i", "-n", "-P", "-F", "pcPtTn"])
        .output()
    else {
        return Vec::new();
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut connections = Vec::new();

    let mut pid: Option<u32> = None;
    let mut process_name: Option<String> = None;
    let mut protocol = String::new();
    let mut state = String::new();
    let mut local_addr = String::new();
    let mut remote_addr = String::new();
    let mut has_network = false;

    let flush = |connections: &mut Vec<ConnectionDetail>,
                 has_network: &mut bool,
                 protocol: &str,
                 local_addr: &str,
                 remote_addr: &str,
                 state: &str,
                 pid: Option<u32>,
                 process_name: &Option<String>| {
        if *has_network {
            connections.push(ConnectionDetail {
                protocol: protocol.to_string(),
                local_addr: local_addr.to_string(),
                remote_addr: remote_addr.to_string(),
                state: state.to_string(),
                pid,
                process_name: process_name.clone(),
                kernel_rtt_us: None,
            });
            *has_network = false;
        }
    };

    for line in text.lines() {
        if line.is_empty() {
            continue;
        }

        let tag = line.as_bytes()[0];
        let value = &line[1..];

        match tag {
            b'p' => {
                flush(
                    &mut connections,
                    &mut has_network,
                    &protocol,
                    &local_addr,
                    &remote_addr,
                    &state,
                    pid,
                    &process_name,
                );
                pid = value.parse().ok();
                process_name = None;
            }
            b'c' => {
                process_name = Some(value.to_string());
            }
            b'f' => {
                flush(
                    &mut connections,
                    &mut has_network,
                    &protocol,
                    &local_addr,
                    &remote_addr,
                    &state,
                    pid,
                    &process_name,
                );
                protocol = String::new();
                state = String::new();
            }
            b'P' => {
                protocol = value.to_string();
            }
            b'T' => {
                if let Some(st) = value.strip_prefix("ST=") {
                    state = st.to_string();
                }
            }
            b'n' => {
                if let Some(arrow_pos) = value.find("->") {
                    local_addr = value[..arrow_pos]
                        .trim_matches(|c| c == '[' || c == ']')
                        .to_string();
                    remote_addr = value[arrow_pos + 2..]
                        .trim_matches(|c| c == '[' || c == ']')
                        .to_string();
                } else {
                    local_addr = value.to_string();
                    remote_addr = "*:*".to_string();
                };
                has_network = true;
            }
            _ => {}
        }
    }

    flush(
        &mut connections,
        &mut has_network,
        &protocol,
        &local_addr,
        &remote_addr,
        &state,
        pid,
        &process_name,
    );

    connections
}

/// Rank connections by likely importance and cap the list to `max`.
/// ESTABLISHED connections are preferred; otherwise keep insertion order.
pub fn top_connections(mut conns: Vec<ConnectionDetail>, max: usize) -> Vec<ConnectionDetail> {
    conns.sort_by_key(|c| if c.state == "ESTABLISHED" { 0 } else { 1 });
    conns.truncate(max);
    conns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_connections_prefers_established() {
        let input = vec![
            ConnectionDetail {
                protocol: "TCP".into(),
                local_addr: "1".into(),
                remote_addr: "a".into(),
                state: "TIME_WAIT".into(),
                pid: None,
                process_name: None,
                kernel_rtt_us: None,
            },
            ConnectionDetail {
                protocol: "TCP".into(),
                local_addr: "2".into(),
                remote_addr: "b".into(),
                state: "ESTABLISHED".into(),
                pid: None,
                process_name: None,
                kernel_rtt_us: None,
            },
        ];
        let ranked = top_connections(input, 10);
        assert_eq!(ranked[0].state, "ESTABLISHED");
    }

    #[test]
    fn parse_ss_output_basic() {
        // Representative `ss -tunapi` output: header, two connections, one
        // with a continuation line carrying kernel tcp_info.
        let text = "\
Netid State    Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   ESTAB    0      0      10.0.0.1:12345      10.0.0.2:443      users:((\"curl\",pid=100,fd=3))
\t cubic wscale:7,7 rto:204 rtt:2.123/1.456 ato:40 mss:1460 cwnd:10
udp   UNCONN   0      0      0.0.0.0:53          0.0.0.0:*         users:((\"dnsmasq\",pid=200,fd=5))
";
        let conns = parse_ss_output(text);
        assert_eq!(conns.len(), 2);
        assert_eq!(conns[0].state, "ESTABLISHED");
        assert_eq!(conns[0].process_name.as_deref(), Some("curl"));
        assert_eq!(conns[0].kernel_rtt_us, Some(2123.0));
        assert_eq!(conns[1].protocol, "UDP");
        assert_eq!(conns[1].kernel_rtt_us, None);
    }

    #[test]
    fn parse_ss_output_handles_missing_rtt() {
        // ESTAB connection with a continuation line but no rtt token.
        let text = "\
Netid State    Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   ESTAB    0      0      10.0.0.1:12345      10.0.0.2:443      users:((\"curl\",pid=100,fd=3))
\t cubic wscale:7,7 rto:204 ato:40 mss:1460 cwnd:10
";
        let conns = parse_ss_output(text);
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].kernel_rtt_us, None);
    }

    #[test]
    fn parse_ss_output_attaches_rtt_to_correct_connection() {
        // Two ESTAB connections each with their own continuation line.
        // Verify RTTs don't cross-pollinate.
        let text = "\
Netid State    Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   ESTAB    0      0      10.0.0.1:1          10.0.0.2:443      users:((\"a\",pid=1,fd=3))
\t rtt:10.0/1.0 mss:1460
tcp   ESTAB    0      0      10.0.0.1:2          10.0.0.3:443      users:((\"b\",pid=2,fd=3))
\t rtt:200.5/50.0 mss:1460
";
        let conns = parse_ss_output(text);
        assert_eq!(conns.len(), 2);
        assert_eq!(conns[0].kernel_rtt_us, Some(10_000.0));
        assert_eq!(conns[1].kernel_rtt_us, Some(200_500.0));
    }

    #[test]
    fn parse_nettop_basic() {
        let sample = "\
time                               interface     state     bytes_in   bytes_out   rx_dupe  rx_ooo   re-tx  rtt_avg   rcvsize  ...
09:31:19.605231 kernel_task.0                                                                 4836        3844        0        0        0
09:31:19.597940    tcp4 127.0.0.1:65448<->127.0.0.1:55679  lo0  Established  4836  3844  0  0  0  1.22 ms  6291456  405248  BE  -  cubic - - - -  so
09:31:19.605279 ControlCenter.589                                                                 0           0        0        0        0
09:31:19.587706    tcp4 *:7000<->*:*                                         Listen
09:31:19.605271 apsd.354                                                                      8208255      5803656  68973  71164  53756
09:31:19.585876    tcp4 192.168.0.213:53077<->17.57.145.38:5223  en0  Established  8208255  5803656  68973  71164  53756  154.16 ms  223744  2950016  RD  -  cubic - - - -  ch
";
        let map = parse_nettop_output(sample);
        assert_eq!(map.len(), 2);
        let lo = map
            .get(&("127.0.0.1:65448".to_string(), "127.0.0.1:55679".to_string()))
            .copied()
            .expect("loopback row");
        assert!((lo - 1220.0).abs() < 0.1, "got {}", lo);
        let wan = map
            .get(&("192.168.0.213:53077".to_string(), "17.57.145.38:5223".to_string()))
            .copied()
            .expect("en0 row");
        assert!((wan - 154_160.0).abs() < 1.0, "got {}", wan);
    }

    #[test]
    fn parse_nettop_skips_listen_and_missing_rtt() {
        let sample = "\
tcp4 *:7000<->*:*                  Listen
tcp4 10.0.0.1:1<->10.0.0.2:2  en0  Established  0 0 0 0 0
";
        let map = parse_nettop_output(sample);
        assert!(map.is_empty());
    }

    #[test]
    fn parse_nettop_ignores_tcp6() {
        // IPv6 nettop syntax differs from lsof; skipping for MVP.
        let sample = "\
tcp6 fe80::1%utun4.1024<->fe80::2%utun4.1024  utun4  Established  0 0 0 0 0  12.34 ms
";
        let map = parse_nettop_output(sample);
        assert!(map.is_empty());
    }

    #[test]
    fn top_connections_caps_length() {
        let conns: Vec<ConnectionDetail> = (0..50)
            .map(|i| ConnectionDetail {
                protocol: "TCP".into(),
                local_addr: format!("{}", i),
                remote_addr: "a".into(),
                state: "ESTABLISHED".into(),
                pid: None,
                process_name: None,
                kernel_rtt_us: None,
            })
            .collect();
        assert_eq!(top_connections(conns, 10).len(), 10);
    }
}
