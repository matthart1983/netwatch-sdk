use std::fs;
use std::process::Command;

pub fn detect_gateway() -> Option<String> {
    // Linux: `ip route`
    if let Ok(output) = Command::new("ip").args(["route"]).output() {
        let text = String::from_utf8_lossy(&output.stdout);
        if let Some(gw) = parse_default_gateway_ip_route(&text) {
            return Some(gw);
        }
    }

    // macOS fallback: `netstat -rn`
    if let Ok(output) = Command::new("netstat").args(["-rn"]).output() {
        let text = String::from_utf8_lossy(&output.stdout);
        if let Some(gw) = parse_default_gateway_netstat(&text) {
            return Some(gw);
        }
    }

    None
}

pub fn detect_dns() -> Option<String> {
    fs::read_to_string("/etc/resolv.conf")
        .ok()
        .and_then(|s| parse_first_nameserver(&s))
}

/// Extract the IPv4 default gateway from the output of `ip route`.
///
/// Matches lines like:
///   `default via 192.168.1.1 dev eth0 proto dhcp metric 100`
///   `default via 10.0.0.1 dev wlp2s0`
/// IPv6 default routes (`default via fe80::1`) are returned unchanged — the
/// caller decides whether that's useful.
pub fn parse_default_gateway_ip_route(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("default via ") {
            return line.split_whitespace().nth(2).map(|s| s.to_string());
        }
    }
    None
}

/// Extract the default gateway from the output of `netstat -rn`.
///
/// macOS prints rows like:
///   `default            10.0.0.1           UGScg          en0`
/// Linux prints rows like:
///   `0.0.0.0         192.168.1.1     0.0.0.0         UG    100    0        0 eth0`
/// We accept either: the row starts with `default` (macOS / BSD) **or** the
/// row's first column is `0.0.0.0` (Linux `netstat -rn`). In both cases the
/// gateway address is the second whitespace-separated column.
pub fn parse_default_gateway_netstat(text: &str) -> Option<String> {
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 2 {
            continue;
        }
        if cols[0] == "default" || cols[0] == "0.0.0.0" {
            return Some(cols[1].to_string());
        }
    }
    None
}

/// Extract the first `nameserver` IP from the contents of `/etc/resolv.conf`.
///
/// Skips comments (`#` or `;`) and blank lines. Indented `nameserver` lines
/// are accepted (some configurations indent for readability).
pub fn parse_first_nameserver(text: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("nameserver") {
            // require whitespace after "nameserver" so "nameserverX" doesn't match
            let Some(rest) = rest.strip_prefix(|c: char| c.is_ascii_whitespace()) else {
                continue;
            };
            if let Some(addr) = rest.split_whitespace().next() {
                return Some(addr.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_route_picks_first_default() {
        let sample = "\
default via 192.168.1.1 dev wlp2s0 proto dhcp metric 600
192.168.1.0/24 dev wlp2s0 proto kernel scope link src 192.168.1.42
169.254.0.0/16 dev wlp2s0 scope link metric 1000
";
        assert_eq!(
            parse_default_gateway_ip_route(sample),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn ip_route_handles_minimal_default_line() {
        let sample = "default via 10.0.0.1 dev eth0\n";
        assert_eq!(
            parse_default_gateway_ip_route(sample),
            Some("10.0.0.1".to_string())
        );
    }

    #[test]
    fn ip_route_returns_none_when_no_default() {
        let sample = "\
192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.42
169.254.0.0/16 dev eth0 scope link metric 1000
";
        assert_eq!(parse_default_gateway_ip_route(sample), None);
    }

    #[test]
    fn ip_route_ignores_leading_whitespace() {
        // Some `ip route` variants prepend whitespace under certain options.
        let sample = "    default via 172.16.0.1 dev eth0\n";
        assert_eq!(
            parse_default_gateway_ip_route(sample),
            Some("172.16.0.1".to_string())
        );
    }

    #[test]
    fn netstat_parses_macos_routing_table() {
        let sample = "\
Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            10.0.0.1           UGScg          en0
127                127.0.0.1          UCS            lo0
";
        assert_eq!(
            parse_default_gateway_netstat(sample),
            Some("10.0.0.1".to_string())
        );
    }

    #[test]
    fn netstat_parses_linux_routing_table() {
        let sample = "\
Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
0.0.0.0         192.168.1.1     0.0.0.0         UG        0 0          0 eth0
192.168.1.0     0.0.0.0         255.255.255.0   U         0 0          0 eth0
";
        assert_eq!(
            parse_default_gateway_netstat(sample),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn netstat_returns_none_when_no_default() {
        let sample = "\
Routing tables
Destination        Gateway            Flags        Netif Expire
127                127.0.0.1          UCS            lo0
";
        assert_eq!(parse_default_gateway_netstat(sample), None);
    }

    #[test]
    fn nameserver_picks_first_uncommented() {
        let sample = "\
# generated by resolvconf
search example.com lan
nameserver 1.1.1.1
nameserver 8.8.8.8
options edns0
";
        assert_eq!(parse_first_nameserver(sample), Some("1.1.1.1".to_string()));
    }

    #[test]
    fn nameserver_skips_comments_and_blanks() {
        let sample = "\
# nameserver 9.9.9.9    <- commented out
;nameserver 8.8.4.4    <- BSD-style comment

nameserver 192.168.1.1
";
        assert_eq!(
            parse_first_nameserver(sample),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn nameserver_does_not_match_keyword_prefix() {
        // "nameserverX" is not "nameserver"
        let sample = "nameserverbogus 1.2.3.4\nnameserver 8.8.8.8\n";
        assert_eq!(parse_first_nameserver(sample), Some("8.8.8.8".to_string()));
    }

    #[test]
    fn nameserver_returns_none_on_empty_or_unrelated() {
        assert_eq!(parse_first_nameserver(""), None);
        assert_eq!(
            parse_first_nameserver("search example.com\noptions edns0\n"),
            None
        );
    }
}
