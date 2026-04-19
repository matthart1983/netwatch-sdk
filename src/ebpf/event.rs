//! Decoded events delivered to userspace consumers.
//!
//! These types are the public face of the eBPF source. They differ from
//! the on-the-wire `netwatch_sdk_common::*Event` structs in two important
//! ways:
//!
//! 1. **Address fields are host byte order.** The kernel writes them in
//!    network byte order (matching `struct sock`); the userspace decoder
//!    converts before pushing onto the channel. Consumers should not have
//!    to think about endianness.
//! 2. **`comm` is a `String`.** The kernel writes a 16-byte NUL-padded
//!    array; userspace trims and validates UTF-8 once.

use chrono::{DateTime, TimeZone, Utc};

/// One event from the eBPF source. New variants will land in subsequent
/// roadmap phases (`AcceptEvent`, `CloseEvent`, `RetransmitEvent`, …).
#[derive(Debug, Clone)]
pub enum EbpfEvent {
    /// A `tcp_v4_connect` syscall fired in the kernel.
    Connect(ConnectEvent),
}

/// A successful connect attempt from a local TCP socket.
///
/// This corresponds to one entry in the kernel's `tcp_v4_connect` kprobe.
/// The event fires *before* the SYN is sent; whether the connection is
/// completed is observable via a future `inet_sock_set_state` event.
#[derive(Debug, Clone)]
pub struct ConnectEvent {
    /// Process group id of the calling task.
    pub tgid: u32,
    /// Thread id of the calling task.
    pub pid: u32,
    /// Process command (16-char `task_struct->comm`, NULs trimmed).
    pub comm: String,
    /// Source IPv4 address in host order. May be 0 if the socket has not
    /// been bound at the time the kprobe fires.
    pub saddr: std::net::Ipv4Addr,
    /// Destination IPv4 address in host order.
    pub daddr: std::net::Ipv4Addr,
    /// Source port in host order. **0 in Phase 1** — the source port is
    /// stored at an offset that requires CO-RE, which lands in a later
    /// iteration. See `crates/ebpf-programs/src/main.rs`.
    pub sport: u16,
    /// Destination port in host order.
    pub dport: u16,
    /// Capture timestamp (kernel boot-time clock, converted to wall-clock
    /// `DateTime<Utc>` by the userspace reader using the boot time).
    pub timestamp: DateTime<Utc>,
}

impl ConnectEvent {
    /// Decode a `netwatch_sdk_common::ConnectV4Event` from the BPF ring
    /// buffer into the public, host-byte-order representation.
    ///
    /// `boot_time` is the wall-clock instant when the kernel booted; we
    /// add the per-event `bpf_ktime_get_ns` to it to produce a usable
    /// timestamp.
    pub(crate) fn decode(
        raw: &netwatch_sdk_common::ConnectV4Event,
        boot_time: DateTime<Utc>,
    ) -> Self {
        let comm_end = raw
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(raw.comm.len());
        let comm = String::from_utf8_lossy(&raw.comm[..comm_end]).into_owned();

        // Address and port fields are stored in memory in network byte
        // order. Reading them back via `to_ne_bytes()` gives us those raw
        // bytes regardless of host endianness; we then re-interpret as
        // (a) an Ipv4Addr — which takes its bytes in IP-octet order — or
        // (b) a u16 from BE bytes for the port.
        let saddr = std::net::Ipv4Addr::from(raw.saddr.to_ne_bytes());
        let daddr = std::net::Ipv4Addr::from(raw.daddr.to_ne_bytes());
        let sport = u16::from_be_bytes(raw.sport.to_ne_bytes());
        let dport = u16::from_be_bytes(raw.dport.to_ne_bytes());

        let timestamp = boot_time + chrono::Duration::nanoseconds(raw.timestamp_ns as i64);

        Self {
            tgid: raw.tgid,
            pid: raw.pid,
            comm,
            saddr,
            daddr,
            sport,
            dport,
            timestamp,
        }
    }
}

/// Read kernel boot time as a wall-clock `DateTime<Utc>` so we can convert
/// `bpf_ktime_get_ns()` (boot-time monotonic) into wall-clock timestamps.
///
/// On Linux this would normally read `/proc/uptime` and subtract from now.
/// Cross-platform fallback: assume "now" is the boot time. That biases
/// every event by a small amount but keeps the API working on macOS where
/// the BPF source itself is unavailable.
#[allow(dead_code)]
pub(crate) fn estimate_boot_time() -> DateTime<Utc> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(uptime_str) = std::fs::read_to_string("/proc/uptime") {
            if let Some(secs_str) = uptime_str.split_whitespace().next() {
                if let Ok(secs) = secs_str.parse::<f64>() {
                    let now = Utc::now();
                    let boot_secs = secs as i64;
                    let boot_nanos = ((secs.fract()) * 1e9) as i64;
                    return now
                        - chrono::Duration::seconds(boot_secs)
                        - chrono::Duration::nanoseconds(boot_nanos);
                }
            }
        }
    }
    Utc.timestamp_opt(0, 0).single().unwrap_or_else(Utc::now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use netwatch_sdk_common::{ConnectV4Event, EventKind, COMM_LEN};

    #[test]
    fn decode_converts_addresses_and_ports_to_host_order() {
        let mut comm = [0u8; COMM_LEN];
        comm[..4].copy_from_slice(b"curl");
        let raw = ConnectV4Event {
            kind: EventKind::TcpV4Connect,
            _pad0: [0; 3],
            tgid: 1234,
            pid: 1235,
            // The kernel writes IP bytes in network order to the u32's
            // memory location. `from_ne_bytes` reproduces that layout
            // regardless of host endianness, so the test is portable.
            saddr: u32::from_ne_bytes([192, 168, 1, 10]),
            daddr: u32::from_ne_bytes([1, 1, 1, 1]),
            sport: 0,
            // Port 443 in network byte order is the bytes [0x01, 0xBB].
            dport: u16::from_ne_bytes([0x01, 0xBB]),
            comm,
            timestamp_ns: 1_000_000_000,
        };
        let boot = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let ev = ConnectEvent::decode(&raw, boot);

        assert_eq!(ev.pid, 1235);
        assert_eq!(ev.tgid, 1234);
        assert_eq!(ev.comm, "curl");
        assert_eq!(ev.saddr, std::net::Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(ev.daddr, std::net::Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(ev.dport, 443);
        // boot + 1s
        assert_eq!(ev.timestamp.timestamp(), 1_700_000_001);
    }

    #[test]
    fn decode_handles_short_comm_without_panicking() {
        let raw = ConnectV4Event::empty();
        let ev = ConnectEvent::decode(&raw, Utc::now());
        assert_eq!(ev.comm, "");
    }
}
