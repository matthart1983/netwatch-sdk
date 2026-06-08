use super::InterfaceStats;
use anyhow::Result;
use std::collections::HashMap;

/// Collect per-interface byte/packet counters and up/down state on macOS
/// entirely in-process via `sysctl(NET_RT_IFLIST2)` — the same source
/// `netstat -ib` reads, with 64-bit counters (`if_data64`).
///
/// This replaces the previous implementation, which forked `netstat -ibn`
/// once plus one `ifconfig <iface>` per interface on **every tick** — a dozen-
/// plus `posix_spawn`s per call that was the largest CPU cost for a daemon
/// left running. One syscall, no forks, same data.
pub fn collect_interface_stats() -> Result<HashMap<String, InterfaceStats>> {
    Ok(parse_iflist2(&sysctl_iflist2()?))
}

/// Fetch the raw `NET_RT_IFLIST2` route-table buffer via the standard two-call
/// sysctl dance: first call (null `oldp`) returns the required size, second
/// fills the buffer.
fn sysctl_iflist2() -> Result<Vec<u8>> {
    let mut mib: [libc::c_int; 6] = [
        libc::CTL_NET,
        libc::AF_ROUTE,
        0,
        0, // address family filter — 0 = all
        libc::NET_RT_IFLIST2,
        0,
    ];
    // SAFETY: `mib` is a valid 6-element control name. The first sysctl with a
    // null data pointer asks only for the size; the second fills `buf`, which is
    // sized to that length. `len` is updated in place and may shrink, so we
    // truncate to the value the kernel reports written.
    unsafe {
        let mut len: libc::size_t = 0;
        if libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut buf = vec![0u8; len];
        if libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        buf.truncate(len);
        Ok(buf)
    }
}

/// Walk a `NET_RT_IFLIST2` buffer into per-interface stats.
///
/// The buffer is a sequence of route messages, each prefixed by a common
/// header: `u_short msglen; u_char version; u_char type; …` (offsets 0, 2, 3
/// are ABI-stable across message kinds). We walk by `msglen` and, for each
/// `RTM_IFINFO2` message, read the 64-bit `if_data64` counters and flags from
/// the `if_msghdr2` header and the interface name from the `sockaddr_dl` that
/// immediately follows it. Non-interface messages (address records, etc.) are
/// skipped by length.
fn parse_iflist2(buf: &[u8]) -> HashMap<String, InterfaceStats> {
    let mut stats = HashMap::new();
    let hdr_size = std::mem::size_of::<libc::if_msghdr2>();
    let mut off = 0usize;

    while off + 4 <= buf.len() {
        // msglen (u16, host byte order) and type (u8) live at fixed offsets in
        // every route message header.
        let msglen = u16::from_ne_bytes([buf[off], buf[off + 1]]) as usize;
        if msglen < 4 || off + msglen > buf.len() {
            break;
        }
        let mtype = buf[off + 3] as libc::c_int;

        if mtype == libc::RTM_IFINFO2 && msglen >= hdr_size {
            // SAFETY: the message is at least `hdr_size` bytes (checked above)
            // and lies within `buf`. `read_unaligned` copies the header out
            // without assuming buffer alignment.
            let hdr: libc::if_msghdr2 = unsafe {
                std::ptr::read_unaligned(buf.as_ptr().add(off) as *const libc::if_msghdr2)
            };
            // The sockaddr_dl carrying the name follows the fixed header.
            if let Some(name) = sockaddr_dl_name(&buf[off + hdr_size..off + msglen]) {
                if name != "lo0" {
                    let d = &hdr.ifm_data;
                    let is_up = (hdr.ifm_flags & libc::IFF_UP) != 0
                        && (hdr.ifm_flags & libc::IFF_RUNNING) != 0;
                    stats.entry(name.clone()).or_insert(InterfaceStats {
                        name,
                        rx_bytes: d.ifi_ibytes,
                        tx_bytes: d.ifi_obytes,
                        rx_packets: d.ifi_ipackets,
                        tx_packets: d.ifi_opackets,
                        rx_errors: d.ifi_ierrors,
                        tx_errors: d.ifi_oerrors,
                        rx_drops: d.ifi_iqdrops,
                        tx_drops: 0, // if_data64 has no output-queue-drop counter
                        is_up,
                    });
                }
            }
        }
        off += msglen;
    }
    stats
}

/// Extract the interface name from a `sockaddr_dl` at the start of `bytes`.
///
/// `sockaddr_dl` layout: `sdl_len, sdl_family, sdl_index(2), sdl_type,
/// sdl_nlen, sdl_alen, sdl_slen` (8 bytes), then `sdl_data[]` holding the name
/// (`sdl_nlen` bytes) followed by the link-layer address. The name is *not*
/// NUL-terminated, so we slice exactly `sdl_nlen` bytes.
fn sockaddr_dl_name(bytes: &[u8]) -> Option<String> {
    const SDL_NLEN_OFF: usize = 5;
    const SDL_DATA_OFF: usize = 8;
    let nlen = *bytes.get(SDL_NLEN_OFF)? as usize;
    let name = bytes.get(SDL_DATA_OFF..SDL_DATA_OFF + nlen)?;
    Some(String::from_utf8_lossy(name).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_dl_name_reads_exactly_nlen_bytes() {
        // sdl_len, sdl_family, sdl_index(2), sdl_type, sdl_nlen=3, sdl_alen=6,
        // sdl_slen=0 (8 bytes), then "en0" + a 6-byte MAC. Name must be "en0".
        let mut b = vec![0u8; 8];
        b[5] = 3; // sdl_nlen
        b[6] = 6; // sdl_alen
        b.extend_from_slice(b"en0");
        b.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        assert_eq!(sockaddr_dl_name(&b).as_deref(), Some("en0"));
    }

    #[test]
    fn sockaddr_dl_name_handles_truncated_buffer() {
        assert_eq!(sockaddr_dl_name(&[0u8; 4]), None);
        // nlen claims 5 bytes but only 2 are present → None, no panic.
        let mut b = vec![0u8; 8];
        b[5] = 5;
        b.extend_from_slice(b"ab");
        assert_eq!(sockaddr_dl_name(&b), None);
    }

    #[test]
    fn collect_interface_stats_returns_real_interfaces_no_fork() {
        // Exercises the real sysctl path on the build host: at least one
        // non-loopback interface, and never the filtered lo0.
        let stats = collect_interface_stats().expect("sysctl NET_RT_IFLIST2 must succeed");
        assert!(!stats.is_empty(), "expected at least one interface");
        for (name, s) in &stats {
            assert_eq!(&s.name, name, "map key and stats.name must agree");
            assert_ne!(name, "lo0", "loopback must be filtered");
        }
    }
}
