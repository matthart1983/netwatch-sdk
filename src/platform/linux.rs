use super::InterfaceStats;
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn collect_interface_stats() -> Result<HashMap<String, InterfaceStats>> {
    collect_interface_stats_from(Path::new("/sys/class/net"))
}

/// Read interface counters from a sysfs-shaped tree rooted at `net_dir`.
///
/// Expects the same layout as `/sys/class/net`:
/// - one subdirectory per interface (its name is the interface name)
/// - each subdirectory contains a `statistics/` dir with `rx_bytes`,
///   `tx_bytes`, `rx_packets`, etc., and an `operstate` file at the top
///   level whose contents are `"up"` / `"down"` / `"unknown"`.
///
/// The loopback interface (`lo`) is skipped by name because the netwatch
/// wire format tracks only non-loopback interfaces.
///
/// Extracted into a helper so unit tests can drive it against a tempdir
/// without needing a real sysfs. The public `collect_interface_stats()`
/// wrapper forwards `/sys/class/net`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn collect_interface_stats_from(
    net_dir: &Path,
) -> Result<HashMap<String, InterfaceStats>> {
    let mut stats = HashMap::new();

    for entry in fs::read_dir(net_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();

        if name == "lo" {
            continue;
        }

        let base = net_dir.join(&name);
        let stat_dir = base.join("statistics");

        let read_stat = |file: &str| -> u64 {
            fs::read_to_string(stat_dir.join(file))
                .unwrap_or_default()
                .trim()
                .parse()
                .unwrap_or(0)
        };

        let is_up = fs::read_to_string(base.join("operstate"))
            .unwrap_or_default()
            .trim()
            == "up";

        stats.insert(
            name.clone(),
            InterfaceStats {
                name,
                rx_bytes: read_stat("rx_bytes"),
                tx_bytes: read_stat("tx_bytes"),
                rx_packets: read_stat("rx_packets"),
                tx_packets: read_stat("tx_packets"),
                rx_errors: read_stat("rx_errors"),
                tx_errors: read_stat("tx_errors"),
                rx_drops: read_stat("rx_dropped"),
                tx_drops: read_stat("tx_dropped"),
                is_up,
            },
        );
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Construct a minimal sysfs-shaped tree in `root` for one interface.
    fn make_iface(root: &Path, name: &str, operstate: &str, counters: &[(&str, &str)]) {
        let base = root.join(name);
        fs::create_dir_all(base.join("statistics")).unwrap();
        let mut f = fs::File::create(base.join("operstate")).unwrap();
        writeln!(f, "{operstate}").unwrap();
        for (key, value) in counters {
            let mut g = fs::File::create(base.join("statistics").join(key)).unwrap();
            write!(g, "{value}").unwrap();
        }
    }

    /// Return a fresh scratch dir unique to this test run. Cleaned up via
    /// Drop on the returned `TempDir`.
    fn scratch() -> tempfile::TempDir {
        tempfile::TempDir::new().expect("tempdir")
    }

    #[test]
    fn reads_counters_and_operstate_for_a_single_interface() {
        let td = scratch();
        make_iface(
            td.path(),
            "eth0",
            "up",
            &[
                ("rx_bytes", "1000"),
                ("tx_bytes", "500"),
                ("rx_packets", "10"),
                ("tx_packets", "5"),
                ("rx_errors", "0"),
                ("tx_errors", "0"),
                ("rx_dropped", "0"),
                ("tx_dropped", "0"),
            ],
        );
        let map = collect_interface_stats_from(td.path()).unwrap();
        assert_eq!(map.len(), 1);
        let s = &map["eth0"];
        assert_eq!(s.rx_bytes, 1000);
        assert_eq!(s.tx_bytes, 500);
        assert_eq!(s.rx_packets, 10);
        assert_eq!(s.tx_packets, 5);
        assert!(s.is_up);
    }

    #[test]
    fn skips_loopback_interface() {
        let td = scratch();
        make_iface(td.path(), "lo", "up", &[("rx_bytes", "42")]);
        make_iface(td.path(), "eth0", "up", &[("rx_bytes", "100")]);
        let map = collect_interface_stats_from(td.path()).unwrap();
        assert!(map.contains_key("eth0"));
        assert!(!map.contains_key("lo"));
    }

    #[test]
    fn defaults_missing_statistics_files_to_zero() {
        // Only rx_bytes is written; other counters fall through the
        // read_to_string().unwrap_or_default().parse().unwrap_or(0) path.
        let td = scratch();
        make_iface(td.path(), "wlan0", "down", &[("rx_bytes", "7")]);
        let map = collect_interface_stats_from(td.path()).unwrap();
        let s = &map["wlan0"];
        assert_eq!(s.rx_bytes, 7);
        assert_eq!(s.tx_bytes, 0);
        assert_eq!(s.rx_packets, 0);
        assert!(!s.is_up);
    }

    #[test]
    fn is_up_true_only_for_exact_up_operstate() {
        // The kernel publishes "unknown" for some virtual interfaces —
        // we report those as down.
        let td = scratch();
        make_iface(td.path(), "tun0", "unknown", &[("rx_bytes", "0")]);
        make_iface(td.path(), "tap0", "down", &[("rx_bytes", "0")]);
        make_iface(td.path(), "eth0", "up", &[("rx_bytes", "0")]);
        let map = collect_interface_stats_from(td.path()).unwrap();
        assert!(map["eth0"].is_up);
        assert!(!map["tun0"].is_up);
        assert!(!map["tap0"].is_up);
    }

    #[test]
    fn errors_when_root_does_not_exist() {
        let result = collect_interface_stats_from(Path::new("/nonexistent/sysclassnet"));
        assert!(result.is_err());
    }
}
