# Platform support

`netwatch-sdk` targets Linux and macOS. Other Unix-likes compile, but most collectors return empty/`None`. Windows isn't supported yet.

## Capability matrix

| Collector / Feature                        | Linux                          | macOS                              | Other Unix     | Windows |
| ------------------------------------------ | ------------------------------ | ---------------------------------- | -------------- | ------- |
| Interface stats (`platform::collect_…`)    | `/sys/class/net`               | `netstat -ibn` + per-iface `ifconfig` | empty `HashMap` | n/a   |
| Interface rates (`InterfaceRateTracker`)   | derived                        | derived                            | derived (empty input) | n/a |
| TCP state counts                           | `/proc/net/tcp`(6)             | `netstat -an -p tcp`               | zeros          | n/a     |
| Full connection list with PID + RTT        | `ss -tunapi`                   | `lsof` + `nettop` (tcp4 RTT only)  | empty          | n/a     |
| Process bandwidth attribution              | yes                            | yes                                | yes (empty input → empty output) | n/a |
| Network intel detectors                    | yes (caller feeds events)      | yes (caller feeds events)          | yes            | n/a     |
| DNS analytics                              | yes                            | yes                                | yes            | n/a     |
| Gateway / DNS detection                    | `ip route`, `/etc/resolv.conf` | `netstat -rn`, `/etc/resolv.conf`  | partial        | n/a     |
| Ping (`run_ping`)                          | system `ping`                  | system `ping`                      | system `ping`  | n/a     |
| Disk usage                                 | `/proc/mounts` + `statvfs`     | `mount` + `statvfs` (skips firmlinks) | partial      | n/a     |
| Disk I/O                                   | `/proc/diskstats`              | _not implemented (`None`)_         | `None`         | n/a     |
| CPU model + cores                          | `/proc/cpuinfo` (+ `lscpu`)    | `sysctl machdep.cpu.brand_string`  | partial        | n/a     |
| CPU usage % (aggregate)                    | `/proc/stat` × 2 (200 ms gap)  | `ps -A -o %cpu` × 2                | `None`         | n/a     |
| CPU per-core %                             | `/proc/stat` per cpuN          | _not implemented (`None`)_         | `None`         | n/a     |
| Memory                                     | `/proc/meminfo`                | `vm_stat`                          | `None`         | n/a     |
| Load average                               | `/proc/loadavg`                | `libc::getloadavg`                 | `None`         | n/a     |
| Swap                                       | `/proc/meminfo`                | `sysctl vm.swapusage`              | `None`         | n/a     |

## External binaries used

The SDK shells out to these standard tools. They're present by default on all supported distributions; the agent's deploy step should still verify availability.

| Tool      | Used by                                                | Linux package        | macOS source                    |
| --------- | ------------------------------------------------------ | -------------------- | ------------------------------- |
| `ss`      | `connections::collect_connections` (Linux)             | `iproute2`           | n/a                             |
| `lsof`    | `connections::collect_connections` (macOS)             | n/a                  | preinstalled                    |
| `nettop`  | `connections::merge_macos_rtt`                         | n/a                  | preinstalled                    |
| `netstat` | TCP states and macOS interfaces / routes               | `net-tools` / preinstalled | preinstalled                    |
| `ifconfig`| macOS per-interface `is_up`                            | n/a                  | preinstalled                    |
| `ip`      | `config::detect_gateway` (Linux)                       | `iproute2`           | n/a                             |
| `ping`    | `health::run_ping`                                     | `iputils-ping`       | preinstalled                    |
| `mount`   | `disk::collect_disk_usage` (macOS)                     | n/a                  | preinstalled                    |
| `vm_stat` | `system::read_memory` (macOS)                          | n/a                  | preinstalled                    |
| `sysctl`  | macOS CPU / memory / swap                              | n/a                  | preinstalled                    |
| `ps`      | `system::measure_cpu_usage` (macOS)                    | n/a                  | preinstalled                    |
| `lscpu`   | fallback for ARM CPU model on Linux                    | `util-linux`         | n/a                             |

## Privilege requirements

None of the collectors need root. Specifically:

- `ping` runs without setuid because we use the system binary, not raw sockets.
- `ss`, `lsof`, and `nettop` show only the calling user's connections unless the agent is elevated.

For full visibility (all PIDs, all sockets, every interface), run the agent under a privileged user. The SDK doesn't gate any code paths on UID — that's the caller's call.

## Adding a new platform

1. Add `src/platform/<os>.rs` exporting `pub fn collect_interface_stats() -> Result<HashMap<String, InterfaceStats>>`.
2. Wire it up in `src/platform/mod.rs` behind `#[cfg(target_os = "<os>")]`.
3. For each collector that's currently `#[cfg(target_os = "linux")]` / `#[cfg(target_os = "macos")]`, add a third arm (or fall through to the existing "unsupported" path, which is usually `None` / empty).

`extending.md` covers the full pattern with a worked example.
