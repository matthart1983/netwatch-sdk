use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskUsage {
    pub mount_point: String,
    pub device: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub usage_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskIo {
    pub read_bytes: u64,
    pub write_bytes: u64,
}

/// A device-backed mount discovered from `/proc/mounts` or `mount`.
/// Pure intermediate type — kept module-private so we can rework it later
/// without affecting consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MountEntry {
    pub device: String,
    pub mount_point: String,
}

/// Filesystems that live entirely in the kernel — never have meaningful
/// `statvfs` numbers and shouldn't appear in disk-usage output.
const VIRTUAL_FS: &[&str] = &[
    "proc",
    "sysfs",
    "devpts",
    "tmpfs",
    "devtmpfs",
    "cgroup",
    "cgroup2",
    "pstore",
    "securityfs",
    "debugfs",
    "configfs",
    "fusectl",
    "mqueue",
    "hugetlbfs",
    "autofs",
    "rpc_pipefs",
    "nfsd",
    "binfmt_misc",
    "tracefs",
    "squashfs",
    "overlay",
    "ramfs",
    "efivarfs",
];

/// Parse `/proc/mounts` (Linux) into a list of mounts backed by a real
/// `/dev/...` device, skipping in-kernel virtual filesystems.
pub fn parse_proc_mounts(text: &str) -> Vec<MountEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let device = parts[0];
        let mount_point = parts[1];
        let fs_type = parts[2];

        if !device.starts_with("/dev/") || VIRTUAL_FS.contains(&fs_type) {
            continue;
        }
        out.push(MountEntry {
            device: device.to_string(),
            mount_point: mount_point.to_string(),
        });
    }
    out
}

/// Parse the output of macOS `mount` into device-backed mount entries.
///
/// Each row looks like:
///   `/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)`
///
/// We skip APFS firmlinks under `/Volumes`, `/System/Volumes`, and `/private`
/// — they're cosmetic mounts that double-count the underlying volume in
/// `df`-style output.
pub fn parse_macos_mount(text: &str) -> Vec<MountEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        // Split into at most 4 chunks: "<dev>", "on", "<mount>", "<rest>".
        let parts: Vec<&str> = line.splitn(4, ' ').collect();
        if parts.len() < 4 {
            continue;
        }
        let device = parts[0];
        let mount_point = parts[2];

        if !device.starts_with("/dev/") {
            continue;
        }
        if mount_point.starts_with("/Volumes")
            || mount_point.starts_with("/System/Volumes")
            || mount_point.starts_with("/private")
        {
            continue;
        }
        out.push(MountEntry {
            device: device.to_string(),
            mount_point: mount_point.to_string(),
        });
    }
    out
}

/// Sum read/write byte totals from `/proc/diskstats`, skipping pseudo-devices
/// (`loop*`, `ram*`, `dm-*`).
///
/// Each row of `/proc/diskstats` has at least 14 whitespace-separated columns;
/// fields 5 and 9 are the cumulative sectors-read and sectors-written counters.
/// We multiply by the standard 512-byte sector size to get bytes.
///
/// Returns `None` when no qualifying device row is present.
pub fn parse_proc_diskstats(text: &str) -> Option<DiskIo> {
    let mut total_read_bytes = 0u64;
    let mut total_write_bytes = 0u64;
    let mut found = false;

    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 14 {
            continue;
        }
        let name = parts[2];
        if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("dm-") {
            continue;
        }

        let read_sectors: u64 = parts[5].parse().unwrap_or(0);
        let write_sectors: u64 = parts[9].parse().unwrap_or(0);

        total_read_bytes += read_sectors * 512;
        total_write_bytes += write_sectors * 512;
        found = true;
    }

    if found {
        Some(DiskIo {
            read_bytes: total_read_bytes,
            write_bytes: total_write_bytes,
        })
    } else {
        None
    }
}

/// `statvfs` a single mount and turn it into a `DiskUsage`.
///
/// Returns `None` if the syscall fails or the filesystem reports a zero size
/// (which can happen for read-only system mounts on macOS).
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn stat_mount(entry: &MountEntry) -> Option<DiskUsage> {
    use std::ffi::CString;

    let c_path = CString::new(entry.mount_point.as_str()).ok()?;
    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut stat) != 0 {
            return None;
        }
        let block_size = stat.f_frsize as u64;
        let total_bytes = stat.f_blocks as u64 * block_size;
        if total_bytes == 0 {
            return None;
        }
        let available_bytes = stat.f_bavail as u64 * block_size;
        let free_bytes = stat.f_bfree as u64 * block_size;
        let used_bytes = total_bytes.saturating_sub(free_bytes);
        let usage_pct = (used_bytes as f64 / total_bytes as f64 * 100.0 * 10.0).round() / 10.0;

        Some(DiskUsage {
            mount_point: entry.mount_point.clone(),
            device: entry.device.clone(),
            total_bytes,
            used_bytes,
            available_bytes,
            usage_pct,
        })
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs;

    pub fn collect_disk_usage() -> Vec<DiskUsage> {
        let Ok(contents) = fs::read_to_string("/proc/mounts") else {
            return Vec::new();
        };
        parse_proc_mounts(&contents)
            .iter()
            .filter_map(stat_mount)
            .collect()
    }

    pub fn collect_disk_io() -> Option<DiskIo> {
        let contents = fs::read_to_string("/proc/diskstats").ok()?;
        parse_proc_diskstats(&contents)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;

    pub fn collect_disk_usage() -> Vec<DiskUsage> {
        let Ok(output) = std::process::Command::new("mount").output() else {
            return Vec::new();
        };
        let text = String::from_utf8_lossy(&output.stdout);
        parse_macos_mount(&text)
            .iter()
            .filter_map(stat_mount)
            .collect()
    }

    pub fn collect_disk_io() -> Option<DiskIo> {
        // macOS doesn't have /proc/diskstats; iostat is available but parsing is complex.
        // Full IOKit integration is a future enhancement.
        None
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod fallback {
    use super::*;

    pub fn collect_disk_usage() -> Vec<DiskUsage> {
        Vec::new()
    }

    pub fn collect_disk_io() -> Option<DiskIo> {
        None
    }
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub use fallback::*;

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_proc_mounts ────────────────────────────────────────────────

    #[test]
    fn proc_mounts_keeps_real_devices() {
        let sample = "\
/dev/sda1 / ext4 rw,relatime 0 0
/dev/nvme0n1p2 /home xfs rw,relatime 0 0
/dev/mapper/vg0-root /var ext4 rw,relatime 0 0
";
        let mounts = parse_proc_mounts(sample);
        assert_eq!(mounts.len(), 3);
        assert_eq!(mounts[0].device, "/dev/sda1");
        assert_eq!(mounts[0].mount_point, "/");
        assert_eq!(mounts[1].mount_point, "/home");
        assert_eq!(mounts[2].device, "/dev/mapper/vg0-root");
    }

    #[test]
    fn proc_mounts_skips_kernel_virtual_filesystems() {
        let sample = "\
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /run tmpfs rw,nosuid,nodev,size=1632400k 0 0
cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate 0 0
/dev/sda1 / ext4 rw,relatime 0 0
";
        let mounts = parse_proc_mounts(sample);
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].device, "/dev/sda1");
    }

    #[test]
    fn proc_mounts_skips_loop_snap_overlays() {
        // Snap mounts use /dev/loopN with squashfs — already excluded by VIRTUAL_FS.
        // Real device-backed overlays (e.g. ZFS-on-luks) keep `/dev/...` but use a
        // different fs_type, so they pass through.
        let sample = "\
/dev/loop12 /snap/core22/834 squashfs ro,nodev,relatime,errors=continue 0 0
/dev/loop13 /snap/firefox/3206 squashfs ro,nodev,relatime,errors=continue 0 0
overlay /var/lib/docker/overlay2/abc/merged overlay rw,relatime,lowerdir=/x 0 0
/dev/sda1 / ext4 rw,relatime 0 0
";
        let mounts = parse_proc_mounts(sample);
        // loop* mounts use squashfs (virtual), overlay starts with "overlay"
        // (not /dev/), so only the ext4 mount survives.
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].device, "/dev/sda1");
    }

    #[test]
    fn proc_mounts_handles_blank_or_truncated_lines() {
        let sample = "\

/dev/sda1
/dev/sda2 /boot
/dev/sda3 / ext4 rw 0 0
";
        let mounts = parse_proc_mounts(sample);
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].device, "/dev/sda3");
    }

    #[test]
    fn proc_mounts_returns_empty_for_empty_input() {
        assert!(parse_proc_mounts("").is_empty());
    }

    // ── parse_macos_mount ────────────────────────────────────────────────

    #[test]
    fn macos_mount_keeps_root_and_skips_firmlinks() {
        let sample = "\
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
/dev/disk3s6 on /System/Volumes/Update (apfs, local, journaled, nobrowse)
/dev/disk3s2 on /System/Volumes/Data (apfs, local, journaled, nobrowse)
/dev/disk3s4 on /private/var/vm (apfs, local, noexec, journaled, nobrowse)
map auto_home on /System/Volumes/Data/home (autofs, automounted, nobrowse)
/dev/disk5s1 on /Volumes/MyExternal (apfs, local, journaled, nobrowse)
";
        let mounts = parse_macos_mount(sample);
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].device, "/dev/disk3s1s1");
        assert_eq!(mounts[0].mount_point, "/");
    }

    #[test]
    fn macos_mount_ignores_non_dev_lines() {
        let sample = "\
map -hosts on /net (autofs, nosuid, automounted, nobrowse)
map auto_home on /home (autofs, automounted, nobrowse)
";
        assert!(parse_macos_mount(sample).is_empty());
    }

    #[test]
    fn macos_mount_handles_truncated_lines() {
        let sample = "\
/dev/disk3s1s1
/dev/disk3s2 on
/dev/disk3s3 on /Users (apfs, local)
";
        let mounts = parse_macos_mount(sample);
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].mount_point, "/Users");
    }

    // ── parse_proc_diskstats ─────────────────────────────────────────────

    #[test]
    fn diskstats_sums_real_devices() {
        // /proc/diskstats columns:
        //   1=major 2=minor 3=name 4=reads_done 5=reads_merged 6=sectors_read
        //   7=time_reading_ms 8=writes_done 9=writes_merged 10=sectors_written ...
        let sample = "\
   8       0 sda 1000 0 2000 100 500 0 4000 200 0 100 100 0 0
   8       1 sda1 800 0 1500 80 400 0 3000 150 0 80 80 0 0
 259       0 nvme0n1 200 0 1000 50 100 0 500 25 0 50 50 0 0
";
        let io = parse_proc_diskstats(sample).unwrap();
        // sectors_read = 2000 + 1500 + 1000 = 4500; bytes = ×512 = 2_304_000
        assert_eq!(io.read_bytes, 4500u64 * 512);
        // sectors_written = 4000 + 3000 + 500 = 7500; bytes = ×512 = 3_840_000
        assert_eq!(io.write_bytes, 7500u64 * 512);
    }

    #[test]
    fn diskstats_skips_loop_ram_dm() {
        let sample = "\
   7       0 loop0 100 0 200 10 50 0 400 20 0 10 10 0 0 0
   7       1 loop1 100 0 200 10 50 0 400 20 0 10 10 0 0 0
   1       0 ram0 100 0 200 10 50 0 400 20 0 10 10 0 0 0
 253       0 dm-0 100 0 200 10 50 0 400 20 0 10 10 0 0 0
   8       0 sda 1000 0 1000 100 500 0 2000 200 0 100 100 0 0 0
";
        let io = parse_proc_diskstats(sample).unwrap();
        // Only `sda` counts: 1000 sectors read, 2000 sectors written.
        assert_eq!(io.read_bytes, 1000u64 * 512);
        assert_eq!(io.write_bytes, 2000u64 * 512);
    }

    #[test]
    fn diskstats_returns_none_when_only_pseudo_devices() {
        let sample = "\
   7       0 loop0 100 0 200 10 50 0 400 20 0 10 10 0 0 0
 253       0 dm-0 100 0 200 10 50 0 400 20 0 10 10 0 0 0
";
        assert!(parse_proc_diskstats(sample).is_none());
    }

    #[test]
    fn diskstats_returns_none_for_empty_input() {
        assert!(parse_proc_diskstats("").is_none());
    }

    #[test]
    fn diskstats_skips_short_lines() {
        // Lines with fewer than 14 columns (truncated header rows, kernel
        // versions that don't emit the discard-stats columns) are skipped.
        let sample = "\
short line ignored
   8       0 sda 1000 0 2000 100 500 0 4000 200 0 100 100 0 0
";
        let io = parse_proc_diskstats(sample).unwrap();
        assert_eq!(io.read_bytes, 2000u64 * 512);
    }
}
