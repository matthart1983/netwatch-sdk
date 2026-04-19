#[derive(Debug)]
pub struct CpuInfo {
    pub model: Option<String>,
    pub cores: Option<u32>,
}

#[derive(Debug)]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Debug)]
pub struct SwapInfo {
    pub total_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Debug)]
pub struct LoadAvg {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
}

/// Parse the contents of `/proc/loadavg` into a `LoadAvg`.
///
/// Returns `None` if fewer than three numeric fields are present.
pub fn parse_proc_loadavg(text: &str) -> Option<LoadAvg> {
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }
    Some(LoadAvg {
        one: parts[0].parse().ok()?,
        five: parts[1].parse().ok()?,
        fifteen: parts[2].parse().ok()?,
    })
}

/// Parse `/proc/meminfo` into a `MemoryInfo`.
///
/// Falls back to `MemFree + Buffers + Cached` when `MemAvailable` is absent
/// (older kernels). Returns `None` only if `MemTotal` is missing.
pub fn parse_proc_meminfo(text: &str) -> Option<MemoryInfo> {
    let mut total_kb = 0u64;
    let mut available_kb = 0u64;
    let mut free_kb = 0u64;
    let mut buffers_kb = 0u64;
    let mut cached_kb = 0u64;
    let mut saw_total = false;

    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        match parts[0] {
            "MemTotal:" => {
                total_kb = parts[1].parse().unwrap_or(0);
                saw_total = true;
            }
            "MemAvailable:" => available_kb = parts[1].parse().unwrap_or(0),
            "MemFree:" => free_kb = parts[1].parse().unwrap_or(0),
            "Buffers:" => buffers_kb = parts[1].parse().unwrap_or(0),
            "Cached:" => cached_kb = parts[1].parse().unwrap_or(0),
            _ => {}
        }
    }

    if !saw_total {
        return None;
    }

    if available_kb == 0 {
        available_kb = free_kb + buffers_kb + cached_kb;
    }
    let used_kb = total_kb.saturating_sub(available_kb);

    Some(MemoryInfo {
        total_bytes: total_kb * 1024,
        available_bytes: available_kb * 1024,
        used_bytes: used_kb * 1024,
    })
}

/// Parse `SwapTotal:` / `SwapFree:` from `/proc/meminfo` into `SwapInfo`.
///
/// Always returns `Some` — a host with no swap shows up as `(0, 0)`.
pub fn parse_proc_swap(text: &str) -> SwapInfo {
    let mut swap_total_kb = 0u64;
    let mut swap_free_kb = 0u64;
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        match parts[0] {
            "SwapTotal:" => swap_total_kb = parts[1].parse().unwrap_or(0),
            "SwapFree:" => swap_free_kb = parts[1].parse().unwrap_or(0),
            _ => {}
        }
    }
    SwapInfo {
        total_bytes: swap_total_kb * 1024,
        used_bytes: swap_total_kb.saturating_sub(swap_free_kb) * 1024,
    }
}

/// Parse the output of macOS `vm_stat` plus a known `total_bytes` into a
/// `MemoryInfo`. Computes `available_bytes` as `(free + inactive + speculative)
/// * page_size`.
///
/// `page_size` is read from the first line of `vm_stat` ("Mach Virtual Memory
/// Statistics: (page size of N bytes)"); if the line is missing or unparseable
/// it falls back to 16 KiB (Apple Silicon default).
pub fn parse_vm_stat(text: &str, total_bytes: u64) -> Option<MemoryInfo> {
    let page_size: u64 = text
        .lines()
        .next()
        .and_then(|l| l.split("page size of ").nth(1))
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(16384);

    let get_pages = |name: &str| -> u64 {
        text.lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|s| s.trim().trim_end_matches('.').parse().ok())
            .unwrap_or(0)
    };

    let free = get_pages("Pages free") * page_size;
    let inactive = get_pages("Pages inactive") * page_size;
    let speculative = get_pages("Pages speculative") * page_size;
    let available = free + inactive + speculative;
    let used = total_bytes.saturating_sub(available);

    Some(MemoryInfo {
        total_bytes,
        available_bytes: available,
        used_bytes: used,
    })
}

/// Parse the output of `sysctl -n vm.swapusage` into a `SwapInfo`.
///
/// The string looks like:
///   `total = 4096.00M  used = 512.50M  free = 3583.50M  (encrypted)`
/// Returns `None` if `total =` is missing or unparseable.
pub fn parse_macos_swapusage(text: &str) -> Option<SwapInfo> {
    let parse_mb = |prefix: &str| -> Option<u64> {
        text.split(prefix)
            .nth(1)?
            .trim()
            .split('M')
            .next()?
            .trim()
            .parse::<f64>()
            .ok()
            .map(|mb| (mb * 1024.0 * 1024.0) as u64)
    };
    let total = parse_mb("total =")?;
    let used = parse_mb("used =").unwrap_or(0);
    Some(SwapInfo {
        total_bytes: total,
        used_bytes: used,
    })
}

/// Extract the CPU model line from `/proc/cpuinfo` ("model name : ...").
/// Returns `None` if the field isn't present (common on ARM).
pub fn parse_proc_cpuinfo_model(text: &str) -> Option<String> {
    text.lines()
        .find(|l| l.starts_with("model name"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs;
    use std::thread;
    use std::time::Duration;

    pub fn detect_cpu_info() -> CpuInfo {
        let contents = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        // x86: "model name : Intel Core i7-..."
        let model = parse_proc_cpuinfo_model(&contents).or_else(|| {
            // ARM: try lscpu for model name and vendor
            let output = std::process::Command::new("lscpu")
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string());
            let output = output.as_deref().unwrap_or("");
            let get = |prefix: &str| {
                output
                    .lines()
                    .find(|l| l.starts_with(prefix))
                    .and_then(|l| l.split(':').nth(1))
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty() && s != "-")
            };
            let arch = get("Architecture:");
            let vendor = get("Vendor ID:");
            let model = get("Model name:");
            match (model, vendor, arch) {
                (Some(m), _, _) => Some(m),
                (None, Some(v), Some(a)) => Some(format!("{} ({})", v, a)),
                (None, Some(v), None) => Some(v),
                (None, None, Some(a)) => Some(a),
                _ => None,
            }
        });
        let cores = contents
            .lines()
            .filter(|l| l.starts_with("processor"))
            .count() as u32;
        CpuInfo {
            model,
            cores: if cores > 0 { Some(cores) } else { None },
        }
    }

    pub fn detect_memory_total() -> Option<u64> {
        let contents = fs::read_to_string("/proc/meminfo").ok()?;
        for line in contents.lines() {
            if line.starts_with("MemTotal:") {
                let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
                return Some(kb * 1024);
            }
        }
        None
    }

    struct CpuSample {
        idle: u64,
        total: u64,
    }

    fn read_cpu_sample() -> Option<CpuSample> {
        let contents = fs::read_to_string("/proc/stat").ok()?;
        let line = contents.lines().next()?;
        if !line.starts_with("cpu ") {
            return None;
        }
        let vals: Vec<u64> = line
            .split_whitespace()
            .skip(1)
            .filter_map(|v| v.parse().ok())
            .collect();
        if vals.len() < 4 {
            return None;
        }
        let idle = vals[3];
        let total: u64 = vals.iter().sum();
        Some(CpuSample { idle, total })
    }

    pub fn measure_cpu_usage() -> Option<f64> {
        let s1 = read_cpu_sample()?;
        thread::sleep(Duration::from_millis(200));
        let s2 = read_cpu_sample()?;

        let total_diff = s2.total.saturating_sub(s1.total);
        let idle_diff = s2.idle.saturating_sub(s1.idle);
        if total_diff == 0 {
            return Some(0.0);
        }

        let usage = (total_diff - idle_diff) as f64 / total_diff as f64 * 100.0;
        Some((usage * 10.0).round() / 10.0)
    }

    fn read_per_core_samples() -> Option<Vec<CpuSample>> {
        let contents = fs::read_to_string("/proc/stat").ok()?;
        let mut cores = Vec::new();
        for line in contents.lines() {
            if line.starts_with("cpu") && !line.starts_with("cpu ") {
                let vals: Vec<u64> = line
                    .split_whitespace()
                    .skip(1)
                    .filter_map(|v| v.parse().ok())
                    .collect();
                if vals.len() < 4 {
                    continue;
                }
                let idle = vals[3];
                let total: u64 = vals.iter().sum();
                cores.push(CpuSample { idle, total });
            }
        }
        if cores.is_empty() {
            None
        } else {
            Some(cores)
        }
    }

    pub fn measure_cpu_per_core() -> Option<Vec<f64>> {
        let s1 = read_per_core_samples()?;
        thread::sleep(Duration::from_millis(200));
        let s2 = read_per_core_samples()?;

        if s1.len() != s2.len() {
            return None;
        }

        let usages: Vec<f64> = s1
            .iter()
            .zip(s2.iter())
            .map(|(a, b)| {
                let total_diff = b.total.saturating_sub(a.total);
                let idle_diff = b.idle.saturating_sub(a.idle);
                if total_diff == 0 {
                    0.0
                } else {
                    let usage = (total_diff - idle_diff) as f64 / total_diff as f64 * 100.0;
                    (usage * 10.0).round() / 10.0
                }
            })
            .collect();

        Some(usages)
    }

    pub fn read_memory() -> Option<MemoryInfo> {
        let contents = fs::read_to_string("/proc/meminfo").ok()?;
        parse_proc_meminfo(&contents)
    }

    pub fn read_load_avg() -> Option<LoadAvg> {
        let contents = fs::read_to_string("/proc/loadavg").ok()?;
        parse_proc_loadavg(&contents)
    }

    pub fn read_swap() -> Option<SwapInfo> {
        let contents = fs::read_to_string("/proc/meminfo").ok()?;
        Some(parse_proc_swap(&contents))
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::process::Command;

    pub fn detect_cpu_info() -> CpuInfo {
        let model = Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string"])
            .output()
            .ok()
            .and_then(|o| {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if s.is_empty() {
                    None
                } else {
                    Some(s)
                }
            });
        let cores = Command::new("sysctl")
            .args(["-n", "hw.ncpu"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok());
        CpuInfo { model, cores }
    }

    pub fn detect_memory_total() -> Option<u64> {
        let output = Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()?;
        String::from_utf8_lossy(&output.stdout).trim().parse().ok()
    }

    fn num_cpus() -> Option<u32> {
        Command::new("sysctl")
            .args(["-n", "hw.ncpu"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
    }

    pub fn measure_cpu_usage() -> Option<f64> {
        let output = Command::new("ps")
            .args(["-A", "-o", "%cpu"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        let total: f64 = text
            .lines()
            .skip(1)
            .filter_map(|l| l.trim().parse::<f64>().ok())
            .sum();
        let cores = num_cpus().unwrap_or(1) as f64;
        let pct = (total / cores).min(100.0);
        Some((pct * 10.0).round() / 10.0)
    }

    pub fn read_memory() -> Option<MemoryInfo> {
        let total_bytes = detect_memory_total()?;
        let output = Command::new("vm_stat").output().ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        parse_vm_stat(&text, total_bytes)
    }

    pub fn read_load_avg() -> Option<LoadAvg> {
        let mut loads: [f64; 3] = [0.0; 3];
        let ret = unsafe { libc::getloadavg(loads.as_mut_ptr(), 3) };
        if ret < 3 {
            return None;
        }
        Some(LoadAvg {
            one: loads[0],
            five: loads[1],
            fifteen: loads[2],
        })
    }

    pub fn read_swap() -> Option<SwapInfo> {
        let output = Command::new("sysctl")
            .args(["-n", "vm.swapusage"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        parse_macos_swapusage(&text)
    }

    pub fn measure_cpu_per_core() -> Option<Vec<f64>> {
        None
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod fallback {
    use super::*;

    pub fn detect_cpu_info() -> CpuInfo {
        CpuInfo {
            model: None,
            cores: None,
        }
    }

    pub fn detect_memory_total() -> Option<u64> {
        None
    }
    pub fn measure_cpu_usage() -> Option<f64> {
        None
    }
    pub fn measure_cpu_per_core() -> Option<Vec<f64>> {
        None
    }
    pub fn read_memory() -> Option<MemoryInfo> {
        None
    }
    pub fn read_load_avg() -> Option<LoadAvg> {
        None
    }
    pub fn read_swap() -> Option<SwapInfo> {
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

    #[test]
    fn loadavg_parses_typical_line() {
        let sample = "0.42 0.38 0.31 1/237 12345\n";
        let la = parse_proc_loadavg(sample).unwrap();
        assert!((la.one - 0.42).abs() < 1e-9);
        assert!((la.five - 0.38).abs() < 1e-9);
        assert!((la.fifteen - 0.31).abs() < 1e-9);
    }

    #[test]
    fn loadavg_returns_none_on_short_input() {
        assert!(parse_proc_loadavg("").is_none());
        assert!(parse_proc_loadavg("0.1 0.2\n").is_none());
    }

    #[test]
    fn loadavg_returns_none_on_garbage_field() {
        assert!(parse_proc_loadavg("abc 0.2 0.3 1/237 12345").is_none());
    }

    #[test]
    fn meminfo_uses_memavailable_when_present() {
        let sample = "\
MemTotal:       16384000 kB
MemFree:         1024000 kB
MemAvailable:    8192000 kB
Buffers:          512000 kB
Cached:          2048000 kB
";
        let m = parse_proc_meminfo(sample).unwrap();
        assert_eq!(m.total_bytes, 16384000 * 1024);
        assert_eq!(m.available_bytes, 8192000 * 1024);
        assert_eq!(m.used_bytes, (16384000 - 8192000) * 1024);
    }

    #[test]
    fn meminfo_falls_back_to_free_buffers_cached_on_old_kernels() {
        let sample = "\
MemTotal:       8192000 kB
MemFree:         500000 kB
Buffers:         100000 kB
Cached:          400000 kB
";
        let m = parse_proc_meminfo(sample).unwrap();
        // No MemAvailable, so available = free + buffers + cached = 1_000_000 KB
        assert_eq!(m.available_bytes, 1_000_000 * 1024);
        assert_eq!(m.used_bytes, (8192000 - 1_000_000) * 1024);
    }

    #[test]
    fn meminfo_returns_none_when_total_missing() {
        let sample = "MemFree: 500000 kB\nMemAvailable: 1000000 kB\n";
        assert!(parse_proc_meminfo(sample).is_none());
    }

    #[test]
    fn swap_parses_present_swap() {
        let sample = "\
MemTotal:    16384000 kB
SwapTotal:    4194304 kB
SwapFree:     2097152 kB
";
        let s = parse_proc_swap(sample);
        assert_eq!(s.total_bytes, 4194304u64 * 1024);
        assert_eq!(s.used_bytes, 2097152u64 * 1024);
    }

    #[test]
    fn swap_zero_when_swap_disabled() {
        let sample = "MemTotal: 16384000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n";
        let s = parse_proc_swap(sample);
        assert_eq!(s.total_bytes, 0);
        assert_eq!(s.used_bytes, 0);
    }

    #[test]
    fn vm_stat_parses_apple_silicon_output() {
        // 16 KiB pages (Apple Silicon default).
        let sample = "\
Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                          12345.
Pages active:                        67890.
Pages inactive:                      54321.
Pages speculative:                    1000.
Pages wired down:                    23456.
";
        let m = parse_vm_stat(sample, 32u64 * 1024 * 1024 * 1024).unwrap();
        let expected_avail = (12345u64 + 54321 + 1000) * 16384;
        assert_eq!(m.available_bytes, expected_avail);
        assert_eq!(m.total_bytes, 32u64 * 1024 * 1024 * 1024);
    }

    #[test]
    fn vm_stat_falls_back_to_default_page_size_if_header_missing() {
        let sample = "\
Pages free:                          1000.
Pages inactive:                       500.
Pages speculative:                    100.
";
        let m = parse_vm_stat(sample, 4u64 * 1024 * 1024 * 1024).unwrap();
        // Fallback page size is 16384.
        assert_eq!(m.available_bytes, (1000u64 + 500 + 100) * 16384);
    }

    #[test]
    fn macos_swapusage_parses_full_line() {
        let sample = "total = 4096.00M  used = 512.50M  free = 3583.50M  (encrypted)\n";
        let s = parse_macos_swapusage(sample).unwrap();
        assert_eq!(s.total_bytes, (4096.0 * 1024.0 * 1024.0) as u64);
        assert_eq!(s.used_bytes, (512.5 * 1024.0 * 1024.0) as u64);
    }

    #[test]
    fn macos_swapusage_returns_none_when_total_missing() {
        assert!(parse_macos_swapusage("used = 512.50M  free = 3583.50M\n").is_none());
    }

    #[test]
    fn cpuinfo_extracts_x86_model_name() {
        let sample = "\
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
model name      : Intel(R) Core(TM) i7-12700H @ 2.30GHz
stepping        : 2
";
        assert_eq!(
            parse_proc_cpuinfo_model(sample).as_deref(),
            Some("Intel(R) Core(TM) i7-12700H @ 2.30GHz")
        );
    }

    #[test]
    fn cpuinfo_returns_none_when_model_name_absent() {
        // Typical ARM /proc/cpuinfo: no "model name" field.
        let sample = "\
processor       : 0
BogoMIPS        : 50.00
Features        : fp asimd evtstrm
";
        assert!(parse_proc_cpuinfo_model(sample).is_none());
    }
}
