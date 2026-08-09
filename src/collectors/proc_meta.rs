//! Per-process metadata from a single `ps` poll: owner, CPU%, memory, scheduler
//! state, start time, and executable path. This is the "who/what is this pid"
//! companion to [`process_bandwidth`](super::process_bandwidth), which measures
//! traffic. Sample on a slow tick (a few seconds+) — each call forks one `ps`.
//!
//! Privacy: `cmd` is the executable path only (`ps comm` on macOS,
//! `/proc/<pid>/exe` on Linux), never argv — command-line arguments can carry
//! secrets and these fields leave the host when streamed to a backend.

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::process::Command;

use super::process_bandwidth::ProcessBandwidth;

/// Metadata for one pid, as reported by `ps` at sample time.
#[derive(Debug, Clone)]
pub struct ProcMeta {
    pub cpu_percent: f64,
    pub ppid: Option<u32>,
    pub user: Option<String>,
    pub mem_rss_bytes: Option<u64>,
    pub mem_virt_bytes: Option<u64>,
    /// Single-char scheduler state (R / S / I / Z / T…).
    pub state: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    /// Executable path; see module docs for the privacy contract.
    pub cmd: Option<String>,
}

/// Sample metadata for every process on the host. Returns `None` when `ps`
/// is unavailable or fails (non-unix platforms, restricted sandboxes).
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn sample() -> Option<HashMap<u32, ProcMeta>> {
    let output = Command::new("ps")
        .args([
            "-A",
            "-o",
            "pid=,ppid=,user=,pcpu=,rss=,vsz=,state=,etime=,comm=",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let now = Utc::now();
    let mut map: HashMap<u32, ProcMeta> = HashMap::new();
    for line in text.lines() {
        if let Some((pid, meta)) = parse_ps_line(line, now) {
            map.insert(pid, meta);
        }
    }
    Some(map)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn sample() -> Option<HashMap<u32, ProcMeta>> {
    None
}

/// Copy sampled metadata onto bandwidth rows by pid, filling the optional
/// detail fields of [`ProcessBandwidth`]. Rows without a pid (or whose pid
/// exited between samples) are left untouched.
pub fn apply(processes: &mut [ProcessBandwidth], meta: &HashMap<u32, ProcMeta>) {
    for p in processes {
        let Some(m) = p.pid.and_then(|pid| meta.get(&pid)) else {
            continue;
        };
        p.cpu_pct = Some(m.cpu_percent);
        p.ppid = m.ppid;
        p.user = m.user.clone();
        p.mem_rss_bytes = m.mem_rss_bytes;
        p.mem_virt_bytes = m.mem_virt_bytes;
        p.state = m.state.clone();
        p.started_at = m.started_at;
        p.cmd = m.cmd.clone();
    }
}

/// Parse one `ps -o pid=,ppid=,user=,pcpu=,rss=,vsz=,state=,etime=,comm=` row.
/// The first 8 fields are whitespace-free; `comm` is the remainder and may
/// contain spaces (macOS reports full bundle paths like
/// `…/Code Helper (Plugin)`). `now` anchors the etime → start-time math.
pub fn parse_ps_line(line: &str, now: DateTime<Utc>) -> Option<(u32, ProcMeta)> {
    let mut rest = line.trim_start();
    let mut fields = [""; 8];
    for f in fields.iter_mut() {
        let end = rest.find(char::is_whitespace)?;
        *f = &rest[..end];
        rest = rest[end..].trim_start();
    }
    let comm = rest.trim_end();

    let pid: u32 = fields[0].parse().ok()?;
    let ppid: Option<u32> = fields[1].parse().ok();
    let user = (!fields[2].is_empty()).then(|| fields[2].to_string());
    let cpu_percent: f64 = fields[3].parse().unwrap_or(0.0);
    // rss/vsz are reported in KiB on both platforms.
    let mem_rss_bytes = fields[4].parse::<u64>().ok().map(|kb| kb * 1024);
    let mem_virt_bytes = fields[5].parse::<u64>().ok().map(|kb| kb * 1024);
    // Linux appends modifier chars ("Ssl"); keep the primary state only.
    let state = fields[6].chars().next().map(|c| c.to_string());
    // `now - Duration::seconds(secs)` panics when the result falls outside
    // chrono's representable range, and it took the whole agent down in the
    // field: right after boot, NTP stepping the clock backwards makes `ps`
    // report an enormous etime, which then underflows the subtraction. A
    // process whose start time we cannot place is worth a `None`, never a
    // crash of the collector — so both the span and the subtraction are
    // checked, and an unrepresentable value simply drops the field.
    let started_at = parse_etime_secs(fields[7])
        .and_then(|secs| i64::try_from(secs).ok())
        .and_then(chrono::TimeDelta::try_seconds)
        .and_then(|elapsed| now.checked_sub_signed(elapsed));
    let cmd = exe_path(pid, comm);

    Some((
        pid,
        ProcMeta {
            cpu_percent,
            ppid,
            user,
            mem_rss_bytes,
            mem_virt_bytes,
            state,
            started_at,
            cmd,
        },
    ))
}

/// Resolve the executable path for `cmd`. On macOS `ps comm` is already the
/// full path. On Linux it's the truncated 15-char comm, so prefer the
/// `/proc/<pid>/exe` symlink (readable for own-uid processes; None when
/// permission is denied rather than falling back to the truncated name).
#[cfg(target_os = "linux")]
fn exe_path(pid: u32, _comm: &str) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

#[cfg(not(target_os = "linux"))]
fn exe_path(_pid: u32, comm: &str) -> Option<String> {
    (!comm.is_empty()).then(|| comm.to_string())
}

/// Parse `ps etime` — `[[dd-]hh:]mm:ss` — into elapsed seconds.
pub fn parse_etime_secs(s: &str) -> Option<u64> {
    let (days, rest) = match s.split_once('-') {
        Some((d, r)) => (d.parse::<u64>().ok()?, r),
        None => (0, s),
    };
    let parts: Vec<&str> = rest.split(':').collect();
    let (h, m, sec): (u64, u64, u64) = match parts.len() {
        3 => (
            parts[0].parse().ok()?,
            parts[1].parse().ok()?,
            parts[2].parse().ok()?,
        ),
        2 => (0, parts[0].parse().ok()?, parts[1].parse().ok()?),
        _ => return None,
    };
    // Checked throughout: a `ps` row claiming ~2^63 days would otherwise panic
    // here in a debug build and silently wrap in a release one.
    days.checked_mul(86400)?
        .checked_add(h.checked_mul(3600)?)?
        .checked_add(m.checked_mul(60)?)?
        .checked_add(sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etime_parses_all_three_shapes() {
        assert_eq!(parse_etime_secs("05:42"), Some(5 * 60 + 42));
        assert_eq!(parse_etime_secs("03:05:42"), Some(3 * 3600 + 5 * 60 + 42));
        assert_eq!(
            parse_etime_secs("12-03:05:42"),
            Some(12 * 86400 + 3 * 3600 + 5 * 60 + 42)
        );
        assert_eq!(parse_etime_secs("42"), None);
        assert_eq!(parse_etime_secs(""), None);
    }

    #[test]
    fn etime_with_absurd_day_count_returns_none_instead_of_overflowing() {
        // `days * 86400` overflows u64 here; unchecked it panics in debug and
        // wraps to a small plausible-looking number in release.
        assert_eq!(parse_etime_secs("99999999999999999999-00:00:00"), None);
        assert_eq!(
            parse_etime_secs(&format!("{}-00:00:00", u64::MAX)),
            None
        );
    }

    #[test]
    fn unrepresentable_start_time_drops_the_field_and_does_not_panic() {
        // The field crash: after boot, NTP steps the clock and `ps` reports an
        // etime far larger than the age of the universe. Subtracting it used to
        // panic with "`DateTime - TimeDelta` overflowed" and kill the agent.
        let now = Utc::now();
        let line = format!(
            "  1234   1 root   0.0 100 200 S {}-00:00:00 /usr/bin/thing",
            u32::MAX
        );
        let (pid, meta) = parse_ps_line(&line, now).expect("row still parses");
        assert_eq!(pid, 1234);
        // Everything else survives; only the unplaceable timestamp is dropped.
        assert_eq!(meta.started_at, None);
        assert_eq!(meta.state.as_deref(), Some("S"));
        assert_eq!(meta.user.as_deref(), Some("root"));
    }

    #[test]
    fn a_sane_start_time_is_still_computed() {
        let now = Utc::now();
        let line = "  1234   1 root   0.0 100 200 S 01:00:00 /usr/bin/thing";
        let (_, meta) = parse_ps_line(line, now).expect("row parses");
        let started = meta.started_at.expect("start time present");
        assert_eq!((now - started).num_seconds(), 3600);
    }

    #[test]
    fn ps_line_parses_with_spaces_in_comm() {
        let now = Utc::now();
        let line = "  29259   650 matt   3.5 184832 411234016 S 02-01:02:03 /Applications/Code.app/Contents/Code Helper (Plugin)";
        let (pid, meta) = parse_ps_line(line, now).expect("line should parse");
        assert_eq!(pid, 29259);
        assert_eq!(meta.ppid, Some(650));
        assert_eq!(meta.user.as_deref(), Some("matt"));
        assert!((meta.cpu_percent - 3.5).abs() < 0.001);
        assert_eq!(meta.mem_rss_bytes, Some(184832 * 1024));
        assert_eq!(meta.state.as_deref(), Some("S"));
        let expected_secs = 2 * 86400 + 3600 + 2 * 60 + 3;
        assert_eq!(
            (now - meta.started_at.unwrap()).num_seconds(),
            expected_secs
        );
        #[cfg(not(target_os = "linux"))]
        assert_eq!(
            meta.cmd.as_deref(),
            Some("/Applications/Code.app/Contents/Code Helper (Plugin)")
        );
    }

    #[test]
    fn ps_line_keeps_primary_state_char_only() {
        let now = Utc::now();
        let line = "1234 1 postgres 12.0 524288 1048576 Ssl 10:00 postgres";
        let (_, meta) = parse_ps_line(line, now).expect("line should parse");
        assert_eq!(meta.state.as_deref(), Some("S"));
    }

    #[test]
    fn malformed_ps_lines_are_skipped() {
        let now = Utc::now();
        assert!(parse_ps_line("", now).is_none());
        assert!(parse_ps_line("garbage", now).is_none());
        assert!(parse_ps_line("notanumber 1 u 0.0 1 1 S 0:01 x", now).is_none());
    }

    #[test]
    fn apply_enriches_rows_by_pid_and_skips_unknown() {
        let mut rows = vec![
            ProcessBandwidth::network_only("nginx".into(), Some(890), 0, 0, 0.0, 0.0, 1),
            ProcessBandwidth::network_only("ghost".into(), Some(999), 0, 0, 0.0, 0.0, 1),
            ProcessBandwidth::network_only("nopid".into(), None, 0, 0, 0.0, 0.0, 1),
        ];
        let mut meta = HashMap::new();
        meta.insert(
            890,
            ProcMeta {
                cpu_percent: 2.5,
                ppid: Some(1),
                user: Some("www-data".into()),
                mem_rss_bytes: Some(1024),
                mem_virt_bytes: Some(2048),
                state: Some("S".into()),
                started_at: Some(Utc::now()),
                cmd: Some("/usr/sbin/nginx".into()),
            },
        );
        apply(&mut rows, &meta);
        assert_eq!(rows[0].user.as_deref(), Some("www-data"));
        assert_eq!(rows[0].cpu_pct, Some(2.5));
        assert_eq!(rows[0].cmd.as_deref(), Some("/usr/sbin/nginx"));
        assert!(rows[1].user.is_none(), "exited pid stays bare");
        assert!(rows[2].user.is_none(), "pid-less row stays bare");
    }

    #[test]
    fn sample_returns_data_on_unix() {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            let map = sample().expect("ps should run");
            assert!(!map.is_empty(), "at least our own process should appear");
        }
    }
}
