# Plan — Drive line coverage from 72 % to 90 %

> Status: **Phases 1–4 shipped.** Landed at 86 % line coverage (planned 90 %; shortfall is macOS-specific `system::*` paths and unsafe `libc::statvfs` that can't be reached from a non-privileged test harness without trait-based mocking of the syscall itself).
> Owner: TBD.
> Scope: SDK only. Doesn't include the `netwatch-agent` integration suite.

## Why

Today's 72 % line coverage came almost entirely from extracting pure parsers and exercising them with captured-output fixtures. That's the cheap, high-value tier. The remaining 28 % falls into three buckets that need different techniques:

1. **Pure parsers still inline with I/O** (`disk.rs`). Same recipe as `system.rs` / `config.rs` — extraction is mechanical and gets us 5–8 percentage points.
2. **Branches in tested files that no fixture currently exercises** (uncovered error paths in `connections.rs`, `network_intel.rs`, `health.rs`). Add fixtures.
3. **Code that touches the OS by design** (`platform/linux.rs`, `system::measure_cpu_usage`, `system::measure_cpu_per_core`, `disk::collect_disk_io`). Either accept a coverage haircut here, or introduce a thin seam (`trait FsReader` injected via `&dyn`) so a test can stand in for `/sys` and `/proc/stat`.

This plan turns each bucket into concrete, sized work.

## Current baseline (per file, as of `ab1e306`)

| File                              | Lines  | Bucket                     |
| --------------------------------- | -----: | -------------------------- |
| `collectors/process_bandwidth.rs` |  99 %  | (already done)             |
| `collectors/traffic.rs`           |  94 %  | (already done)             |
| `collectors/config.rs`            |  85 %  | (already done)             |
| `collectors/connections.rs`       |  78 %  | bucket 2                   |
| `collectors/network_intel.rs`     |  74 %  | bucket 2                   |
| `collectors/health.rs`            |  65 %  | bucket 2 (some bucket 3)   |
| `collectors/system.rs`            |  62 %  | bucket 3 (CPU sampling)    |
| `collectors/disk.rs`              |   0 %  | bucket 1                   |
| `platform/linux.rs`               |   0 %  | bucket 3                   |
| **Total**                         | **72 %** | —                        |

CI floor is set at 65 % (`--fail-under-lines 65` in the workflow). The plan is to raise it as each phase lands.

## Phasing

### Phase 1 — extract `disk.rs` parsers (1 day)

Mirror the `system.rs` / `config.rs` work exactly. Lift the parsers out as module-scope `pub fn`s and add fixture tests.

- `parse_proc_diskstats(&str) -> Option<DiskIo>` — sums sector deltas (×512), excludes `loop`, `ram`, `dm-*`. Tests for typical kernel output, the empty `Module` line, virtual devices skipped, the `disk-stats` format vs the older 11-field format.
- `parse_proc_mounts(&str) -> Vec<MountEntry>` — filters to real `/dev/*`, returns `(device, mount_point, fstype)` tuples. Tests for the snap mounts (`/dev/loop12 on /snap/...`), for filesystem types we want to skip (`tmpfs`, `proc`, `sysfs`, `cgroup2`), and for the macOS variant (returned by `mount` not `/proc/mounts`).
- `parse_macos_mount(&str)` — same, for the `mount` output format.

Coverage payoff: `disk.rs` jumps from 0 % to ~80 %. **Total: ~72 % → ~78 %.**

After landing, raise CI floor to 70 %.

### Phase 2 — fixture-fill the uncovered branches in `connections.rs`, `network_intel.rs`, `health.rs` (3–4 days)

These files already have tests for the happy paths. The gaps are error paths and rare-format cases.

#### `connections.rs` (78 % → ~92 %)

Branches currently uncovered:
- IPv6 RTT extraction in `parse_nettop_output` — currently skipped pending IPv6 normalisation. Add the parsing and the test.
- `lsof` rows with neither `pcPtTn` field. Capture a real-world `lsof -i -F` output where a line is missing the optional fields.
- `parse_ss_output` lines without a valid `users:` field (root processes hidden when running unprivileged).
- The "macOS netstat-only" path in `count_established_connections` and `collect_tcp_states` (currently only the Linux path has fixture coverage).

#### `network_intel.rs` (74 % → ~90 %)

The four detectors are well-covered on the trigger path, but the **alert lifecycle** isn't:
- `tick()` pruning of stale port-scan windows.
- `tick()` pruning of expired DNS outstanding transactions (`DNS_OUTSTANDING_TIMEOUT_SECS`).
- `tick()` aging of alerts past `ACTIVE_ALERT_TTL_SECS`.
- The `BW_ALERT_CLEAR_RATIO` recovery path (alert that fires, then clears).
- `MAX_TRACKED_*` eviction caps.

Each of these is ~5 lines of test setup: build a collector, seed events at known timestamps, advance simulated time by calling `tick()` repeatedly, assert state.

#### `health.rs` (65 % → ~85 %)

The big gap is `run_ping` itself (it shells out to `ping`). Two options:
- **Don't test it** — accept the haircut. The parsers (`parse_loss`, `parse_avg_rtt`) are already well-covered and they're the bug-prone bit.
- **Test the smoke path** — a live test that runs `run_ping("127.0.0.1")` and asserts loss < 50 %. Skip on unprivileged hosts where loopback ping is restricted.

Recommend the live smoke test; it adds confidence that the SDK still talks to the system `ping`.

Coverage payoff: ~6 percentage points across the three files. **Total: ~78 % → ~84 %.**

After landing, raise CI floor to 78 %.

### Phase 3 — seams for `system::measure_cpu_*` and `platform::collect_interface_stats` (3–5 days)

This is where coverage gets architectural. Both functions read live OS state and sleep. Without a seam, they can only be exercised by integration tests on real hosts.

Two design options:

#### Option A — fakeable filesystem trait

Introduce a private trait:

```rust
pub(crate) trait FsReader {
    fn read_to_string(&self, path: &Path) -> std::io::Result<String>;
}
```

Production code uses a `RealFs` implementation that calls `std::fs::read_to_string`. Tests construct collectors with a `FakeFs` map of `path → contents`.

- Pros: parses everything against fixtures, gets `platform/linux.rs` and the CPU-sampling code paths to ~95 % covered, no behaviour change in production.
- Cons: changes the public signature of `measure_cpu_usage`, `read_memory`, and friends. Or — keep the public signature, accept a `&impl FsReader` only in `pub(crate)` helpers, and have the public functions call them with `RealFs`. The latter has zero public-API impact.

Recommend the latter. It's the pattern used by `tokio` for its mocked clock and by `git2-rs` for repo objects.

#### Option B — `#[cfg(test)]` substitution

Replace `std::fs::read_to_string` with a thin wrapper that, under `#[cfg(test)]`, reads from a `thread_local!` map.

- Pros: no API change at all.
- Cons: less explicit; the seam is invisible to readers; test setup is a bit magic.

Recommend Option A.

#### What this unlocks

After the seam exists:

- `system::measure_cpu_usage` — fixture: two `/proc/stat` snapshots → assert the computed %.
- `system::measure_cpu_per_core` — same.
- `platform::linux::collect_interface_stats` — fixture: synthetic `/sys/class/net/eth0/statistics/*` files → assert the returned `InterfaceStats`. macOS gets the same treatment with a `CommandRunner` trait if needed.
- `disk::collect_disk_io` — fixture: synthetic `/proc/diskstats`.

Coverage payoff: ~6 percentage points. **Total: ~84 % → ~90 %.**

After landing, raise CI floor to 85 %.

### Phase 4 — property-based tests (optional, 1 week)

For the highest-stakes parsers (`parse_ss_output`, `parse_nettop_output`, `parse_proc_meminfo`), add `proptest` generators that produce structurally-valid synthetic outputs and assert round-trip / invariant properties.

- `parse_ss_output(format(c)).unwrap() == c` for any synthetic `Connection`.
- `parse_proc_meminfo` never returns more "used" than "total".
- `parse_nettop_output` never returns negative RTTs.

This won't move the coverage % much (the parsers are already at high %), but it catches the bugs the fixture suite never thought of.

## Targets and floor schedule

| After phase | Total coverage | CI floor (`--fail-under-lines`) |
| ----------- | -------------: | ------------------------------: |
| Today       | 72 %           | 65                              |
| Phase 1     | ~78 %          | 70                              |
| Phase 2     | ~84 %          | 78                              |
| Phase 3     | ~90 %          | 85                              |
| Phase 4     | ~92 %          | 88                              |

The floor lags the target by ~3 percentage points so legitimate refactors don't accidentally fail CI on a one-line uncovered helper.

## What we explicitly won't pursue

- **100 % coverage.** Some `unsafe` libc blocks (in `system::macos::read_load_avg`) would require linker-level mocking to exercise — not worth the complexity for one function call.
- **Mocking the system `ping` binary** in a way that returns crafted output. Either we live-test against `127.0.0.1` (preferred) or we don't test `run_ping` at all.
- **Coverage for the eBPF programs** (when phase 1 of the eBPF plan ships). BPF coverage tooling exists (`bpftool prog profile`) but isn't a fit for unit tests; rely on the privileged-container integration suite.

## Tooling housekeeping

- **Codecov / Coveralls upload.** The CI job already produces `lcov.info` as an artifact. A 5-line addition to publish to Codecov gives us per-PR diff summaries. Worth doing alongside Phase 1.
- **Coverage badge in README.** Codecov auto-generates one. Slot it next to the existing crates.io and license badges.
- **Diff coverage gate** (Codecov's "patch coverage"). Stricter than the absolute floor: every PR must cover ≥ 80 % of the lines it adds. Saves us from review fatigue around "did this PR add tests?".

## Estimate

| Phase | Effort         | Coverage gain |
| ----- | -------------- | ------------- |
| 1     | 1 day          | +6 pp         |
| 2     | 3–4 days       | +6 pp         |
| 3     | 3–5 days       | +6 pp         |
| 4     | 1 week (opt)   | +2 pp + bug-finding |

End state: **~90 % line coverage** with a CI floor of 85 %, plus property tests for the highest-leverage parsers and per-PR diff coverage in the review surface.
