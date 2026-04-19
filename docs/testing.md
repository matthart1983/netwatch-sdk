# Testing

```sh
cargo test
```

That's the whole thing — no fixtures, no test database, no env vars required. The tests run on Linux and macOS; the live ones skip themselves when the underlying tool isn't available.

## What's covered

73 unit tests across 8 modules, weighted toward parsing and state-machine logic. The shape of the suite:

| Module                 | Tests | What they actually exercise                                                                                               |
| ---------------------- | ----: | ------------------------------------------------------------------------------------------------------------------------- |
| `traffic.rs`           | 4     | First-call zero rates; history accumulation; 60-sample window cap; eviction of dropped interfaces                         |
| `connections.rs`       | 8     | `parse_ss_output`, `parse_nettop_output`, `parse_lsof`, RTT merge, `top_connections` ranking                              |
| `process_bandwidth.rs` | 5     | Proportional split, ranking by combined rate, `max` truncation, empty-input guards                                        |
| `network_intel.rs`     | 10    | Each of the four detectors; DNS analytics aggregation; latency bucketing; bandwidth alert state machine; `split_host_port` |
| `health.rs`            | 8     | `parse_loss` (zero / partial / full), `parse_avg_rtt`, `RttHistory` window cap, `Option<f64>` gap preservation            |
| `system.rs`            | 14    | `parse_proc_loadavg`, `parse_proc_meminfo` (with/without `MemAvailable`), `parse_proc_swap`, `parse_vm_stat`, `parse_macos_swapusage`, `parse_proc_cpuinfo_model` |
| `config.rs`            | 11    | `parse_default_gateway_ip_route`, `parse_default_gateway_netstat` (Linux + macOS formats), `parse_first_nameserver` (comments, indent, keyword-prefix safety) |
| `disk.rs`              | 13    | `parse_proc_mounts` (real devices, virtual FS skip, snap/loop filtering), `parse_macos_mount` (root, firmlink skip), `parse_proc_diskstats` (sector summing, loop/ram/dm-* skip) |

## Test conventions in this repo

- **Pure parsers are public** so they can be tested directly without spawning a process. `parse_ss_output`, `parse_nettop_output`, and `parse_lsof` all live as `pub fn`s at module scope.
- **Live tests are gated on tool availability** so the suite stays green on minimal CI images:

  ```rust
  #[test]
  fn live_ss_returns_something() {
      if std::process::Command::new("ss").arg("--version").output().is_err() {
          return; // ss not installed; skip
      }
      let conns = collect_connections();
      // …assert structural properties, not exact contents…
  }
  ```

- **Detector tests build a collector and feed it events** — they don't mock time, they just push enough events into a fresh `NetworkIntelCollector` to cross the threshold. Look at `network_intel.rs` tests for the pattern when adding a new detector.
- **No async runtime assumptions.** All tests are synchronous `#[test]`. If you add a stateful collector that needs a runtime, gate the test behind a feature.

## Running a subset

```sh
cargo test --test ''                                # all unit tests
cargo test parse_ss                                 # by name pattern
cargo test --package netwatch-sdk -- --nocapture    # see println! output
```

## Coverage gaps worth knowing

- **`system::measure_cpu_usage` and `measure_cpu_per_core` aren't tested** because they sleep and read live `/proc/stat`. Reaching them needs the FsReader seam (Phase 3 in `docs/plans/test-coverage.md`).
- **`libc::statvfs` paths in `disk::stat_mount` aren't tested** — same class of problem as the CPU sampling. Unsafe syscall, no mock today.
- **Live `connections::collect_connections` runs `ss`/`lsof`/`nettop` against the real machine.** The test asserts only "no panic; results are well-formed", because exact contents depend on the host.
- **Cross-platform behaviour is verified by running CI on both Linux and macOS runners**, not by mocking each platform from the other.

## Measuring coverage

CI runs `cargo-llvm-cov` on every push and uploads an `lcov.info` artifact. The job fails if line coverage drops below **70 %** (current baseline is ~76 %, so there's modest headroom).

To reproduce locally:

```sh
cargo install cargo-llvm-cov            # one-time
rustup component add llvm-tools-preview # one-time
cargo llvm-cov --lib --summary-only
```

Per-file baseline at the time of writing:

| File                              | Lines  |
| --------------------------------- | -----: |
| `collectors/process_bandwidth.rs` |  99 %  |
| `collectors/traffic.rs`           |  94 %  |
| `collectors/config.rs`            |  85 %  |
| `collectors/disk.rs`              |  84 %  |
| `collectors/connections.rs`       |  78 %  |
| `collectors/network_intel.rs`     |  74 %  |
| `collectors/health.rs`            |  65 %  |
| `collectors/system.rs`            |  62 %  |
| `platform/linux.rs`               |   0 %  |
| **Total**                         | **76 %** |

`platform/linux.rs` is at 0 % because nothing in the test suite calls `collect_interface_stats()` directly — `traffic` tests construct an `InterfaceStats` map by hand. That's by design: platform shims are exercised by the integration suite in the agent, not by SDK unit tests.

The remaining ~16 % on `disk.rs` is the unsafe `libc::statvfs` path inside `stat_mount`. Reaching it from a unit test would require an `FsReader`-style seam — see `docs/plans/test-coverage.md` Phase 3.

Once coverage trends up, raise `--fail-under-lines` in `.github/workflows/ci.yml` so the floor moves with you.

## Pre-commit hook (recommended)

Same pattern as the netwatch / netscan repos:

```sh
cat > .git/hooks/pre-commit <<'SH'
#!/bin/sh
set -e
if ! cargo fmt --check; then
    echo "rustfmt would rewrite files above. Run: cargo fmt && git add -u"
    exit 1
fi
SH
chmod +x .git/hooks/pre-commit
```

If you also want clippy and tests to run before each commit, append them — but be aware they slow commits noticeably and CI catches them anyway.
