# Testing

```sh
cargo test
```

That's the whole thing — no fixtures, no test database, no env vars required. The tests run on Linux and macOS; the live ones skip themselves when the underlying tool isn't available.

## What's covered

About 40 unit tests, weighted toward parsing and state-machine logic. The shape of the suite:

| Module                     | Tests | What they actually exercise                                                                |
| -------------------------- | ----: | ------------------------------------------------------------------------------------------ |
| `traffic.rs`               | 4     | First-call zero rates; history accumulation; 60-sample window cap; eviction of dropped interfaces |
| `connections.rs`           | 8     | `parse_ss_output`, `parse_nettop_output`, `parse_lsof`, RTT merge, `top_connections` ranking |
| `process_bandwidth.rs`     | 5     | Proportional split, ranking by combined rate, `max` truncation, empty-input guards         |
| `network_intel.rs`         | 12    | Each of the four detectors; DNS analytics aggregation; latency bucketing; bandwidth alert state machine; `split_host_port` |
| `health.rs`                | 8     | `parse_loss` (zero / partial / full), `parse_avg_rtt`, `RttHistory` window cap, `Option<f64>` gap preservation |
| `system.rs`, `disk.rs`, `config.rs` | 0 | Rely on syscall/libc behavior — covered by integration in the agent rather than here       |

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

- **`system::*` and `disk::*` aren't unit-tested** — they're thin wrappers around platform APIs and tests would essentially mirror the implementation. The downstream agent integration test catches regressions.
- **Live `connections::collect_connections` runs `ss`/`lsof`/`nettop` against the real machine.** The test asserts only "no panic; results are well-formed", because exact contents depend on the host.
- **Cross-platform behaviour is verified by running CI on both Linux and macOS runners**, not by mocking each platform from the other.

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
