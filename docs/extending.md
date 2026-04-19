# Extending the SDK

Three common extension points:

1. Adding a new payload field to the wire format.
2. Adding a new collector.
3. Adding a new alert detector to `network_intel`.

A fourth — adding a new platform — is sketched at the end of [`platform-support.md`](platform-support.md).

---

## 1. Adding a wire-format field

For an additive change (the only kind you should make without a major version bump):

1. **Pick the right struct.** Most additions belong on `Snapshot` (per-cycle data), `InterfaceMetric` (per-interface), or `SystemMetric` (per-host).
2. **Make it `Option<T>`** with `#[serde(default, skip_serializing_if = "Option::is_none")]`. Existing agents won't send it; new servers will see `None` and degrade. Existing servers will silently ignore it; new agents won't break old peers.
3. **Bump the minor version** of `netwatch-sdk` (`0.1.x → 0.2.0`). Pre-1.0 the SDK uses minor for additive changes.
4. **Document it in [`docs/wire-format.md`](wire-format.md).**

Example — adding a `kernel_version` to `HostInfo` is fine because it's already `Option<String>`. Adding a new `gpu: Option<GpuMetric>` to `Snapshot` is the same pattern: define `GpuMetric` with all-optional fields, drop it on the struct, mark `#[serde(skip_serializing_if = "Option::is_none")]`.

If you genuinely need a required field, that's a major version bump — coordinate with the agent and cloud teams before doing it.

---

## 2. Adding a new collector

Decide whether the collector is **stateless** (a free function) or **stateful** (a struct with `&mut` methods). The split is documented in [architecture.md](architecture.md#stateful-vs-stateless-collectors); choose the simpler one that does the job.

### Stateless collector (preferred)

A single file under `src/collectors/`, exported from `collectors/mod.rs`:

```rust
// src/collectors/gpu.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuMetric {
    pub name:           String,
    pub memory_used:    Option<u64>,
    pub utilization_pct: Option<f64>,
}

pub fn collect_gpus() -> Vec<GpuMetric> {
    #[cfg(target_os = "linux")]
    {
        // run nvidia-smi or read /sys/class/drm/cardN/, return Vec<GpuMetric>
        return read_gpus_linux();
    }
    #[cfg(not(target_os = "linux"))]
    Vec::new()
}
```

Then:

- `src/collectors/mod.rs` → `pub mod gpu;`
- `src/types.rs` → add `pub gpus: Option<Vec<GpuMetric>>` to `Snapshot` (re-exporting `GpuMetric` if needed).

The `cfg` pattern matches every other collector — concentrate the platform branching at the top of one function rather than scattering it everywhere.

### Stateful collector

If you need cross-call state (rolling window, accumulator, deltas), follow the `InterfaceRateTracker` template:

```rust
pub struct GpuRateTracker {
    last: HashMap<String, GpuStatsRaw>,
    last_at: Option<Instant>,
}

impl GpuRateTracker {
    pub fn new() -> Self { Self { last: HashMap::new(), last_at: None } }

    pub fn sample(&mut self) -> Vec<GpuMetric> {
        let now = Instant::now();
        let raw = read_gpus_raw(); // platform-specific
        let elapsed = self.last_at.map(|t| now.duration_since(t).as_secs_f64());
        // …compute deltas using self.last + raw, write rates into GpuMetric…
        self.last = raw_into_map(&raw);
        self.last_at = Some(now);
        out
    }
}
```

Document the cadence and the first-call behavior — those are the things consumers always get wrong.

### What to test

Pure parsers are the highest-leverage tests in this codebase:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_nvidia_smi_csv() {
        let sample = "name, memory.used, utilization.gpu\nNVIDIA RTX 4090, 1234, 12\n";
        let gpus = parse_nvidia_smi(sample);
        assert_eq!(gpus.len(), 1);
        assert_eq!(gpus[0].name, "NVIDIA RTX 4090");
        assert_eq!(gpus[0].memory_used, Some(1234));
    }
}
```

Compare against `connections::tests::*` — every shell-out has a parser test that takes a snippet of real output and asserts the parsed structure. Live tests that actually invoke the binary are gated on its presence (`if Command::new("foo").arg("--version").output().is_err() { return; }`).

---

## 3. Adding a new alert detector to `network_intel`

The four built-in detectors (port scan, beacon, DNS tunnel, bandwidth) all follow the same shape. To add a fifth (say, "abnormally large outbound transfers"):

1. **Add a variant to `AlertCategory`** in `network_intel.rs`:

   ```rust
   pub enum AlertCategory {
       PortScan, Beaconing, DnsTunnel, Bandwidth,
       LargeTransfer,           // ← new
   }

   impl AlertCategory {
       pub fn label(self) -> &'static str {
           match self { /* …existing arms…*/
               Self::LargeTransfer => "large transfer",
           }
       }
   }
   ```

   Adding a variant is a breaking change for any code that does `match` exhaustively on `AlertCategory`. If you expect more variants in the future, add `#[non_exhaustive]` to the enum in the same change.

2. **Add tracking state** to `NetworkIntelCollector`:

   ```rust
   pub struct NetworkIntelCollector {
       // …existing fields…
       transfers: HashMap<TransferKey, TransferState>,
   }
   ```

   Include cleanup in `tick()` so the map can't grow unbounded.

3. **Add an event** if the detector needs new input. Reuse `InterfaceRateEvent` or `ConnAttemptEvent` if you can; only define a new event type if the data isn't already in one.

4. **Detect and raise:**

   ```rust
   fn detect_large_transfer(&mut self, ev: &SomeEvent) {
       // …compute condition…
       if triggered {
           self.raise_alert(Alert {
               severity: AlertSeverity::Warning,
               category: AlertCategory::LargeTransfer,
               message: format!("Large outbound transfer to {}", ev.dst),
               detail:  format!("{:.1} MB in {:?}", ev.bytes as f64 / 1e6, ev.duration),
               timestamp: Utc::now(),
           });
       }
   }
   ```

   `raise_alert` is the existing helper that adds to both `active_alerts` and `alert_history`, dedupes, and respects the active TTL.

5. **Test it.** Each existing detector has a unit test that constructs a collector, feeds a sequence of events, and asserts on `active_alerts()`. Mirror the pattern.

6. **Document the new detector** in `collectors.md` under the threshold table.

---

## Don'ts

- **Don't add silent retries inside collectors.** They're called on the agent's clock — if the collector returns empty, the agent decides what to do (skip the field, retry next cycle, log).
- **Don't read system state inside `types.rs`.** That file is wire format only; collectors live next door.
- **Don't add a dependency to satisfy one collector.** If the collector needs something exotic (eBPF, kernel modules, IOKit), gate it behind a Cargo feature so callers who don't need it don't pay the build cost.
- **Don't break the wire format silently.** Bump the version when you add a field that affects existing payloads' interpretation, even if the change is technically additive.
