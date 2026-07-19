# Testing

The suite has Rust unit/integration tests and Python binding tests. CI runs both on every push
and pull request.

## Pre-PR checks

Run all three before opening a pull request — these mirror CI:

```bash
# 1. Formatting
cargo fmt --check

# 2. Rust unit + integration tests
cargo test -p patronus-security

# 3. Python binding tests (after `maturin develop`)
.venv/bin/python -m unittest discover -s python/tests
```

## What the tests cover

### Rust (`rust/tests/`)

| File | Focus |
| --- | --- |
| `native_detectors.rs` | Native L1 detector behavior. |
| `pipeline_units.rs`, `pipeline_routing.rs` | Pipeline composition and per-category routing. |
| `ml_units.rs` | ML/ONNX units. |
| `l3_scheduler.rs` | L3 worker scheduling, fairness, max-wait. |
| `unified_l3.rs` | Unified multi-head L3 behavior. |
| `dynamic_pii.rs` | GLiNER dynamic-PII pipeline. |
| `assets_manifest.rs` | Asset manifest integrity. |
| `hf_e2e.rs` | End-to-end with real Hugging Face assets (needs network / `HF_TOKEN`). |

### Python (`python/tests/`)

| File | Focus |
| --- | --- |
| `test_public_api.py` | The public `SecurityGateway` surface and result shapes. |
| `test_native_scanners.py` | Native scanning through the bindings. |
| `test_benchmark_data.py` | Integrity of the shipped benchmark validation samples. |

## Network-dependent tests

`hf_e2e.rs` and anything that exercises L2/L3 needs model assets. Provide `HF_TOKEN` if the
repositories require authentication. Tests that only exercise native L1 run fully offline.

## Benchmarking (not a correctness gate)

The [local benchmark](../how-to/run-local-benchmark.md) measures accuracy, latency, and
false-positive rate on the shipped samples. It is a measurement tool, not a pass/fail test —
use it to validate performance changes, not as part of the PR gate. Do **not** commit benchmark
output (it is machine-specific and git-ignored).

## Adding tests

- New native detector → add cases to `native_detectors.rs` and, if exposed, `test_native_scanners.py`.
- New public API → extend `test_public_api.py` so the result shape is pinned.
- Threshold/manifest/result-shape change → update the affected tests and call it out in the PR.
