# Testing

The suite has Rust unit/integration tests and Python binding tests. CI runs both on pushes to
`main` and on internal pull requests.

## Pre-release checks

Use the repository-pinned Rust toolchain and a fresh Python 3.12 virtual environment
for CI parity. Install `requirements-test.txt`: the script tests need NumPy even
though the published Ark wheel has no Python runtime dependencies.

Run these before merging or releasing — these mirror the correctness jobs in CI:

```bash
.venv/bin/python -m pip install -r requirements-test.txt
.venv/bin/python -m maturin develop --manifest-path python/Cargo.toml

# Formatting and lint (Rust 1.98.0)
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings

# Rust unit + integration tests
cargo test -p patronus-ark
cargo test -p ark-api

# Python binding and benchmark-script tests
.venv/bin/python -m unittest discover -s python/tests
.venv/bin/python -m pytest scripts/tests -q
.venv/bin/python scripts/generate_docs.py --check
cargo deny check licenses
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

## Token pipeline (no inference)

`cargo test -p patronus-ark --lib token_pipeline_e2e` exercises compact tokenization,
v4 L2-output materialization, promotion, duplicate-head handoff, and L3 input
assembly without loading either model. `cargo test -p patronus-ark --lib ml::tokenizer`
also checks input byte limits, exactly-once window encoding, true source offsets,
BOS/EOS, padding, and rejection instead of truncation or Hugging Face fallback.
These tests use the small checked-in compact fixture and run in normal CI.

The ignored `mmbert_mmbpe_matches_huggingface_ids_and_special_tokens` test additionally
compares the real compact artifact's IDs and source offsets with its conversion
source, then verifies token-only L3 input assembly. Set `PATRONUS_TEST_MMBERT_TOKENIZER_JSON`
and `PATRONUS_TEST_MMBERT_TOKENIZER_MMBPE` to the pinned local tokenizer artifacts
and run that test with `-- --ignored`. It performs no model inference.

## Network-dependent tests

`hf_e2e.rs` and anything that exercises L2/L3 needs model assets. Provide `HF_TOKEN` if the
repositories require authentication. Tests that only exercise native L1 run fully offline.

## Benchmarking (not a correctness gate)

The [local benchmark](../how-to/run-local-benchmark.md) measures accuracy, latency, and
false-positive rate on the shipped samples. It is a measurement tool, not a pass/fail test —
use it to validate performance changes, not as part of the PR gate. Do **not** commit benchmark
output (it is machine-specific and git-ignored).

Separately, CI's `native-throughput` job installs a fresh release wheel and runs
`scripts/ark_api_throughput_benchmark.py` against the real L1/L2/unified-L3 profile,
without GLiNER. Its 0.3 MiB/s and 0.5 requests/s limits are pass/fail gates; a local
macOS result does not prove that the Linux runner passes them.

## Adding tests

- New native detector → add cases to `native_detectors.rs` and, if exposed, `test_native_scanners.py`.
- New public API → extend `test_public_api.py` so the result shape is pinned.
- Threshold/manifest/result-shape change → update the affected tests and document it in the changelog.
