<p align="center">
  <img src="https://raw.githubusercontent.com/patronus-protect/patronus-security/main/docs/img/patronus-ark-banner.svg" alt="Patronus Ark — local security scanning for AI and agent traffic" width="100%">
</p>

<p align="center">
  <a href="https://crates.io/crates/patronus-ark-core"><img src="https://img.shields.io/crates/v/patronus-ark-core.svg?style=flat-square&logo=rust&logoColor=white" alt="crates.io"></a>
  <a href="https://pypi.org/project/patronus-ark-core/"><img src="https://img.shields.io/pypi/v/patronus-ark-core.svg?style=flat-square&logo=pypi&logoColor=white" alt="PyPI"></a>
  <a href="https://docs.rs/patronus-ark-core"><img src="https://img.shields.io/docsrs/patronus-ark-core?style=flat-square&logo=docsdotrs" alt="docs.rs"></a>
  <a href="https://patronus-protect.github.io/patronus-security/getting-started/core/"><img src="https://img.shields.io/badge/docs-ark--core-38bdf8?style=flat-square" alt="Documentation"></a>
  <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-34d399?style=flat-square" alt="License: MIT OR Apache-2.0">
</p>

# Patronus Ark Core

**Synchronous, local scanning for PII, DLP and prompt injection — native rules plus optional
[Wolf Defender](https://huggingface.co/patronus-studio/wolf-defender-prompt-injection-small) inference.**

Ark Core is the standalone core of [Patronus Ark](https://github.com/patronus-protect/patronus-security).
It runs the native L1 detectors and, when enabled, a local prompt-injection model on the calling
thread: no request queue, no worker threads, no L2/L3 models, no network calls during a scan.
Full Ark builds on the same detectors, so rule IDs and L1 findings are identical in both.

Use Core when you embed scanning in your own process — an agent hook, a proxy, a CLI, a desktop
app — and PII, DLP and prompt injection cover your policy. Use
[full Ark](https://github.com/patronus-protect/patronus-security#choose-a-package) for the
model-backed categories, L2→L3 promotion and the async queue.

## Install

```bash
cargo add patronus-ark-core              # native rules only
cargo add patronus-ark-core -F wolf      # + Wolf inference from local assets
cargo add patronus-ark-core -F download  # + Wolf and the official asset downloader
pip install patronus-ark-core            # Python 3.11+
```

| Feature | Adds |
| --- | --- |
| *(none)* | native PII, DLP and prompt-injection rules; no HTTP client, no ONNX Runtime |
| `wolf` | local Wolf Defender inference through ONNX Runtime |
| `download` | `wolf` plus the asset downloader used by `Scanner::warmup` |
| `onnx-coreml`, `onnx-cuda`, `onnx-directml`, `onnx-tensorrt` | GPU execution providers for Wolf |

The [Python package](https://github.com/patronus-protect/patronus-security/blob/main/ark-core/python/README.md) (`patronus_ark_core`) exposes the same scanner. Its
published wheels include CPU Wolf support.

## Quickstart

```rust
use patronus_ark_core::{Scanner, ScannerConfig};

let mut scanner = Scanner::new(ScannerConfig::default())?;
let report = scanner.scan("Text to inspect")?;
for result in &report.native {
    println!("{} {} {:.2}", result.category, result.class_name, result.confidence);
    for span in &result.evidence_spans {
        println!("  {} at bytes {}..{}", span.label, span.start_byte, span.end_byte);
    }
}
```

`ScannerConfig::default()` scans all three categories. The configuration also takes:

- `categories` — any of `Pii`, `Dlp`, `Injection`;
- `rules` — per-rule gates keyed by the stable IDs in the
  [L1 rule catalog](https://patronus-protect.github.io/patronus-security/reference/l1-rule-catalog/);
- `pii_mode`, `dlp_mode` and `explain` — the scoring modes and anchor context shared with full Ark;
- `max_input_bytes` (default 1 MiB) and `max_findings` (default 10,000 evidence spans) — exceeding
  either returns an error, never a truncated clean report;
- `wolf` — the optional model configuration (see below).

## Reading a report

A `ScanReport` has three parts:

- `input_bytes` — the size of the scanned input;
- `native` — one `NativeResult` per category with `class_name`, `confidence`, the ordered `layers`,
  `label_scores`, `decision` and `evidence_spans` (UTF-8 byte and character offsets);
- `wolf` — the separate `WolfResult` (`attack_probability`, `threshold`, `matched`, `windows`, model
  revision and precision), or `None` when Wolf is not configured.

Core reports; your application decides whether to block, redact or log. Judge native results by
class, evidence and decision: a native layer's `matched` flag can be true for a `safe` class.
`WolfResult::matched` means the attack probability met your threshold.

## Choose checks per input

One scanner can skip categories for a single input. Checks are intersected with the configured
categories; skipping `injection` also skips Wolf.

```rust
use patronus_ark_core::ScanChecks;

let report = scanner.scan_with_checks(
    tool_output,
    ScanChecks { pii: false, dlp: true, injection: true },
)?;
```

## Wolf Defender

Wolf Defender is a local prompt-injection classifier. Configure a bundle directory and a threshold
on the attack probability; thresholds are deployment-specific, the examples use `0.8`.

```rust
use patronus_ark_core::{DownloadPolicy, Scanner, ScannerConfig, WarmupOptions};
use patronus_ark_core::wolf::WolfConfig;

let mut config = ScannerConfig::default();
config.wolf = Some(WolfConfig::new("/srv/models/wolf-defender", 0.8));
let mut scanner = Scanner::warmup(config, WarmupOptions {
    download: DownloadPolicy::Missing,
    ..WarmupOptions::default()
})?;
let report = scanner.scan("Please summarize the meeting agenda.")?;
```

**Assets and downloads.** Only construction touches assets; scans never download.

- `Scanner::new` uses an existing bundle and never downloads.
- `Scanner::warmup` (`download` feature) prepares missing official files first. The default policy
  is `DownloadPolicy::Never`, which accepts an existing complete bundle as is. `Missing` fills an
  empty or managed cache from the official Wolf revision; an unknown, incomplete bundle is rejected
  rather than mixed with official files.
- `warmup::prepare_assets(&config, &options)` runs the preparation alone, for a separate delivery
  step or an air-gapped install; then construct with `Scanner::new`.
- Downloads use file locks and publish completion metadata atomically, so partial downloads are
  never treated as ready. `download_timeout_ms` (default 600,000) budgets lock waiting, retries and
  reads.

A bundle holds the ONNX export(s), `tokenizer.mmbpe` or `tokenizer.json`, and `config.json` for
label and padding metadata. An optional `wolf.manifest.json` pins BLAKE3 hashes, revision,
tokenization settings and numerical reference cases; when present it is validated at load.

**Precision and backend.** `precision` is `auto`, `fp16` or `int8_int4`. `auto` prefers INT8/INT4,
or FP16 when `PATRONUS_L3_PRECISION=fp16`, and falls back to the other available export; an
explicit choice requires that export. `backend` and `runtime_options` select the ONNX Runtime
provider and threads; the default CPU profile uses one intra-op and one inter-op thread.

**Long inputs.** Wolf scores a whole document over token windows and pools them with a smooth max:

```text
logit       = 0.1 * (logsumexp(window_logits / 0.1) - log(window_count))
probability = sigmoid(logit)
```

Every window counts; there is no early exit and no fallback to L1 on model error. The default is
256 tokens per window (254 content tokens plus BOS/EOS), no overlap, batch 1. Change it with
`WolfExecutionOptions`:

```rust
use patronus_ark_core::WolfExecutionOptions;

let execution = WolfExecutionOptions {
    window_tokens: 2048, // includes BOS/EOS: up to 2046 content tokens
    overlap_tokens: 256, // content stride: 1790 tokens
    batch_size: 4,       // windows of one document, not concurrent requests
};
let mut scanner = Scanner::new_with_wolf_options(config, execution)?;
```

`Scanner::warmup_with_wolf_options` does the same with asset preparation. Window and overlap change
the document scores, and INT8/INT4 batches can shift logits through dynamic quantization, so
recalibrate the threshold when you change either. Memory is bounded by window and batch size.

## Timeouts, cancellation and concurrency

A `Scanner` owns one warm session and scans take `&mut self` on the calling thread; the host
controls parallelism, for example with a pool of scanners. Restarting or creating a scanner warms
a new session; cached assets are reused.

```rust
use std::time::Duration;
use patronus_ark_core::{ScanChecks, ScanControl};

let control = ScanControl::with_timeout(Duration::from_millis(200))?;
let report = scanner.scan_with_control(text, ScanChecks::default(), &control)?;
```

- The budget starts when the `ScanControl` is created; reusing a control shares what is left.
- `control.cancel()` from another thread stops native stages at their next checkpoint and
  terminates an active ONNX run.
- A cancelled or expired scan returns an error, never a partial report.
- ONNX deadlines share one process-wide timer thread; scans never spawn a thread per call.

## Embedding in a host

Hosts that keep their own levels, queues and result mapping can drive the detectors directly
through `native::NativeEngine`, as full Ark does. It initializes only the selected categories and
creates no threads. `NativeEngine::producers(category)` returns the producers in their established
order; check `producer.enabled(policy)` before `run_producer`. `NativePolicy` carries rule choices,
explain mode and scoring modes. The engine returns raw `NativeDetection`s; the host keeps its error
policy, evidence filtering, confidence mapping and aggregation. Core stops a scan on detector
failure, while Ark degrades per producer — pick one policy and don't substitute the other silently.

`ml::text_classifier::OnnxTextClassifier` is the general synchronous ONNX sequence classifier that
full Ark re-exports. It accepts `[batch, classes]` (or `[classes]` for batch one) Float32/Float16
logits and rejects inconsistent shapes and non-finite values.

## Development

```sh
cargo test -p patronus-ark-core                  # native detectors
cargo test -p patronus-ark-core --features wolf  # + pooling, tokenizer and synthetic ONNX runtime
```

`tests/fixtures/wolf_synthetic_fp16.onnx` exercises runtime behavior only; it is not a Wolf
checkpoint. Checks against real assets are opt-in:

```sh
# FP16 export vs. an independent Hugging Face tokenizer + direct ONNX Runtime oracle
ARK_WOLF_BUNDLE=/path/to/bundle cargo test -p patronus-ark-core --features wolf \
  published_fp16_254_profile_matches_independent_hf_ort_oracle -- --ignored

# window/overlap/batch profiles (repeat with ARK_WOLF_PRECISION=int8_int4)
ARK_WOLF_BUNDLE=/path/to/fp16 ARK_WOLF_PRECISION=fp16 \
  cargo test -p patronus-ark-core --features wolf --test wolf_profiles -- --ignored --nocapture

# latency and RSS: bundle, threshold, window, overlap, batch, short-input samples
cargo run --release -p patronus-ark-core --features wolf --example wolf_benchmark -- \
  /path/to/bundle 0.8 2048 256 4 16

# copy existing FP16 assets into a new bundle with a compact tokenizer
cargo run --release -p patronus-ark-core --features wolf \
  --example prepare_wolf_bundle -- /path/to/existing-assets /path/to/new-bundle 0.8
```

Reference checks allow an absolute logit error of 0.02 plus 0.005 relative, and at most 0.005
absolute probability error for the FP16 export against its FP32 reference. The tokenizer parity
test needs `PATRONUS_TEST_PYTHON`, `PATRONUS_TEST_MMBERT_TOKENIZER_JSON` and
`PATRONUS_TEST_MMBERT_TOKENIZER_MMBPE`.

## License

Core code and Core-authored rule catalogs are licensed under **MIT OR Apache-2.0**
([LICENSE-MIT](https://github.com/patronus-protect/patronus-security/blob/main/ark-core/LICENSE-MIT), [LICENSE-APACHE](https://github.com/patronus-protect/patronus-security/blob/main/ark-core/LICENSE-APACHE)). Per-rule `source_license` fields
record upstream provenance and do not change that license; third-party catalog notices are kept.
The full `patronus-ark` runtime has its own license.
