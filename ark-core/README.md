# Patronus Ark Core

Synchronous local PII, DLP and prompt-injection scanning. The default build
contains native detectors only; the `wolf` feature enables local inference with
Wolf Defender.
There is no request queue, L2 runtime or promotion router.

The independently licensed [Python package](python/README.md),
`patronus-ark-core`, exposes the same scanner and optional Wolf runtime through
PyO3 bindings. It does not depend on the full Ark runtime.

```rust
use patronus_ark_core::{Scanner, ScannerConfig};
let mut scanner = Scanner::new(ScannerConfig::default())?;
let report = scanner.scan("Text to inspect")?;
# Ok::<(), patronus_ark_core::ScanError>(())
```

Native rules, scored PII/DLP modes, source offsets, registry ordering and
post-prediction evidence filtering are shared with `patronus-ark`. Reports
keep native findings and model results separate. A `Scanner` owns one warm
session and takes `&mut self`; the host controls parallelism.

`scan()` runs the configured stages. Hosts selecting checks per input can use
`scan_with_checks(text, ScanChecks { pii, dlp, injection })` on the same scanner.
Disabling `injection` skips both native PI producers and model inference; native
checks still respect the configured categories, rule gates and resource limits.

`scan_with_control(text, checks, &control)` accepts a shared `ScanControl` for
cancellation and a configurable deadline. An active ONNX run receives Runtime
termination; native stages stop at their next checkpoint. No partial report is
returned on cancellation. Scans execute on the calling thread. Active ONNX runs
with finite deadlines share one process-wide timer thread; registrations are removed
when a run finishes. Scans never create a timer thread per call or batch.
`ScanControl::with_timeout` starts its budget when the control is constructed,
not when inference starts. Reusing a control shares its remaining budget across calls.

Default limits: 1 MiB per input and 10,000 actionable evidence spans. Limits
are configurable; exceeding either returns an error, never a truncated clean
report. Native text views and findings grow with input size. Wolf's working
set uses bounded BPE pieces, configured windows/batches and constant-size pooling state;
model weights and the bounded tokenizer cache remain loaded. Individual
unsplittable BPE pieces larger than 128 KiB are refused. They are never split
at arbitrary byte positions, which would change training tokenization.

## Shared native execution

`Scanner` remains the public queue-free facade used by embedded integrations.
Full Ark uses the same initialized detector state through `native::NativeEngine`,
while keeping its own levels, conditional gates, request queues and result mapping.
The engine initializes only selected categories and creates no worker threads.

`NativeEngine::producers(category)` returns opaque descriptors in the established
order. Call `producer.enabled(policy)` before `run_producer`; this centralizes
parent-model, model and required-rule gates. `NativePolicy` supplies existing rule
choices, explain mode and PII/DLP scoring modes without copying host configuration.
The engine returns raw `NativeDetection` and elapsed time. The host retains its
error policy, evidence filtering, confidence mapping and final aggregation.

Existing `Scanner`, `WolfRunner`, configuration, report and error interfaces stay
available. Core stops a native scan on detector failure; Ark can preserve its
per-producer degradation. A host must not silently substitute one policy for the other.

## Asset preparation and warmup

The `download` feature enables the shared Ark asset downloader and includes Wolf
inference. Native-only builds retain no HTTP client or ONNX dependency.

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
# Ok::<(), patronus_ark_core::ScanError>(())
```

`Scanner::warmup` prepares missing official files, then creates one warm scanner.
Subsequent scans reuse that session. Client/provider guards can share the scanner;
requests, tool steps and token windows do not create sessions or rerun warmup.
Restarting or creating a new scanner warms its own session; assets stay cached.

`WarmupOptions::default()` uses `download = "never"`. Existing complete local
bundles are accepted without a new pin, manifest or writes to the bundle.
`download = "missing"` uses the existing official Wolf revision when an empty or
trusted managed cache needs files. Unknown incomplete local bundles are rejected
rather than mixed with official files: supply their matching assets or use an
empty cache directory. Managed preparation uses file locks and atomically
publishes completion metadata; partial downloads are not ready assets.

`download_timeout_ms` defaults to `600000`. It budgets preparation lock waiting,
HTTP retries and reads, not ONNX session construction. OS DNS and filesystem
operations follow their system behavior. Errors prevent scanner startup.

For separate delivery/startup phases, call
`warmup::prepare_assets(&config, &options)` first, then `Scanner::new(config)`.
Preparation creates no tokenizer or model session. Full Ark's existing
`prepare_assets()` and `warmup()` reuse the same Wolf preparation and transport.

## Wolf Defender

Window size, content overlap and ONNX batch size are shared execution options:

```rust
use patronus_ark_core::{Scanner, ScannerConfig, WolfExecutionOptions};
use patronus_ark_core::wolf::WolfConfig;
let mut config = ScannerConfig::default();
config.wolf = Some(WolfConfig::new("/srv/models/wolf-defender", 0.8));
let execution = WolfExecutionOptions {
    window_tokens: 2048, // Includes BOS/EOS: up to 2046 content tokens.
    overlap_tokens: 256, // Content stride: 1790 tokens.
    batch_size: 4, // Windows of one document, not concurrent requests.
};
let mut scanner = Scanner::new_with_wolf_options(config, execution)?;
let report = scanner.scan("Please summarize the meeting agenda.")?;
# Ok::<(), patronus_ark_core::ScanError>(())
```

`Scanner::warmup_with_wolf_options(config, warmup, execution)` also prepares assets.
Existing constructors use `WolfExecutionOptions::default()`: 256 total tokens,
overlap 0, batch 1. Options are available without the `wolf` feature for adapter
configuration. Core validates positive batch size, overlap below content capacity,
checked tensor sizes and the actual export dimensions at initialization. A static
batch-one export cannot be configured for larger batches; local model position
limits also apply. Existing Small assets need no new pin or metadata.

All windows contribute once to the same document Smooth Max. Final partial batches
contain only actual windows; shorter rows receive padding and attention masks.
Overlap alone does not generate an extra final window. Cancellation terminates
the active ONNX batch and returns an error rather than partial success. Texts
and requests remain separate documents. Memory is bounded by the chosen window
and batch, while ONNX activations may grow nonlinearly with sequence length.
Changing window/overlap changes the model's document scores. The INT8/INT4 export
also contains dynamic activation quantization: mixed-row batches can change its
quantization scales and logits, even for unchanged windows. Batch-one and batched
scores are therefore not interchangeable calibration profiles. Both exports are
checked against direct ORT inference; FP16 additionally matches batch-one logits
within the tested numerical tolerance. No universal probability-error bound is
claimed for quantized batches.

Full Ark re-exports the synchronous `ml::text_classifier::OnnxTextClassifier`
from Core; its lazy loader, session TTL and queue remain host adapters. Both
that classifier and Wolf use the same Core batch-input assembler for boundary
tokens, padding and attention masks. Dedicated Wolf jobs forward the original
document directly, without preparing throwaway classifier chunks in Ark.

Full Ark reuses this implementation through
`SecurityGateway::set_wolf_execution_options` or
`ScanExecution::set_wolf_execution_options`. Its other model runtimes and generic
chunk-overlap options retain their existing behavior.

Enable `wolf` and configure `WolfConfig::new(bundle_dir, threshold)`. The
threshold is required, finite and in `[0,1]`, and applies to attack probability.
`Scanner::new` and scanning never download assets. The default CPU profile uses one intra-op and one inter-op thread.
`backend` and `runtime_options` share Ark's existing ONNX Runtime configuration;
provider features are optional. Real export parity was verified on CPU.

Use an existing local ONNX artifact with `tokenizer.mmbpe` or
`tokenizer.json`. The JSON fallback uses the same converter in memory and
writes no cache or metadata into the existing asset directory.
Set `precision` to `auto`, `fp16` or `int8_int4`. Auto retains Ark's preference
for INT8/INT4, or FP16 when `PATRONUS_L3_PRECISION=fp16`; it falls back to the
other available export. Explicit choices require that export. Existing directory
layouts are discovered automatically; `config.json` supplies
label and padding metadata, and `.patronus-revision` records asset provenance
when available. Existing Ark assets keep their current revision and need no
manifest migration. A short inference warms the configured backend on load.

An optional `wolf.manifest.json` can explicitly pin BLAKE3 hashes, model revision,
output semantics, tokenization settings and numerical reference cases. When
present, its constraints are validated. Missing required assets, incompatible
inputs, non-finite outputs and failed optional reference checks are errors.
The default Ark profile uses 254 content tokens plus BOS and EOS (256 total), overlap zero.
Execution options select the window width; old optional manifests cannot silently change it.
Scalar outputs are binary attack logits; two-class outputs use the declared
`[benign, attack]` margin.

Document pooling matches `runtime/wolf.py:smooth_max`:

```text
logit = 0.1 * (logsumexp(chunk_logits / 0.1) - log(chunk_count))
probability = sigmoid(logit)
```

All windows are evaluated. There is no highest-window decision, probability
averaging, L1-to-L3 gate, early positive exit or fallback to L1 on model error.
Full-text tokenization is streamed at the tokenizer's real piece boundaries,
including added tokens, before grouping tokens into model windows.

Optionally copy existing FP16 assets to a separate directory with the Rust helper:

```sh
cargo run --release -p patronus-ark-core --features wolf \
  --example prepare_wolf_bundle -- /path/to/existing-assets /path/to/new-bundle 0.8
```

This copies the existing FP16 artifact, tokenizer and available model metadata,
generates the compact tokenizer with the shared Rust converter, and performs
a local ONNX Runtime inference. It generates no mandatory manifest, does not
repin or download assets, and never overwrites an existing output directory.
The helper leaves the application's explicit threshold unchanged.

Compare the 254-token profile against an independent Hugging Face tokenizer and
direct Rust ONNX Runtime oracle, including long documents:

```sh
ARK_WOLF_BUNDLE=/path/to/bundle cargo test -p patronus-ark-core --features wolf \
  published_fp16_254_profile_matches_independent_hf_ort_oracle -- --ignored
```

Historical 256-content-token reference values remain identified as that profile;
they are not relabeled as 254-token references or run at production startup.

Reference checks use absolute logit tolerance 0.02 plus relative tolerance
0.005, and independently require at most 0.005 absolute probability error for the published FP16 artifact versus its FP32 reference.
These are numerical export tolerances, not blocking thresholds. Dynamic
sequence length avoids computing padding positions on short windows while
retaining the configured content-token maximum.

MCP policy/runtime checks remain shared because they are part of Ark's existing
DLP-L1 behavior. The separate Threat-category detector remains in full Ark.

## Verification and compatibility

`cargo test -p patronus-ark-core` runs native checks. Add `--features wolf`
for pooling, tokenizer and synthetic ONNX runtime checks. The tiny model in
`tests/fixtures/wolf_synthetic_fp16.onnx` tests runtime behavior only; it is
not a Wolf checkpoint or evidence of classifier quality. Pooling reference
values were generated from the supplied PyTorch Single training function.

Existing Ark public imports are retained through re-exports. Dedicated Wolf
uses the same Core document runner and precision selection from the
existing pinned asset bundle. Compact-tokenizer preparation stays shared;
no new manifest or asset revision is required. Other classifiers and the
unified model keep their execution paths.

## License

Core implementations and Core-authored rule definitions are licensed under
MIT OR Apache-2.0. The bundled Core-authored catalogs carry that same declaration.
Per-rule `source_license` fields describe referenced upstream provenance and are
retained as such; they do not change the license of the Core-authored implementation.
Existing third-party catalog notices remain intact. The consuming `patronus-ark`
package retains its existing license.

Real-export profile tests (repeat with `int8_int4` and its existing asset directory):

```sh
ARK_WOLF_BUNDLE=/path/to/fp16 ARK_WOLF_PRECISION=fp16 \
  cargo test -p patronus-ark-core --features wolf --test wolf_profiles -- --ignored --nocapture
```

The tests compare batch sizes 1, 2 and 4 at 256 total tokens (with and without
64-token overlap) and 2048 total tokens with 256-token overlap, using each export
as its own numerical baseline. Synthetic fixtures additionally assert exact row
mapping, attention-mask padding, partial batches, overlap and progress.

For isolated latency/RSS measurements, the benchmark accepts optional total window
size, overlap, batch size and short-input sample count after the threshold:

```sh
cargo run --release -p patronus-ark-core --features wolf --example wolf_benchmark -- \
  /path/to/bundle 0.8 2048 256 4 16
```


The opt-in tokenizer parity test uses the repository fixture materializer, including
DLP generator recipes. Set `PATRONUS_TEST_PYTHON` to the project's virtual-environment
Python when running it, alongside `PATRONUS_TEST_MMBERT_TOKENIZER_JSON` and
`PATRONUS_TEST_MMBERT_TOKENIZER_MMBPE`. This fixture tooling is test-only.

## General ONNX classification

`ml::text_classifier::OnnxTextClassifier` is the synchronous sequence classifier
also re-exported by Ark. Its existing constructors and inference methods remain
available. Class names must be nonempty, and model logits must have matching
`[batch, classes]` dimensions (`[classes]` is accepted for batch one). Float32 and
Float16 outputs are supported; inconsistent shapes and non-finite values are errors.
Wolf scalar/margin decoding uses the separate `WolfRunner` contract.

Model-produced raw outputs are validated before return. For manually constructed
`RawClassifierOutput`, use the additive `try_decode` and `try_probabilities`
methods. Existing unchecked methods remain available for compatibility.

For native L1 layers, the legacy `LayerResult.matched` flag may be true even when
`class_name` is `safe`; it is not a universal attack flag. Hosts should interpret
the class, evidence and decision for their policy. `WolfResult.matched` specifically
means that attack probability meets the configured Wolf threshold.
