# Patronus Ark Core

Synchronous local PII, DLP and prompt-injection scanning. The default build
contains native detectors only; `wolf` adds offline Wolf Small FP16 inference.
There is no request queue, L2 runtime, promotion router or background worker.

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

Default limits: 1 MiB per input and 10,000 actionable evidence spans. Limits
are configurable; exceeding either returns an error, never a truncated clean
report. Native text views and findings grow with input size. Wolf's working
set uses bounded BPE pieces, batch size one and constant-size pooling state;
model weights and the bounded tokenizer cache remain loaded. Individual
unsplittable BPE pieces larger than 128 KiB are refused. They are never split
at arbitrary byte positions, which would change training tokenization.

## Wolf Single FP16

Enable `wolf` and configure `WolfConfig::new(bundle_dir, threshold)`. The
threshold is required, finite and in `[0,1]`, and applies to attack probability.
Loading and scanning never download assets. The default CPU profile uses one intra-op and one inter-op thread.
`backend` and `runtime_options` share Ark's existing ONNX Runtime configuration;
provider features are optional. Real export parity was verified on CPU.

A bundle contains a self-contained FP16 ONNX model, matching compact
`tokenizer.mmbpe`, and `wolf.manifest.json`. The manifest pins BLAKE3 hashes,
model revision, output name/semantics, tokenizer padding, and reference
chunk logits. It describes the Single contract: 256 content tokens plus BOS
and EOS, 258 input slots, overlap zero. Scalar outputs are binary attack
logits. A two-class export must prove its `[benign, attack]` margin against
the same training reference logits.

Every reference case runs on load, both as export verification and backend
warmup. Missing files, wrong hashes, incompatible inputs, non-finite outputs
and reference mismatches are errors. A filename alone does not establish
model precision or readiness.

Document pooling matches `runtime/wolf.py:smooth_max`:

```text
logit = 0.1 * (logsumexp(chunk_logits / 0.1) - log(chunk_count))
probability = sigmoid(logit)
```

All windows are evaluated. There is no highest-window decision, probability
averaging, L1-to-L3 gate, early positive exit or fallback to L1 on model error.
Full-text tokenization is streamed at the tokenizer's real piece boundaries,
including added tokens, before grouping tokens into model windows.

Prepare a bundle directly in Rust from the pinned Hugging Face snapshot:

```sh
cargo run --release -p patronus-ark-core --features wolf \
  --example prepare_wolf_bundle -- /path/to/snapshot /path/to/new-bundle 0.8
```

This copies the published FP16 ONNX artifact, generates the compact tokenizer
with the shared Rust converter, and verifies checksums, raw logits, full-text
tokenization and document pooling through ONNX Runtime. It never overwrites
an existing bundle or changes the application's explicit decision threshold.
The pinned contract is `assets/wolf-small-single-fp16.json`.

Reference checks use absolute logit tolerance 0.02 plus relative tolerance
0.005, and independently require at most 0.005 absolute probability error for the published FP16 artifact versus its FP32 reference.
These are numerical export tolerances, not blocking thresholds. Dynamic
sequence length avoids computing padding positions on short windows while
retaining the 256-content-token maximum.

## Verification and migration

`cargo test -p patronus-ark-core` runs native checks. Add `--features wolf`
for pooling, tokenizer and synthetic ONNX runtime checks. The tiny model in
`tests/fixtures/wolf_synthetic_fp16.onnx` tests runtime behavior only; it is
not a Wolf checkpoint or evidence of classifier quality. Pooling reference
values were generated from the supplied PyTorch Single training function.

Existing Ark public imports are retained through re-exports. Dedicated Wolf
uses the same Core document runner. Old 254-content-token bundles without
a verified Single manifest are rejected: prepare and install the corrected
bundle before enabling dedicated Wolf. Other classifiers and the unified
model keep their execution paths. The standard Ark asset-preparation path now creates the pinned verified manifest
after generating its compact tokenizer.

## License

MIT OR Apache-2.0. Embedded rule sources retain their provenance and license
metadata. The consuming `patronus-ark` package retains its existing license.
