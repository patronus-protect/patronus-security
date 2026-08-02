# Performance & memory

Patronus Ark is built to sit in the request path on ordinary hardware — a laptop CPU, no
GPU required. This page explains the design levers that make that possible. For step-by-step
tuning, see [Tune performance & memory](../how-to/tune-performance.md); for the full
measurements and rationale, see
[`OPTIMISATIONS.md`](https://github.com/patronus-protect/patronus-security/blob/main/OPTIMISATIONS.md).

## Where the time goes

The layered design means cost is proportional to how far a scan escalates:

| Layer | Typical latency (batch 1) | Runs on |
| --- | --- | --- |
| L1 native | microseconds | every request |
| L2 NTDB | ~1 ms | when configured & cached |
| L3 transformer | tens of ms | only promoted requests |

Because most traffic is resolved at L1/L2, the expensive transformer runs for only the
uncertain minority. This is the single most important performance property of the system.

## The memory and latency levers

### Static-embedding L2

L2 uses a **static token-embedding encoder** shared across all categories in a process — no
per-token attention pass. One encoder serves seven categories, so L2 is cheap to run and cheap
to add categories to. See [NTDB format](models-and-ntdb.md).

### Quantized ONNX at L3

L3 transformers ship as a single combined INT8-weight / INT4-embedding ONNX variant, so a model
bundle is a few hundred MB on disk and a few hundred MB resident — small enough to run several
classifiers on a laptop. (`PATRONUS_DOWNLOAD_OPTIONAL_ASSETS=1` only adds non-required files such
as `tokenizer_config.json`; there is no separate full-precision ONNX asset.)

### Compact tokenizers

The L2 Granite embedder's tokenizer is converted once, on first use, into a compact `.kit` file
in the shared encoder cache (hash- and version-invalidated, with the source JSON as fallback),
which cuts load time and memory. A separate `.mmbpe` compact format exists for mmBERT-style
(Wolf) tokenizers. It is generated locally during verified asset downloads and cached warmup when
the tokenizer JSON has the supported byte-fallback BPE shape. The generated file stores explicit
merge-pair identity, is hash- and version-invalidated, and keeps the canonical Hugging Face
`tokenizer.json` as fallback.

### L3 sessions: built on first use, then RAM-resident

An L3 ONNX session is built the first time a scan reaches that model, then held **resident in
RAM** and evicted only after a long idle TTL (`PATRONUS_L3_TTL_SECS`, default 300 s). Models are
never hot-swapped per request, so you do not pay repeated load/unload costs under steady
traffic — but budget memory for the L3 models your configuration enables, since a hot model
stays resident. (The one exception is `dynamic-pii`: its GLiNER session is warmed eagerly during
`warmup()`, before any request, then follows the same idle-TTL eviction.)

### Cost-scheduled worker

The L3 worker schedules promoted jobs by **estimated and observed compute cost** (an EWMA of
real execution time), with a **max-wait guard** so no request starves, and processes work off
the request path so a slow transformer never blocks a fast L1/L2 answer.

### Long-text windowing

Long inputs are split into tokenizer-bounded windows and aggregated, so memory stays bounded
regardless of input length while still catching attacks buried deep in a document. With
representative clustering enabled (off by default) near-duplicate windows are grouped by
similarity and only cluster representatives run — the rest inherit the representative's verdict —
which cuts physical inferences per request on top of the memory bound. See the
[L3 worker policy](../reference/configuration.md#l3-worker-policy).

### Unified multi-head L3

Running one coalesced multi-head model (`l3_strategy="multi"`) instead of one model per
category lets several promoted categories share a single inference — a large throughput win
when multiple model-backed categories are active. Compare both strategies with the
[local benchmark](../how-to/run-local-benchmark.md).

### Cache-skip inference for repeats and near-duplicates

The optional [model-output cache](../how-to/configure-caching.md) is the largest latency lever
for repetitive traffic: an exact-chunk hit returns stored logits from RAM in microseconds instead
of running the transformer (tens of milliseconds), and a close L2-embedding match can propagate a
non-safe verdict without any L3 inference. The `dynamic-pii` GLiNER pipeline caches both exact
chunks and known entity spans the same way. The cache is memory-only by default; add a persistent
[redb](https://github.com/cberner/redb) file to keep hits across restarts.

## Execution backend and threading

The ONNX execution provider is configured via
[`set_execution_backend`](../reference/configuration.md#execution-backend) (CPU, CoreML, CUDA, …).
Threading and spin-wait behavior are configured with `OnnxRuntimeOptions` through
`set_onnx_runtime_options`. Defaults target constrained CPU execution. See the
[configuration reference](../reference/configuration.md).

## Measuring on your hardware

Do not trust generic numbers — measure. Every gateway can benchmark itself on the shipped
validation samples, reporting latency, throughput, false-positive rate, and per-layer timing
for both L3 strategies:

```python
scanner.run_local_benchmark()
```

See [Run the local benchmark](../how-to/run-local-benchmark.md).
