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

L3 transformers are quantized (FP16 / INT8 / INT4-embedding variants) so a model bundle is a
few hundred MB on disk and a few hundred MB resident — small enough to run several classifiers
on a laptop. Optional full-precision ONNX assets are downloaded only when
`PATRONUS_DOWNLOAD_OPTIONAL_ASSETS=1`.

### Compact tokenizers

Tokenizers are converted once into a compact on-disk form (`.kit` for Granite/ModernBERT,
`.mmbpe` for Wolf/mmBERT) in the shared cache, with the source JSON kept as canonical
fallback. This reduces load time and memory.

### Lazy L3 sessions with idle eviction

An L3 ONNX session is created only when a scan first reaches L3, and evicted only after a long
idle TTL (`PATRONUS_L3_TTL_SECS`, default 300 s). Models are never hot-swapped per request, so
you do not pay repeated load/unload costs under steady traffic.

### Cost-scheduled worker

The L3 worker schedules promoted jobs by **estimated and observed compute cost** (an EWMA of
real execution time), with a **max-wait guard** so no request starves, and processes work off
the request path so a slow transformer never blocks a fast L1/L2 answer.

### Long-text windowing

Long inputs are split into tokenizer-bounded windows with token overlap and aggregated, so
memory stays bounded regardless of input length while still catching attacks buried deep in a
document.

### Unified multi-head L3

Running one coalesced multi-head model (`l3_strategy="multi"`) instead of one model per
category lets several promoted categories share a single inference — a large throughput win
when multiple model-backed categories are active. Compare both strategies with the
[local benchmark](../how-to/run-local-benchmark.md).

## Execution backend and threading

The ONNX execution provider and thread counts are configurable via environment variables
(`PATRONUS_ONNX_EXECUTION_PROVIDER`, `PATRONUS_ONNX_INTER_THREADS`,
`PATRONUS_ONNX_INTRA_THREADS`, `PATRONUS_ONNX_SPINNING`) and the
[`set_execution_backend`](../reference/configuration.md#execution-backend) setter (CPU, CoreML,
CUDA, …). Defaults target CPU. See the [configuration reference](../reference/configuration.md).

## Measuring on your hardware

Do not trust generic numbers — measure. Every gateway can benchmark itself on the shipped
validation samples, reporting latency, throughput, false-positive rate, and per-layer timing
for both L3 strategies:

```python
scanner.run_local_benchmark()
```

See [Run the local benchmark](../how-to/run-local-benchmark.md).
