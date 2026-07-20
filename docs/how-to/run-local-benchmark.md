# Run the local benchmark

**Goal:** measure a gateway's accuracy, latency, throughput, and false-positive rate on your
own hardware, using the validation samples shipped with the package — no extra datasets,
config, or environment variables.

## Run it

```python
from patronus_ark import SecurityGateway

scanner = SecurityGateway(
    categories=["injection", "sensitive_document", "tool_class", "threat"],
    max_level="l3",
    l3_strategy="multi",
)
scanner.warmup()
scanner.run_local_benchmark()
```

This runs the complete suite **twice** — once with dedicated L3 models and once with the
unified multi-head L3 model — so you can compare strategies directly.

### Signature

```python
run_local_benchmark(
    output_dir="benchmark",
    limit_per_pipeline=None,        # cap samples per pipeline (None = up to 100/class)
    load_requests=200,              # requests for the throughput scenario
    print_summary=True,
    native_l1_iterations=200,
)
```

## What it writes

Results land under `./benchmark/`. `./benchmark/BENCHMARK.md` links both runs; the JSON and
summaries live in `./benchmark/dedicated/` and `./benchmark/multi/` — with the real prompts, so
you can inspect mispredictions:

| File | Reports |
| --- | --- |
| `benign_result.json` | 100 benign prompts through the joint `scan_all` decision: class distribution, **false-positive rate**, latency. |
| `example_result.json` | One real queued sample with all pipelines active — every complete result exactly as returned by the consume queue (L2 and L3). |
| `classifier_result.json` | Labelled validation samples per pipeline (up to 100/class): **accuracy, macro-F1**, class distribution, latency — measured L2-only and (at `l3`) with L3. |
| `dynamic_pii_result.json` | Exact-span GLiNER NER precision/recall/F1, per-label and per-context. Runs in a fresh process so its peak RSS excludes other pipelines. |
| `native_l1_result.json` | Native L1 latency for unique 10 KiB inputs, per detector family and all together. |
| `load_result.json` | Burst + sustained 10 req/s load through `enqueue`, one consumer draining the shared queue: offered/completed throughput, error counts, enqueue/first/total latency, chunk counts, L3 queue wait, pure L3 execution time. |

## Reading the results

- **False-positive rate** comes from `benign_result.json` — the single most important number
  for a production firewall.
- **Accuracy / macro-F1** per pipeline is in `classifier_result.json`, at both L2 and L3.
- **Throughput and tail latency** are in `load_result.json`; note that ready L2 results are not
  blocked by another request waiting for L3 (results carry their request ID).
- **Dedicated vs. multi** — compare the same files across `benchmark/dedicated/` and
  `benchmark/multi/` to choose an [`l3_strategy`](../reference/configuration.md#l3-strategy).

!!! note "GLiNER corpus scope"
    The GLiNER corpus is the established 100-sample source corpus plus probes for each mapped
    semantic label. The classification-specific probes are an initial smoke baseline, not a
    statistically complete production validation set.
