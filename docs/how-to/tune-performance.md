# Tune performance & memory

**Goal:** get the latency, throughput, and memory profile you need. For the *why* behind these
levers, see [Performance & memory](../concepts/performance.md).

Always [measure on your own hardware](run-local-benchmark.md) before and after each change.

!!! note "Both APIs expose the same knobs"
    The examples below are shown in Python. The Rust gateway has the identical setters —
    `set_l3_strategy`, `set_execution_backend`, `set_ntdb_operating_point`,
    `set_onnx_batch_mode`, `set_execution_gates` — the only difference is that Rust takes typed
    enums (`L3Strategy::Multi`, `ExecutionBackend::CoreMl`, …) where Python takes the equivalent
    strings. For example:

    ```rust
    use patronus_ark::{ExecutionBackend, L3Strategy};
    scanner.set_l3_strategy(L3Strategy::Multi);
    scanner.set_execution_backend(ExecutionBackend::CoreMl);
    ```

## Cap escalation

The cheapest lever is not running L3. If you don't need transformer-grade accuracy on a path,
cap it:

```python
scanner = SecurityGateway(categories=["injection"], max_level="l2")
```

Or gate L3 off per request while keeping the ceiling:

```python
scanner.set_execution_gates({"levels": {"l1": True, "l2": True, "l3": False}})
```

## Choose a final-decision threshold profile

Trade final-decision recall and precision with the NTDB threshold profile:

```python
scanner.set_ntdb_operating_point("best_fpr_in_f1")   # lower false positives within an F1 band
```

Options: `best_f1`, `best_promote`, `best_fpr_in_f1`, `best_fnr_in_f1`, `best_latency_in_f1`.
See the [reference](../reference/configuration.md#ntdb-operating-point).

This does not change which chunks promote to L3. Use `max_level`, execution gates, and
`l3_strategy` for L3 cost/throughput control.

## Use the unified multi-head model when several categories are active

If you scan multiple model-backed categories at L3, the coalesced multi-head model runs them
in a single inference:

```python
scanner = SecurityGateway(
    categories=["injection", "sensitive_document", "threat", "routing"],
    max_level="l3",
    l3_strategy="multi",     # one inference vs. one per category
)
```

Compare `l3_strategy="dedicated"` vs `"multi"` with the [local benchmark](run-local-benchmark.md).

## Tune ONNX execution

Pick a backend and thread counts to match your hardware:

```rust
scanner.set_execution_backend(ExecutionBackend::CoreMl); // or Cpu, Cuda, Auto, ...
scanner.set_onnx_runtime_options(OnnxRuntimeOptions {
    intra_threads: Some(2),
    inter_threads: Some(1),
    spinning: Some(false),
});
```

## Batch L3 fallback inference

For async workloads that promote many texts, coalesce L3 fallback batches:

```python
scanner.set_onnx_batch_mode("tensor_batch")   # vs. "lazy_batches"
```

## Manage L3 session lifetime

L3 sessions are held resident in RAM and evict after an idle TTL. Raise it for bursty traffic to avoid
reload cost, or lower it to reclaim memory sooner:

```bash
export PATRONUS_L3_TTL_SECS=600
```

## Keep resident memory low

- Stay at `max_level="l2"` where transformer accuracy isn't required — L2 shares one static
  encoder across categories.
- Don't download optional full-precision assets (leave `PATRONUS_DOWNLOAD_OPTIONAL_ASSETS`
  unset) — the quantized bundles are the default.
- Scan only the categories you act on.
