# Tune performance & memory

**Goal:** get the latency, throughput, and memory profile you need. For the *why* behind these
levers, see [Performance & memory](../concepts/performance.md).

Always [measure on your own hardware](run-local-benchmark.md) before and after each change.

!!! note "Both APIs take the same keys"
    The examples below are shown as Python config keys. The Rust `GatewayConfig` has the same
    keys as fields (`l3_strategy`, `execution_backend`, `ntdb_decision_threshold_point`,
    `onnx_batch_mode`, and the gate keys in `core.gates`) — the only difference is that Rust takes
    typed enums (`L3Strategy::Multi`, `ExecutionBackend::CoreMl`, …) where Python takes the
    equivalent strings.

## Cap escalation

The cheapest lever is not running L3. If you don't need transformer-grade accuracy on a path,
cap it:

```python
scanner = SecurityGateway({"categories": ["injection"], "max_level": "l2"})
```

Or switch L3 off with the `l3` gate key while keeping the ceiling; a request can override it
with `enqueue(..., execution_gates=...)`:

```python
scanner = SecurityGateway({"categories": ["injection"], "max_level": "l3", "l3": False})
```

## Choose a final-decision threshold profile

Trade final-decision recall and precision with the NTDB threshold profile:

```python
scanner = SecurityGateway({
    "categories": ["injection"],
    "ntdb_decision_threshold_point": "best_fpr_in_f1",  # lower false positives within an F1 band
})
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
    {
        "categories": ["injection", "sensitive_document", "unsafe_action", "routing"],
        "max_level": "l3",
        "l3_strategy": "multi",
    }
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
scanner = SecurityGateway({
    "categories": ["injection"],
    "onnx_batch_mode": "tensor_batch",  # vs. "lazy_batches"
})
```

## Manage L3 session lifetime

L3 sessions evict after an idle TTL by default. Keep them resident for latency-sensitive services,
raise the TTL for bursty traffic, or lower it to reclaim memory sooner:

```bash
export PATRONUS_L3_TTL_SECS=-1  # never evict loaded sessions
# or use a finite idle timeout:
export PATRONUS_L3_TTL_SECS=600
```

## Keep resident memory low

- Stay at `max_level="l2"` where transformer accuracy isn't required — L2 shares one static
  encoder across categories.
- Don't download optional full-precision assets (leave `PATRONUS_DOWNLOAD_OPTIONAL_ASSETS`
  unset) — the quantized bundles are the default.
- Scan only the categories you act on, and leave rules you do not need switched off: native
  rules are compiled only when the gates enable them, so rules of categories a scanner does not
  run, opt-in forms and rules switched off in `rules` take no memory. The enabled rules are
  compiled when the scanner or gateway is built, so the first scan does not pay for them.
- Run `warmup()` (or `prepare_assets()`) with downloads allowed at least once per cache: it
  moves the weights of each downloaded ONNX graph into `model.onnx.data` next to it, which ONNX
  Runtime memory-maps instead of copying onto the heap. The cache needs about as much disk space
  as before (the graph file shrinks by what moves into the data file); keep both files together
  when you copy a cache to another machine.
