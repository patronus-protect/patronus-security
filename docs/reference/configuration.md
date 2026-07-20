# Configuration reference

Every knob that changes gateway behavior, in one place. For the full method signatures see the
generated [Python API](../python-api.md) and [Rust API](../rust-api.md); for concepts see
[Architecture](../concepts/architecture.md) and [Layered scanning](../concepts/layered-scanning.md).

## Constructor options

Set at gateway construction:

| Option | Type | Meaning |
| --- | --- | --- |
| `categories` | list of category names | Which [categories](../concepts/categories.md) to scan. |
| `max_level` | `"l1"` \| `"l2"` \| `"l3"` | Hard ceiling on escalation. |
| `download_files` | bool | Whether missing assets may be downloaded on warmup. |
| `download_categories` | list | Restrict automatic downloads to these categories. |
| `model_dir` | path | Custom asset cache location (default: platform cache dir). |
| `l3_strategy` | `"dedicated"` \| `"multi"` | One model per category, or one coalesced multi-head model. |
| `execution_gates` | dict / matrix | Initial [execution gates](#execution-gates). |
| `dynamic_pii_config` | dict | Configuration for the [`dynamic-pii`](#dynamic-pii) pipeline. |

Rust exposes the same via `with_max_level(...)` and `with_download_categories(...)`.

## Runtime setters

Change behavior on a live gateway (Python names; Rust has equivalents):

| Setter | Values | Effect |
| --- | --- | --- |
| `set_execution_gates(dict \| None)` | see [below](#execution-gates) | Enable/disable levels and detectors; `None` resets to all-enabled. |
| `set_l3_strategy(str)` | `dedicated`, `multi` | Switch the [L3 strategy](#l3-strategy). |
| `set_ntdb_operating_point(str)` | see [below](#ntdb-operating-point) | Pick the L2 threshold profile. |
| `set_onnx_batch_mode(str)` | `lazy_batches`, `tensor_batch` | How L3 fallback batches execute. |
| `set_execution_backend(str)` | see [below](#execution-backend) | ONNX execution provider. |
| `set_dynamic_pii_config(dict)` | see [dynamic PII](#dynamic-pii) | Reconfigure the GLiNER pipeline. |

## Levels

| Value | Layers used |
| --- | --- |
| `l1` | Native L1 only. |
| `l2` | L1 + L2 (NTDB), when assets are cached. |
| `l3` | L1 + L2 + L3 (transformer, on promotion), when assets are cached. |

`max_level` is a ceiling; execution gates can disable levels *below* it per request.

## Execution gates

Gates decide which levels and which model/native scanners are active for subsequent scans.
Unspecified gates stay enabled; `max_level` remains the hard upper bound.

```python
scanner.set_execution_gates({
    "levels": {"l1": True, "l2": False, "l3": False},
    "models": {"native:mcp_runtime_risk": False, "external:internal_token": False},
})
```

- `levels` — per-level on/off (`l1`, `l2`, `l3`).
- `models` — per-detector on/off, keyed by public model name: `native:<name>` for native
  detectors, `external:<id>` for [external L1 detectors](../how-to/external-l1-signals.md).
- `l3` — optional worker policy (see [below](#l3-worker-policy)).

Per-request gates passed to `enqueue()` are **snapshotted** at enqueue time and do not change
the gateway defaults. In Rust, build a `ScanGateMatrix`:

```rust
scanner.set_execution_gates(
    ScanGateMatrix::levels(true, false, false)
        .with_model("native:mcp_runtime_risk", false),
);
```

### L3 worker policy

The optional `execution_gates.l3` policy tunes the shared L3 worker. Initial costs are
bootstrap values; the worker updates them with an EWMA of observed execution time.

```python
execution_gates = {
    "l3": {
        "priority": ["injection", "dynamic-pii"],
        "estimated_cost_ms": {"injection": 200, "dynamic-pii": 240},
        "fairness_quantum_ms": 50,
        "max_wait_ms": 2_000,
        "ttl_ms": {"injection": 15_000, "dynamic-pii": 12_000},
    }
}
```

## L3 strategy

| Value | Behavior |
| --- | --- |
| `dedicated` | One transformer per category (Wolf Defender, Orca Sonar, Husky, …). Best per-category tuning. |
| `multi` | One coalesced multi-head model (Lion Warden) serves several categories per inference. Best throughput when several model-backed categories are active. |

See [Models & the NTDB format](../concepts/models-and-ntdb.md#dedicated-vs-unified-l3).

## NTDB operating point

Selects the precomputed L2 threshold profile:

| Value | Optimizes |
| --- | --- |
| `best_f1` | Balanced F1. |
| `best_promote` | Quality of what L2 promotes to L3. |
| `best_fpr_in_f1` | Low false-positive rate within an F1 band. |
| `best_fnr_in_f1` | Low false-negative rate within an F1 band. |
| `best_latency_in_f1` | Lowest latency within an F1 band. |

## Execution backend

ONNX execution provider for L3 (and model-backed L2 where applicable):

`auto` · `cpu` · `gpu` · `coreml` · `cuda` · `directml` · `tensorrt`

`auto` selects a provider based on the platform; `cpu` is the portable default. Availability of
GPU providers depends on the ONNX Runtime build.

## ONNX batch mode

| Value | Behavior |
| --- | --- |
| `lazy_batches` | Execute L3 fallback texts as they arrive. |
| `tensor_batch` | Coalesce L3 fallback texts into one ONNX tensor batch where possible. |

## Dynamic PII

The `dynamic-pii` pipeline is configured with a dict (constructor `dynamic_pii_config` or
`set_dynamic_pii_config`):

```python
dynamic_pii_config = {
    "labels": ["organization", "location", "date"],
    "threshold": 0.5,
    "label_thresholds": {"organization": 0.6},
    "execution_gate": {
        "type": "if_result_in",
        "pipeline": "injection",
        "results": ["attack", "instruction_override"],
    },
    "conditional_labels": [
        {"labels": ["account identifier"],
         "when": {"pipeline": "injection", "results": ["attack"]}},
    ],
    "chunk_size_words": 256,
    "chunk_overlap_words": 32,
    "max_text_bytes": 1_048_576,
    "timeout_ms": 5_000,
}
```

| Key | Meaning |
| --- | --- |
| `labels` | GLiNER entity labels to extract. |
| `threshold` / `label_thresholds` | Global and per-label score thresholds. |
| `execution_gate` | When the pipeline runs (`always`, `if_result_in`, `if_no_result`). |
| `conditional_labels` | Extra labels enabled only when a source pipeline returns given results. |
| `chunk_size_words` / `chunk_overlap_words` | Windowing for long text. |
| `max_text_bytes` | Hard input size limit. |
| `timeout_ms` | Per-scan timeout for the pipeline. |

Only labels with measured exact-span F1 ≥ 0.6 are mapped; deterministic identifiers (email, IP,
IBAN, SWIFT/BIC, phone, card) stay native L1 heuristics. See
[`gliner_category_map.py`](https://github.com/patronus-protect/patronus-security/blob/main/python/patronus_ark/gliner_category_map.py).

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `HF_TOKEN` | — | Authenticated / rate-limited Hugging Face access for asset downloads. |
| `HF_HOME` | HF default | Hugging Face cache location. |
| `PATRONUS_DOWNLOAD_OPTIONAL_ASSETS` | unset | `1` also downloads optional full-precision ONNX assets. |
| `PATRONUS_L3_TTL_SECS` | `300` | Idle seconds before an L3 session is evicted. |
| `PATRONUS_ONNX_EXECUTION_PROVIDER` | platform | Override the ONNX execution provider. |
| `PATRONUS_ONNX_INTRA_THREADS` | ORT default | Intra-op thread count. |
| `PATRONUS_ONNX_INTER_THREADS` | ORT default | Inter-op thread count. |
| `PATRONUS_ONNX_SPINNING` | ORT default | Toggle ORT spin-wait (set `0` to lower idle CPU). |
| `PATRONUS_NTDB_INJECTION_DIR` | — | Local NTDB override for `injection`. |
| `PATRONUS_NTDB_ROUTING_DIR` | — | Local NTDB override for `routing`. |
| `PATRONUS_NTDB_SENSITIVE_DOCUMENTS_DIR` | — | Local NTDB override for `sensitive_document`. |
| `PATRONUS_NTDB_THREAT_DIR` | — | Local NTDB override for `threat`. |
| `PATRONUS_NTDB_TOOL_CLASS_DIR` | — | Local NTDB override for `tool_class`. |
| `PATRONUS_NTDB_TOOL_ACTION_DIR` | — | Local NTDB override for `tool_action`. |
| `PATRONUS_NTDB_TOOL_TAGS_DIR` | — | Local NTDB override for `tool_tags`. |

Local NTDB override directories are treated as canonical and are never rewritten by the asset
manager. (`PATRONUS_TEST_*` variables exist for the test suite only and are not part of the
public runtime configuration.)
