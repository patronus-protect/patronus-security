# Configuration reference

Every knob that changes gateway behavior, in one place. For the full method signatures see the
generated [Python API](../python-api.md) and [Rust API](../rust-api.md); for concepts see
[Architecture](../concepts/architecture.md) and [Layered scanning](../concepts/layered-scanning.md).

## Constructor options

Set at gateway construction:

| Option | Type | Meaning | Rust |
| --- | --- | --- | --- |
| `categories` | list of category names | Which [categories](../concepts/categories.md) to scan. | constructor |
| `max_level` | `"l1"` \| `"l2"` \| `"l3"` | Hard ceiling on escalation (default `"l2"`). | constructor |
| `download_files` | bool | Whether missing assets may be downloaded on warmup. | constructor |
| `download_categories` | list | Restrict automatic downloads to these categories. | constructor |
| `model_dir` | path | Custom asset cache location (default: platform cache dir). | constructor |
| `cache_storage_location` | path or `None` | Explicit persistent cache database; `None` keeps the cache memory-only. | cache constructor |
| `cache_encryption_key_hex` | 64 hex chars or `None` | Encrypt persistent cache values and keyed similarity bucket indexes. | `PersistentCacheConfig.encryption` |
| `cache_entry_ttl_seconds` | positive integer | Shared hot/persistent TTL; defaults to 30 days (`2_592_000`). | `ExactCacheConfig.entry_ttl` |
| `cache_memory_max_entries` | non-negative integer | Per-hot-tier entry bound; `0` disables hot retention. | `ExactCacheConfig.memory.max_entries` |
| `cache_memory_max_bytes` | non-negative integer | Per-hot-tier byte bound; `0` disables hot retention. | `ExactCacheConfig.memory.max_bytes` |
| `l3_strategy` | `"dedicated"` \| `"multi"` | One model per category, or one coalesced multi-head model. | setter |
| `execution_gates` | dict / matrix | Initial [execution gates](#execution-gates). | setter |
| `dynamic_pii_config` | dict | Configuration for the [`dynamic-pii`](#dynamic-pii) pipeline. | setter |
| `execution_backend` | str | ONNX [execution backend](#execution-backend) (default `"auto"`). | setter |
| `onnx_batch_mode` | str | [ONNX batch mode](#onnx-batch-mode); default `"backend_default"` follows whatever the backend implies. | setter |
| `ntdb_operating_point` | str | Initial [final-decision threshold profile](#ntdb-operating-point), default `"best_f1"`. | setter |

In Python, all of these are keyword arguments to `SecurityGateway(...)`. In Rust the
*constructor*-marked options are positional: `with_max_level(categories, max_level, model_dir,
download_files)` takes four arguments (it always downloads for every configured category), and
`with_download_categories(...)` adds the fifth, `download_categories`. Every other option is
applied after construction with its setter (`set_l3_strategy`, `set_execution_gates`,
`set_dynamic_pii_config`, `set_execution_backend`, `set_onnx_runtime_options`,
`set_onnx_batch_mode`). Rust persistent caching uses
`try_with_download_categories_and_cache(...)` with `ExactCacheConfig`; the path is fixed for
the gateway lifecycle and cannot be overridden per request.

Python persistent writes are asynchronous. Call `flush_cache()` when shutdown or a durability
boundary must wait for all queued writes. See
[Configure and understand caching](../how-to/configure-caching.md) for storage variants,
cache-hit behavior, Dynamic PII events, metadata, and measured latencies.

## Runtime setters

Change behavior on a live gateway (Python names; Rust has equivalents):

| Setter | Values | Effect |
| --- | --- | --- |
| `set_execution_gates(dict \| None)` | see [below](#execution-gates) | Enable/disable levels and detectors; `None` resets to all-enabled. |
| `set_l3_strategy(str)` | `dedicated`, `multi` | Switch the [L3 strategy](#l3-strategy). |
| `set_ntdb_operating_point(str)` | see [below](#ntdb-operating-point) | Pick the final-decision threshold profile. |
| `set_onnx_batch_mode(str)` | `lazy_batches`, `tensor_batch` | How L3 fallback batches execute. |
| `set_execution_backend(str)` | see [below](#execution-backend) | ONNX execution provider. |
| `set_onnx_runtime_options(...)` | constrained CPU | Configure ONNX Runtime intra/inter threads and spin-wait behavior. |
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
    "rules": {"pii_email": False, "dlp_password_assignment": False},
})
```

- `levels` — per-level on/off (`l1`, `l2`, `l3`).
- `models` — per-detector on/off, keyed by public model name: `native:<name>` for native
  detectors, `external:<id>` for [external L1 detectors](../how-to/external-l1-signals.md).
- `rules` — per-L1-rule on/off. Missing IDs remain enabled. PII patterns use stable `pii_*`
  IDs. DLP patterns use `dlp_*` IDs; its separate heuristics are `dlp_sensitive_material`,
  `dlp_secret_transfer`, `dlp_mcp_runtime_risk`, `dlp_mcp_policy`, and
  `dlp_destructive_operation`. Injection uses the `ark.injection.*` IDs returned in evidence.
  See the complete [L1 rule catalog](l1-rule-catalog.md) for every accepted ID and the Ark API
  default state of DLP rules.
- `conditional` — conditional gates (see [below](#conditional-gates)).
- `l3` — optional worker policy (see [below](#l3-worker-policy)).

Per-request gates passed to `enqueue()` are **snapshotted** at enqueue time and do not change
the gateway defaults. In Rust, build a `ScanGateMatrix`:

```rust
scanner.set_execution_gates(
    ScanGateMatrix::levels(true, false, false)
        .with_model("native:mcp_runtime_risk", false)
        .with_rule("pii_email", false),
);
```

The Python/Rust request shape uses `levels` plus the separate L3 worker-policy object under `l3`.
Ark API YAML mirrors the Rust matrix more directly: its level switches are top-level `l1`, `l2`,
and `l3`, while the worker policy is named `policy`. For example:

```yaml
gates:
  l1: true
  l2: false
  l3: false
  rules:
    pii_employee_id: true
    dlp_sql_statement: false
  models:
    native:mcp_runtime_risk: false
```

The reference Ark API configuration is intentionally credentials-only for DLP L1: key, token,
password, hash, and private-key rules remain enabled, while business identifiers, metrics, source,
SQL, dump, log, MCP/runtime, and destructive-operation families require an explicit profile.

### L3 worker policy

The optional `execution_gates.l3` policy tunes the shared L3 worker. Initial costs are
bootstrap values; the worker updates them with an EWMA of observed execution time.

```python
execution_gates = {
    "l3": {
        "enabled": True,                # master switch for the L3 worker policy
        "priority": ["injection", "dynamic-pii"],
        "estimated_cost_ms": {"injection": 200, "dynamic-pii": 240},
        "fairness_quantum_ms": 50,
        "max_wait_ms": 2_000,
        "degraded_factor": 0.75,        # confidence multiplier applied to degraded fallbacks
        "ttl_ms": {"injection": 15_000, "dynamic-pii": 12_000},
        # Request-wide defaults:
        "execution": "rank_only",
        "early_exit": "class_stable",   # request-wide master switch: "disabled" | "class_stable"
        "progress": "disabled",         # "disabled" | "progress" | "provisional" (both dedicated-only)
        "representatives_per_cluster": 1,
        "verify_representatives_per_cluster": 1,
        "min_cluster_similarity": 0.90,
        "max_cluster_size": 8,
        # Category/model-specific overrides:
        "pipelines": {
            "injection": {
                "execution": "representative",
                "representatives_per_cluster": 1,
                "min_cluster_similarity": 0.96,
                "aggregation": {
                    "type": "any_positive_or_highest",
                    "positive_class": "attack",
                    "threshold": 0.93,
                },
                "early_exit": "request_wide_positive",
            },
            "tool_class": {
                "execution": "verify_representative",
                "verify_representatives_per_cluster": 1,
                "aggregation": {"type": "majority_vote_or_highest"},
                "early_exit": "head_stable",
            },
        },
    }
}
```

`execution` accepts `disabled`, `rank_only`, `representative`, and
`verify_representative`; `clustering` remains a compatible alias. Pipeline overrides are
resolved by category first and model name second. They are part of the enqueue-time gate
snapshot, so two requests on the same gateway can use different policies.

`representative` first infers the configured number of highest-priority members from every cluster
in global L2-priority order, then propagates each aggregated representative decision to the
remaining cluster. `verify_representative` runs a second global wave containing the configured
number of least-similar members. A class mismatch opens only that cluster and schedules its
remaining members in global priority order. `rank_only` never propagates.

`aggregation.type` selects how the per-chunk L3 outputs combine into the category verdict:
`any_positive_or_highest` (fields `positive_class`, `threshold`),
`highest_risk_above_threshold_or_confidence` (field `threshold`), or `majority_vote_or_highest`.
When omitted it defaults per pipeline — `any_positive_or_highest` for injection,
`majority_vote_or_highest` for routing/tool_class/tool_action/sensitive_document, and
`highest_risk_above_threshold_or_confidence` (threshold `0.93`) for every other pipeline.

There are **two** `early_exit` fields with different value sets. The request-wide
`execution_gates.l3.early_exit` (shown in the defaults block above) is the master switch —
`disabled` or `class_stable` (default `class_stable`); it turns early exit on or off and resolves
each pipeline's default scope. The per-pipeline `early_exit` inside `pipelines.<name>` overrides
that pipeline's scope explicitly:

- `disabled`: do not stop from a stable head decision.
- `head_stable`: stop only the current head when its result can no longer change.
- `request_wide_positive`: a thresholded positive result stops lower-priority heads for the
  request. This is the default behavior for Injection and Threat.

Independently of the per-pipeline `early_exit` scope above, a fixed cross-pipeline guard cancels
the rest of a request's queued (or coalesced) L3 jobs once any Injection or Threat result crosses
`0.93` confidence on a non-safe class. That threshold is not configurable.

`progress` controls streaming status while L3 resolves: `disabled` (default), `progress`
(non-terminal `progress` events carrying chunk counters), or `provisional` (also emits interim
`provisional` result previews). It takes effect only under `l3_strategy="dedicated"` — the unified
`multi` strategy never emits progress or provisional events. See
[Result schema](result-schema.md#async-queue-events) for the event shapes.

Dedicated and unified L3 use the same cluster planner, representative/verify state machine,
aggregation rules, and early-exit state. Unified keeps the full output of every physical chunk and
reuses it when a later head requests the same chunk.

Runnable examples:

- `rust/examples/08_l3_pipeline_policies.rs`
- `python/examples/08_l3_pipeline_policies.py`

### Conditional gates

Beyond flat on/off gates, `conditional` gates suppress L2 or L3 work for a pipeline unless a
predicate holds. The predicate (`when`) is evaluated against caller-supplied request
`metadata` (arbitrary JSON passed to `enqueue`) and the results of pipelines that already ran
earlier in the same request. This lets you, for example, run the expensive `dynamic-pii` L3
pass **only** when `injection` flagged the text.

```python
scanner.set_execution_gates({
    "conditional": [
        {
            "level": "l3",
            "pipeline": "dynamic-pii",
            "when": {"result": {"pipeline": "injection", "classes": ["attack"], "min_confidence": 0.8}},
        }
    ]
})
```

An L3 conditional may instead carry `l3_policy`. When its predicate matches, the specified
execution, clustering, aggregation, and early-exit fields override that pipeline's request-local
policy. A policy conditional does not suppress the pipeline when its predicate does not match:

```python
scanner.set_execution_gates({
    "conditional": [{
        "level": "l3",
        "pipeline": "injection",
        "when": {
            "result": {
                "pipeline": "routing",
                "classes": ["code_development_request"],
                "min_confidence": 0.8,
            }
        },
        "l3_policy": {
            "execution": "representative",
            "representatives_per_cluster": 1,
            "min_cluster_similarity": 0.96,
            "early_exit": "disabled",
        },
    }]
})
```

Predicate forms: `all` / `any` / `not` (combinators), `metadata` (`{path, equals|in|exists}`),
and `result` (`{pipeline, classes, min_confidence}`). A runnable example is
[`rust/examples/07_contextual_gates.rs`](https://github.com/patronus-protect/patronus-security/blob/main/rust/examples/07_contextual_gates.rs).

## L3 strategy

| Value | Behavior |
| --- | --- |
| `dedicated` *(default)* | One transformer per category (Wolf Defender, Orca Sonar, Husky, …). Best per-category tuning. |
| `multi` | One coalesced multi-head model (Lion Warden) serves several categories per inference. Best throughput when several model-backed categories are active. |

See [Models & the NTDB format](../concepts/models-and-ntdb.md#dedicated-vs-unified-l3).

## NTDB operating point

Selects the precomputed final-decision threshold profile used after L2/L3 scoring. The profile
controls the L2 acceptance threshold, L3 acceptance threshold, and L2/L3 union threshold/weights
for supported classifier pipelines. It does **not** change the L2 promote-router threshold; L3
promotion still uses the package's promote operating point. When no candidate is accepted, the
pipeline returns its default class and preserves the model's default-class confidence when one is
available.

| Value | Optimizes |
| --- | --- |
| `best_f1` *(default)* | Balanced final-decision F1. |
| `best_promote` | Uses the bundled final-decision profile named `best_promote`; promotion itself remains separate. |
| `best_fpr_in_f1` | Low false-positive rate within an F1 band. |
| `best_fnr_in_f1` | Low false-negative rate within an F1 band. |
| `best_latency_in_f1` | Lowest latency within an F1 band. |

For queued scans, Python callers can override the profile per request with
`enqueue(..., ntdb_operating_point="best_fpr_in_f1")`.

## Execution backend

ONNX execution provider for L3 (and model-backed L2 where applicable):

`auto` · `cpu` · `gpu` · `coreml` · `cuda` · `directml` · `tensorrt`

`auto` selects a provider based on the platform; `cpu` is the portable default. Availability of
GPU providers depends on the ONNX Runtime build.

Setting the backend also **resets `onnx_batch_mode`**: `auto`/`cpu` → `lazy_batches`, and the GPU
providers (`gpu`/`coreml`/`cuda`/`directml`/`tensorrt`) → `tensor_batch`. If you need a non-default
batch mode, call `set_onnx_batch_mode(...)` *after* `set_execution_backend(...)`.

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
    "labels": ["organization", "date", "person", "city", "country"],
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
    "queue_timeout_ms": 5_000,
    "timeout_per_chunk_ms": 500,
    "max_timeout_ms": 120_000,
}
```

| Key | Meaning |
| --- | --- |
| `labels` | GLiNER entity labels to extract. |
| `threshold` / `label_thresholds` | Global and per-label score thresholds. |
| `execution_gate` | When the pipeline runs (`always`, `if_result_in`, `if_no_result`). |
| `conditional_labels` | Extra label groups run separately, and only on chunks whose final source-pipeline result matches. Labels already present in `labels` are removed from the extra call. |
| `chunk_size_words` / `chunk_overlap_words` | Windowing for long text. |
| `max_text_bytes` | Hard input size limit. |
| `timeout_ms` | Minimum inference timeout for the pipeline. |
| `queue_timeout_ms` | Maximum wait after the L2 gate resolves and before inference starts. |
| `timeout_per_chunk_ms` | Inference budget contributed by each planned chunk. |
| `max_timeout_ms` | Upper bound for the adaptive inference timeout. |

Configured GLiNER labels are subject to the model and threshold you choose; this API makes no
cross-domain quality guarantee. Deterministic identifiers (email, IP, IBAN, SWIFT/BIC, phone,
card) stay native L1 heuristics. See
[`gliner_category_map.py`](https://github.com/patronus-protect/patronus-security/blob/main/python/patronus_ark/gliner_category_map.py).

The first detected Dynamic PII entity is emitted immediately as a `provisional` queue event. It
contains `details.partial_result = true`, `details.provisional = true`, and one evidence span. The
authoritative complete result follows after the remaining chunks finish. Dynamic PII reuses only
exact, context-bound chunk candidates; cross-text entity-cache matches do not become evidence.

The base `labels` are always inferred as one stable label group across the complete input. Each
matching `conditional_labels` entry is a separate GLiNER call scoped to the chunks carrying that
source pipeline's terminal class. Dynamic PII waits for a referenced source pipeline to finish
(including an L2 result that does not promote), so an interim L2 class cannot activate a
contextual label group that the final source result rejects.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `HF_TOKEN` | — | Authenticated / rate-limited Hugging Face access for asset downloads. Falls back to `HUGGINGFACE_HUB_TOKEN`, then `HUGGING_FACE_HUB_TOKEN`, then the cached `huggingface-cli login` token file. |
| `HF_HOME` | HF default | Hugging Face cache location. |
| `PATRONUS_DOWNLOAD_OPTIONAL_ASSETS` | unset | `1` also downloads non-required asset files (currently `tokenizer_config.json` for the legacy L3 manifest). |
| `PATRONUS_L3_TTL_SECS` | `300` | Idle seconds before an L3 session is evicted; `-1` keeps loaded sessions resident. The Ark API container sets `-1`. |
| `PATRONUS_L3_TRACE_CHUNKS` | unset | `1` logs per-chunk L3 execution traces (diagnostic). |
| `PATRONUS_L3_TIMING` | unset | When set, logs Unified-L3 tokenization, ONNX session-run, and output-decoding timings. |
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
