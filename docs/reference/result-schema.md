# Result schema

What the async queue (`enqueue` + `consume_next_event`) and the blocking `scan_*` helpers
return. Python names are shown; the Rust types (`SecurityScanResult`, `LayerResult`,
`EvaluationResult`, `QueuedSecurityEvent`, `SecurityFailure`) are in the
[Rust API reference](../rust-api.md).

## Scan result

A single result — the `result` field of a queue `result` event, or one element of the list the
blocking `scan_*` helpers return — is a **dictionary describing one category's verdict**:

```python
[
    {
        "category": "dlp",
        "class_name": "safe",
        "confidence": 1.0,
        "level": "L1",
        "model": "native:dlp",
        "duration_ms": 0.4,
        "evidence_spans": [],
        "label_scores": [],
        "layers": [
            {
                "level": "L1",
                "layer_type": "native",
                "class_name": "safe",
                "confidence": 1.0,
                "matched": True,
                "duration_ms": 0.4,
                "thresholds": {},
                "details": {},
            }
        ],
    }
]
```

| Field | Type | Meaning |
| --- | --- | --- |
| `category` | str | The scan category this result belongs to. |
| `class_name` | str | Winning class (a category-specific label, or `safe`). |
| `confidence` | float | Confidence in `class_name`, `0.0`–`1.0`. |
| `level` | str | The level that produced the winning verdict: `L1`, `L2`, or `L3`. |
| `model` | str | The producing scanner, e.g. `native:dlp`, `external:<id>`, or a model id. |
| `duration_ms` | float | Wall-clock time spent producing this result. |
| `decision` | dict | Structured classifier decision envelope for terminal model-backed classifier results. Python omits this key when no authoritative classifier decision exists; Rust exposes `SecurityScanResult.decision: Option<DecisionEnvelope>`. |
| `evidence_spans` | list | Exact matched spans (PII/DLP/dynamic-pii); empty for safe/model-only results. |
| `label_scores` | list | Per-label scores for multi-label heads (e.g. `tool_tags`); each entry is `{label, confidence, matched}`. Empty for single-label results. |
| `layers` | list | Per-layer breakdown of everything that ran for this category. |

### Layer entry

Each element of `layers` records one layer's output:

| Field | Type | Meaning |
| --- | --- | --- |
| `level` | str | `L1` / `L2` / `L3`. |
| `layer_type` | str | e.g. `native`, or the model layer type. |
| `class_name` | str | This layer's class. |
| `confidence` | float | This layer's confidence. |
| `matched` | bool | Whether this layer produced a positive match. |
| `duration_ms` | float | Wall-clock time spent in this layer. |
| `thresholds` | dict | Thresholds applied at this layer (operating point, etc.). |
| `details` | dict | Layer-specific extra detail. NTDB L2 layers add L3 promotion context; L3 layers add chunk execution metadata. The stable policy contract is `decision`, not free-form `details`. |

### Decision envelope

Model-backed classifier pipelines (`injection`, `threat`, `routing`, `sensitive_document`,
`tool_class`, `tool_action`, and `tool_tags`) apply the configured final-decision threshold profile
after raw L2/L3 scoring. The top-level `class_name` / `confidence` is the accepted final verdict.
When no candidate passes its threshold, the result falls back to the pipeline default class
(`benign`, `unknown`, `other`, etc.) and uses the model's default-class confidence when available,
or `0.0` otherwise.

Terminal classifier results expose that policy input and Ark's calibrated recommendation under
`decision`. `decision.is_some()` is the lifecycle marker for an authoritative classifier policy
input. Early L2 results that still contain an `l3_pending` layer, provisional events, progress
events, and result-preview events leave `decision` unset (`None` in Rust) even when they carry
classifier-looking scores.

```python
{
    "schema_version": "ark.decision.v1",
    "final_result": {"class_name": "benign", "confidence": 0.0, "source": "default"},
    "decision_candidate": {
        "source": "l2",
        "class_name": "instruction_override",
        "confidence": 0.5640919208526611,
        "acceptance_threshold": 0.86471,
        "accepted": False,
        "evidence": None,
    },
    "recommendation": {
        "accepted": False,
        "final_arbitration": "default",
        "operating_point": "best_f1",
        "acceptance_threshold": 0.86471,
    },
    "candidates": [
        {
            "source": "l2",
            "class_name": "instruction_override",
            "confidence": 0.5640919208526611,
            "acceptance_threshold": 0.86471,
            "accepted": False,
            "evidence": None,
        }
    ],
    "terminality": {"completion": "complete", "degraded": False, "degradation_reason": None},
    "provenance": {
        "ark_version": "0.1.3",
        "schema_version": "ark.decision.v1",
        "model": "unified-v3-threat",
    },
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | str | Decision-envelope schema version. Currently `ark.decision.v1`. |
| `final_result` | dict | The final Ark verdict after threshold arbitration: `{class_name, confidence, source}`. |
| `decision_candidate` | dict \| null | Canonical policy input. It is the winning accepted candidate when `final_arbitration` is `l2`, `l3`, or `union`; for `default`, it is the highest-priority rejected candidate in `l3`, `union`, `l2` order. `None` when no valid classifier candidate exists. |
| `recommendation` | dict | Ark's calibrated default recommendation. `accepted` is false only for `final_arbitration: "default"`. |
| `candidates` | list | All typed L2, L3, and Union candidates available to arbitration. |
| `terminality` | dict | Completion state for the result: `completion`, `degraded`, and optional `degradation_reason`. |
| `provenance` | dict | Minimal source provenance: `ark_version`, `schema_version`, and `model`. |

Candidate entries have this shape:

| Field | Type | Meaning |
| --- | --- | --- |
| `source` | str | `l2`, `l3`, or `union`. `final_result.source` may also be `default`. |
| `class_name` | str | Candidate class before downstream Patronus policy. |
| `confidence` | float | Candidate confidence from that source. |
| `acceptance_threshold` | float | Ark's calibrated acceptance threshold for this candidate's source/class/operating point. |
| `accepted` | bool | Whether this candidate passed Ark's calibrated acceptance threshold. |
| `evidence` | dict \| null | Extra candidate evidence. Union candidates include `l2_weight`, `l3_weight`, `l2_confidence`, and `l3_confidence`. |

Example: if Threat L2 predicts `instruction_override` at `0.5640919`, but the selected threshold
profile requires a higher L2 confidence, the top-level result is the default `benign` class while
`decision.decision_candidate` retains the rejected `l2` candidate with
`acceptance_threshold: 0.86471` and `decision.recommendation.accepted: False`.

`label_scores[].matched` is layer-local model output metadata. It is not threshold acceptance and
must not be treated as equivalent to `decision.recommendation.accepted` or
`decision.candidates[].accepted`.

Candidate confidences are calibrated for Ark's bundled threshold profiles. Treat them in the
context of their `category`, `source`, `model`, and `operating_point`; do not compare scores across
unrelated sources or model versions without their matching thresholds.

### Evidence spans

Native PII and DLP findings, and `dynamic-pii` entities, populate `evidence_spans` with exact
offsets:

```python
for span in result["evidence_spans"]:
    print(span["label"], span["text"], span["score"], span["start_byte"], span["end_byte"])
```

Each span carries the matched `label`, the matched `text`, a `score`, and both **byte** and
**character** offsets (`start_byte`/`end_byte`/`start_char`/`end_char`). Safe native results
leave `evidence_spans` empty.

## Async queue events

`consume_next_event(timeout)` returns one event dict at a time (or `None` on timeout).
`consume_events(timeout)` yields them. There are up to four `event_type`s: `result` and
`finished` always, plus `progress` and `provisional` when L3 progress reporting is enabled
(`execution_gates.l3.progress`, off by default). The blocking `scan_*` helpers only ever return
`result` / `finished`.

### `result`

```python
{
    "event_type": "result",
    "request_id": "…",
    "result": { …a scan result dict, as above… },
}
```

One request can emit **several** `result` events. L1 results are visible as soon as L1
finishes; L2 and a later promoted L3 result follow independently.

Promoting NTDB L2 layers expose `details.l3_candidates` (each entry: byte `span`,
`promote_score`, `promote_threshold`, `source_pipeline`, `source_model`, `l2_class`) and
`details.l2_chunk_outputs` (the per-chunk L2 outputs retained for aggregation, with the raw
embeddings stripped). Under `l3_strategy="multi"`, candidates from every promoted pipeline in the
coalesced run are deduplicated by **exact span match** — when two heads promote the same span,
`source_pipeline` / `source_model` / `l2_class` become comma-joined unions; under the default
`l3_strategy="dedicated"` each pipeline's candidates stay separate and this merge never runs. The
L3 worker maps candidate spans onto tokenizer-bounded windows; with representative
clustering enabled it groups near-duplicate windows, infers only cluster representatives, and
propagates their verdict to the rest (see
[L3 worker policy](configuration.md#l3-worker-policy)). An empty or unusable candidate list
deliberately falls back to full-text L3.

### `progress`

Opt-in, non-authoritative status while a long L3 scan resolves — only under the dedicated L3
strategy (`l3_strategy="multi"` never emits it):

```python
{
    "event_type": "progress",
    "request_id": "…",
    "progress": {
        "category": "injection", "model": "…", "stage": "l3_chunk",
        "completed_chunks": 3, "total_chunks": 8,
        "inferred_chunks": 2, "propagated_chunks": 1, "cache_hits": 0,
        "early_exit": False, "coverage": 0.375, "details": { … },
    },
}
```

`stage` is one of `l3_started`, `l3_chunk`, `l3_cluster_propagated`, `l3_early_exit`. A progress
event carries no verdict — never treat it as a result.

### `provisional`

Same shape as a `result` event's `result`, but an **interim preview** re-aggregated from the
chunks resolved so far. It is non-authoritative and may be superseded by later `result` /
`finished` events; only emitted when `execution_gates.l3.progress` is set to `"provisional"`.

### `finished`

Exactly one terminal event follows all results for a request:

```python
{
    "event_type": "finished",
    "request_id": "…",
    "completion": "…",     # "complete" | "degraded" | "failed"
    "failures": [ … ],     # structured failures, if any
}
```

`completion` is one of `complete` (all planned work succeeded), `degraded` (some layer failed
but a lower-layer result was delivered), or `failed` (no usable result). Consuming `finished`
removes all library state for that request ID. Correlate every event by `request_id`.

### Failures

Each `failures` entry is a structured `SecurityFailure` dict:

| Field | Type | Meaning |
| --- | --- | --- |
| `stage` | str | `warmup`, `asset`, `scanner`, `inference`, `queue`, or `worker`. |
| `kind` | str | `not_ready`, `missing_asset`, `integrity_failure`, `initialization_failure`, `inference_failure`, `timeout`, `worker_unavailable`, or `internal`. |
| `level` | str \| null | The level that failed (`L1`/`L2`/`L3`), if applicable. |
| `detector_id` | str \| null | The specific detector or model that failed, if applicable. |
| `retryable` | bool | Whether the failure is transient and could succeed on retry. |
| `message` | str | Human-readable description. |

A failure does not throw during scanning — the scan
[degrades](../concepts/layered-scanning.md#degradation-contract) to the best available
lower-layer result and reports the failure here. (`warmup()` itself is the exception: a missing
required asset there raises rather than degrades.)

## Request introspection

| Method | Returns |
| --- | --- |
| `has_request(request_id)` | Whether the gateway still tracks this request. |
| `request_state(request_id)` | Current state dict, or `None`. |
| `is_finished(request_id)` | `True` / `False`, or `None` if unknown. |
| `runtime_readiness()` | Initialized runtime state (levels ready, per stage/kind). |

Request state reflects `SecurityRequestState` — whether any planned scanner or promoted L3 job
can still publish an event.
