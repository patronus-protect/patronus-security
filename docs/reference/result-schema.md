# Result schema

What `scan_all`, `scan_category`, `scan_categories`, and the async queue return. Python names
are shown; the Rust types (`SecurityScanResult`, `LayerResult`, `EvaluationResult`,
`QueuedSecurityEvent`, `SecurityFailure`) are in the [Rust API reference](../rust-api.md).

## Scan result

The synchronous scan methods return a **list of result dictionaries — one per category**:

```python
[
    {
        "category": "dlp",
        "class_name": "safe",
        "confidence": 1.0,
        "level": "L1",
        "model": "native:dlp",
        "evidence_spans": [],
        "layers": [
            {
                "level": "L1",
                "layer_type": "native",
                "class_name": "safe",
                "confidence": 1.0,
                "matched": True,
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
| `evidence_spans` | list | Exact matched spans (PII/DLP/dynamic-pii); empty for safe/model-only results. |
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
| `thresholds` | dict | Thresholds applied at this layer (operating point, etc.). |
| `details` | dict | Layer-specific extra detail. |

### Evidence spans

Native PII and DLP findings, and `dynamic-pii` entities, populate `evidence_spans` with exact
offsets:

```python
for span in result["evidence_spans"]:
    print(span["label"], span["text"], span["start_byte"], span["end_byte"])
```

Spans carry the matched `label`, the matched `text`, and both **byte** and **character**
offsets. Safe native results leave `evidence_spans` empty.

## Async queue events

`consume_next_event(timeout)` returns one event dict at a time (or `None` on timeout).
`consume_events(timeout)` yields them. There are two `event_type`s:

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

Promoting NTDB L2 layers expose `details.l3_candidates`. Each entry carries a byte `span`,
`promote_score`, `promote_threshold`, `source_pipeline`, `source_model`, and `l2_class`.
Unified L3 merges overlapping candidates from the request's promoted heads and scans only
the highest-scored windows plus bounded neighboring context. Candidate-driven execution is
capped at eight distinct chunk texts per physical L3 call, so repetitive chunks are inferred
only once. An empty or unusable candidate list deliberately falls back to full-text L3.

### `finished`

Exactly one terminal event follows all results for a request:

```python
{
    "event_type": "finished",
    "request_id": "…",
    "completion": "…",     # how the request completed
    "failures": [ … ],     # structured failures, if any
}
```

Consuming `finished` removes all library state for that request ID. Correlate every event by
`request_id`.

### Failures

`failures` entries are structured (`SecurityFailure`) with a **stage** and a **kind**:

- **Stage:** `warmup`, `asset`, `scanner`, `inference`, `queue`, `worker`.
- **Kind:** `not_ready`, `missing_asset`, `integrity_failure`, `initialization_failure`,
  `inference_failure`, `timeout`, `worker_unavailable`, `internal`.

A failure does not throw — the scan [degrades](../concepts/layered-scanning.md#degradation-contract)
to the best available lower-layer result and reports the failure here.

## Request introspection

| Method | Returns |
| --- | --- |
| `has_request(request_id)` | Whether the gateway still tracks this request. |
| `request_state(request_id)` | Current state dict, or `None`. |
| `is_finished(request_id)` | `True` / `False`, or `None` if unknown. |
| `runtime_readiness()` | Initialized runtime state (levels ready, per stage/kind). |

Request state reflects `SecurityRequestState` — whether any planned scanner or promoted L3 job
can still publish an event.
