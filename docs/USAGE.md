# Usage walkthrough

Nine numbered examples cover the
main flows ([`rust/examples/`](https://github.com/patronus-protect/patronus-security/tree/main/rust/examples),
[`python/examples/`](https://github.com/patronus-protect/patronus-security/tree/main/python/examples)).

| # | Flow | When to use it | Rust | Python |
| --- | --- | --- | --- | --- |
| 01 | Basic scan | One-off, blocking scan of a single text | `cargo run --example 01_basic_scan` | `python python/examples/01_basic_scan.py` |
| 02 | Enqueue / consume | Many texts, async, one shared result queue | `cargo run --example 02_enqueue_consume` | `python python/examples/02_enqueue_consume.py` |
| 03 | L2 → L3 promotion | Heavy ONNX model runs only when L2 promotes | `cargo run --example 03_l2_l3_promotion` | `python python/examples/03_l2_l3_promotion.py` |
| 04 | Execution gates | Turn levels/models on or off per request | `cargo run --example 04_execution_gates` | `python python/examples/04_execution_gates.py` |
| 05 | Dynamic PII | Runtime GLiNER labels + evidence spans | `cargo run --example 05_dynamic_pii` | `python python/examples/05_dynamic_pii.py` |
| 06 | Unified L3 speedup | Compare two promoted Dedicated models with one coalesced Multi inference | `cargo run --release --example 06_multi_l3_speedup` | `python python/examples/06_multi_l3_speedup.py` |
| 07 | Multi-head L2 validation | Run all seven L2 classifiers on real unified-v3 Val rows | — | `python python/examples/07_multitask_val_l2.py` |
| 08 | L3 pipeline policies | Configure clustering, aggregation, progress, and early exit by logical head | `cargo run --example 08_l3_pipeline_policies` | `python python/examples/08_l3_pipeline_policies.py` |
| 09 | Caching | Compare memory-only, persistent async, write-through, and cache metadata | `cargo run --example 09_caching -- async` | `python python/examples/09_caching.py /tmp/patronus-cache.redb` |

Examples 01, 02, and 04 run fully offline (`download_files=false`, native L1 +
cached L2). Examples 03, 05, 06, 07, 08, and 09 need model assets and will print a
warmup error if they are missing.

## 01 — Basic scan

Build a gateway for a set of categories and call `scan_all`. You get one result
per configured pipeline, each with `category`, `class_name`, `confidence`,
`level`, and `model`. Best for simple, synchronous checks.

## 02 — Enqueue / consume

`enqueue(text)` returns a request id immediately and does the work on a
background worker. `consume_next_event` drains a single shared queue that carries
results for *every* request, so a fast L2 result is never blocked behind another
request waiting on L3. Correlate each event by `request_id`; exactly one terminal
`finished` event follows all results for a request.

## 03 — L2 → L3 promotion

With `max_level = L3`, an NTDB L2 classifier can promote a scan to the full ONNX
transformer. The queue first publishes the L2 fallback result, then the final L3
result — both under the same `request_id`. Configured L3 models are held resident
in RAM and evicted only after the idle TTL (`PATRONUS_L3_TTL_SECS`).

## 04 — Execution gates

`ScanGateMatrix` (Rust) / an `execution_gates` dict (Python) decides which levels
and which individual models run. Set a default with `set_execution_gates`, or
pass a gate per request to `enqueue`. `max_level` remains the hard upper bound.

## 05 — Dynamic PII

`dynamic-pii` is an L3-only GLiNER pipeline. Choose entity labels at runtime,
gate it on another pipeline's result (e.g. run only when injection flags the
text), and read first-class `evidence_spans` with byte- and char-accurate
offsets. See the pipeline design in [Models & the NTDB format](concepts/models-and-ntdb.md#onnx-transformers-the-l3-format)
and the [dynamic PII configuration](reference/configuration.md#dynamic-pii).

## 06 — Unified L3 speedup

The same cache-unique text promotes both Injection and Sensitive Document to
L3. Dedicated executes two L3 models; Multi returns both logical head results
from one shared `physical_job_id`. Each strategy runs in a fresh process, L3
sessions are materialized before timing, and the example prints median and
mean end-to-end latency plus the measured speedup.

## 07 — Multi-head L2 validation

Runs all seven L2 NTDB classifiers on real unified-v3 validation rows and reports their per-head
agreement — a fast way to sanity-check the L2 packages without invoking L3. Python only
(`07_multitask_val_l2.py`). The Rust example in slot 07 is a separate contextual-gates demo
(`07_contextual_gates.rs`), documented under
[Conditional gates](reference/configuration.md#conditional-gates).

## 08 — L3 pipeline policies

Tune L3 execution per logical head and per request. The example turns on request-wide `progress`
reporting and sets per-pipeline policies — `injection` uses `representative` clustering with an
`any_positive_or_highest` aggregation and request-wide early exit, `tool_class` uses
`verify_representative` — then adds a `conditional` `l3_policy` override that applies only when
`routing` classified the text as a code request. See the
[L3 worker policy](reference/configuration.md#l3-worker-policy).

## 09 — Caching

Runs the same input twice and prints cache metadata. The Python example also
shows the early partial Dynamic PII `result` event. See
[Configure and understand caching](how-to/configure-caching.md) for the exact,
similarity, Dynamic PII, storage-mode, and latency breakdown.
