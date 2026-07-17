# Usage walkthrough

Six runnable examples cover the main flows. Each exists in both Rust
([`rust/examples/`](../rust/examples/)) and Python
([`python/examples/`](../python/examples/)).

| # | Flow | When to use it | Rust | Python |
| --- | --- | --- | --- | --- |
| 01 | Basic scan | One-off, blocking scan of a single text | `cargo run --example 01_basic_scan` | `python python/examples/01_basic_scan.py` |
| 02 | Enqueue / consume | Many texts, async, one shared result queue | `cargo run --example 02_enqueue_consume` | `python python/examples/02_enqueue_consume.py` |
| 03 | L2 → L3 promotion | Heavy ONNX model runs only when L2 promotes | `cargo run --example 03_l2_l3_promotion` | `python python/examples/03_l2_l3_promotion.py` |
| 04 | Execution gates | Turn levels/models on or off per request | `cargo run --example 04_execution_gates` | `python python/examples/04_execution_gates.py` |
| 05 | Dynamic PII | Runtime GLiNER labels + evidence spans | `cargo run --example 05_dynamic_pii` | `python python/examples/05_dynamic_pii.py` |
| 06 | Unified L3 speedup | Compare two promoted Dedicated models with one coalesced Multi inference | `cargo run --release --example 06_multi_l3_speedup` | `python python/examples/06_multi_l3_speedup.py` |

Examples 01, 02, and 04 run fully offline (`download_files=false`, native L1 +
cached L2). Examples 03, 05, and 06 need model assets and will print a warmup
error if they are missing.

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
result — both under the same `request_id`. L3 sessions are lazily created on the
first promoted scan and evicted after the idle TTL (`PATRONUS_L3_TTL_SECS`).

## 04 — Execution gates

`ScanGateMatrix` (Rust) / an `execution_gates` dict (Python) decides which levels
and which individual models run. Set a default with `set_execution_gates`, or
pass a gate per request to `enqueue`. `max_level` remains the hard upper bound.

## 05 — Dynamic PII

`dynamic-pii` is an L3-only GLiNER pipeline. Choose entity labels at runtime,
gate it on another pipeline's result (e.g. run only when injection flags the
text), and read first-class `evidence_spans` with byte- and char-accurate
offsets. See the pipeline design in [gliner-integration.md](../gliner-integration.md).

## 06 — Unified L3 speedup

The same cache-unique text promotes both Injection and Sensitive Document to
L3. Dedicated executes two L3 models; Multi returns both logical head results
from one shared `physical_job_id`. Each strategy runs in a fresh process, lazy
ONNX session creation happens before timing, and the example prints median and
mean end-to-end latency plus the measured speedup.
