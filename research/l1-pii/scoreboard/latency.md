# L1-PII latency: Ark vs. Presidio

Machine: Intel Core Processor (Haswell, no TSX), 6 usable CPUs, Linux x86_64. One call per sample, sequential, each engine in its own process. Workloads v1: DE + EN pooled per size class.

| Engine | Init ms | short p50 / p95 / p99 ms | 4kib p50 / p95 / p99 ms | 100kib p50 / p95 / p99 ms |
|---|---:|---:|---:|---:|
| ark | 451 | 0.215 / 0.334 / 0.390 | 1.469 / 1.841 / 1.994 | 12.575 / 15.920 / 16.557 |
| ark-native | 245 | 0.202 / 0.324 / 0.408 | 1.255 / 1.606 / 1.719 | 7.765 / 9.402 / 9.595 |
| presidio-default | 4565 | 10.151 / 13.928 / 16.559 | 212.486 / 338.831 / 390.239 | 10407.527 / 13634.609 / 15005.935 |
| presidio-tuned | 8764 | 12.540 / 30.829 / 33.890 | 200.656 / 259.931 / 290.922 | 9803.598 / 11978.768 / 12399.738 |

| p95 / Ark (Python) | short | 4kib | 100kib |
|---|---:|---:|---:|
| ark-native | 0.97× | 0.87× | 0.59× |
| presidio-default | 42× | 184× | 856× |
| presidio-tuned | 92× | 141× | 752× |

| Workload | Bytes | Chars | ark spans | ark-native spans | presidio-default spans | presidio-tuned spans |
|---|---:|---:|---:|---:|---:|---:|
| short-de | 115 | 115 | 2 | 2 | 7 | 3 |
| short-en | 98 | 98 | 2 | 2 | 5 | 5 |
| 4kib-de | 4096 | 4052 | 46 | 46 | 140 | 82 |
| 4kib-en | 4096 | 4096 | 42 | 42 | 117 | 109 |
| 100kib-de | 102400 | 101229 | 1173 | 1173 | 3613 | 2051 |
| 100kib-en | 102400 | 102400 | 1038 | 1038 | 2907 | 2701 |

M4 (ark 100kib p95 ≤ 10 ms): 15.920 ms, FAIL.
M4 (ark-native 100kib p95 ≤ 10 ms): 9.402 ms, pass.

## Profile and remaining hotspots (H06 pass 2)

Ark rows measured after H06-2 (`latency.py run --engines ark ark-native`, the second of three runs;
100 KiB p95 over the three: ark 14.139 / 15.920 / 15.811 ms, ark-native 8.822 / 9.402 / 10.025 ms, so
ark-native sits at the budget within the noise of the machine); the Presidio rows are the H03 run.
Spans per workload are unchanged. 100 KiB p95 since pass 1: ark 24.651 → 15.920 ms, ark-native
15.324 → 9.402 ms.

Profile of the 100 KiB workloads (median per call, DE and EN alike, release build with timers):

| Part | ms |
|---|---:|
| Native: lowercase view, lexical anchors, structure parse | 1.4–1.7 |
| Native: value runs (`rule_scan`) | 0.2–0.3 |
| Native: per-rule gates, searches, validation, scoring, `matched_rules` entries (parallel; CPU sum about 17: searches 13.3, per-match work 3.1) | 4.0–4.5 wall |
| Native: overlap resolution, finalize, char offsets; deobfuscation view; secondary marks | 0.9 |
| Native: drop of the result (about 1 360 `matched_rules` objects) | 1.5–1.6 |
| Python: `_to_dict`, mostly the `matched_rules` details as Python objects (about 4 500 dicts) | 3.4–4.5 |
| Python: freeing the result dicts and the native result | 1.6–2.5 |

Pass 2 moves the whole per-rule work of large texts onto the rayon pool: each rule is gated,
searched, and its matches validated, scored and turned into `matched_rules` entries and spans on its
own (`NativeRegexDetector::rule_findings`); the results are joined in rule order, so overlap
resolution is unchanged. The Python binding no longer round-trips the layer details through JSON
text (serialize in Rust, `json.loads` in Python, about 3.7 ms): the `details` and `thresholds`
getters build the Python objects directly. The `evidence_spans` getter returns the span dicts of
the public result. Building the anchors and the structure side by side before the parallel search
was measured and gave nothing; it is not in.

M4 holds for ark-native, not for ark (Python). Remaining hotspots, each ≥ 10 % of the ark p95, for
H06-3: the `matched_rules` details as Python objects and their release (about 5–6 ms together; a
lazy details view or a leaner entry would cut them, but the result shape is public), the CPU time of
the rule searches (13 ms over 6 threads; most PII rules start with their value, not a keyword), and
the native result drop (1.5 ms, about 20 000 small allocations of the `matched_rules` JSON).

## Profile and remaining hotspots (H06 pass 1)

Ark rows measured after H06 pass 1 (`latency.py run --engines ark ark-native`); the Presidio rows are
the H03 run on the same machine (Presidio and the workloads are unchanged). Spans per workload are
unchanged. 100 KiB p95 since H03: ark 35.898 → 24.651 ms, ark-native 28.441 → 15.324 ms.

Profile of the 100 KiB workloads through the gateway (native, strict, mean per call, before → after
pass 1; DE / EN):

| Part | DE ms | EN ms |
|---|---:|---:|
| Whole call | 25.9 → 12.3 | 24.5 → 12.2 |
| Rule gates and searches (93 rules, each a full-text lazy-DFA scan of about 0.18 ms) | 14.4 → parallel | 14.7 → parallel |
| Validation, scoring and `matched_rules` JSON of about 1 360 matches | 3.4 | 3.4 |
| Drop of the result (1 360 `matched_rules` objects, 1 100 spans) | 2.3 | 2.5 |
| Lowercase view + lexical anchors | 2.3 → 1.0 | 1.0 |
| Overlap resolution, finalize, char offsets | 0.7 | 0.7 |
| Structure parse, deobfuscation view, value runs | 1.1 | 1.4 |

Pass 1 lowercases the ASCII runs of non-ASCII text in place and gates and searches the rules of texts
from 32 KiB on in parallel (rayon); validation, scoring and overlap resolution stay sequential.
Remaining hotspots, each ≥ 10 % of p95, for H06-2: the Python result conversion (ark minus
ark-native, about 9 ms: the `matched_rules` details of every match become Python objects), the
sequential per-match work and the result drop (about 6 ms together), and the rule searches themselves
(CPU time unchanged; a shared literal or multi-pattern prefilter would cut it, but most PII rules start
with their value, not a keyword).
