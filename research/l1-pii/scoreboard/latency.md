# L1-PII latency: Ark vs. Presidio

Machine: Intel Core Processor (Haswell, no TSX), 6 usable CPUs, Linux x86_64. One call per sample, sequential, each engine in its own process. Workloads v1: DE + EN pooled per size class.

| Engine | Init ms | short p50 / p95 / p99 ms | 4kib p50 / p95 / p99 ms | 100kib p50 / p95 / p99 ms |
|---|---:|---:|---:|---:|
| ark | 423 | 0.314 / 0.401 / 0.469 | 1.675 / 2.114 / 2.275 | 11.864 / 14.641 / 15.579 |
| ark-native | 311 | 0.240 / 0.342 / 0.384 | 1.570 / 1.919 / 2.119 | 8.068 / 9.947 / 10.690 |
| presidio-default | 4565 | 10.151 / 13.928 / 16.559 | 212.486 / 338.831 / 390.239 | 10407.527 / 13634.609 / 15005.935 |
| presidio-tuned | 8764 | 12.540 / 30.829 / 33.890 | 200.656 / 259.931 / 290.922 | 9803.598 / 11978.768 / 12399.738 |

| p95 / Ark (Python) | short | 4kib | 100kib |
|---|---:|---:|---:|
| ark-native | 0.85× | 0.91× | 0.68× |
| presidio-default | 35× | 160× | 931× |
| presidio-tuned | 77× | 123× | 818× |

| Workload | Bytes | Chars | ark spans | ark-native spans | presidio-default spans | presidio-tuned spans |
|---|---:|---:|---:|---:|---:|---:|
| short-de | 115 | 115 | 2 | 2 | 7 | 3 |
| short-en | 98 | 98 | 2 | 2 | 5 | 5 |
| 4kib-de | 4096 | 4052 | 46 | 46 | 140 | 82 |
| 4kib-en | 4096 | 4096 | 42 | 42 | 117 | 109 |
| 100kib-de | 102400 | 101229 | 1173 | 1173 | 3613 | 2051 |
| 100kib-en | 102400 | 102400 | 1038 | 1038 | 2907 | 2701 |

M4 (ark 100kib p95 ≤ 10 ms): 14.641 ms, FAIL.
M4 (ark-native 100kib p95 ≤ 10 ms): 9.947 ms, pass.

## Profile and remaining hotspots (H06 pass 3)

Ark rows measured after H06-3 (`latency.py run --engines ark ark-native`, the second of three runs;
100 KiB p95 over the three: ark 14.058 / 14.641 / 14.900 ms, ark-native 10.251 / 9.947 / 9.897 ms);
the Presidio rows are the H03 run. The native code is unchanged, so the ark-native spread is the
noise of the machine, which was busier than in pass 2. Spans per workload are unchanged. An A/B of
the Python binding against main, both in turn under the same load: 100 KiB p95 17.6–18.0 → 13.2–13.9
ms, short and 4 KiB unchanged.

Profile of the 100 KiB workloads through the Python binding (median per call, DE and EN pooled,
before → after pass 3):

| Part | ms |
|---|---:|
| Native scan (`scan_category` with the GIL released) | 7.9 (unchanged) |
| `_to_dict`: layer `details` (about 4 600 Python objects of 1 369 `matched_rules` entries), warm | 2.5 → 1.6 |
| `_to_dict`: layer `details`, right after the scan (the entries were built on the rayon workers) | 5.1 → 3.8 |
| `_to_dict`: `evidence_spans` (about 1 100 dicts) | 1.7 → 1.5 |
| Freeing the result dicts | 0.8 → 0.6 |
| Freeing the native result (serde values of the `matched_rules`) with the GIL held | 2.8 → 0.3 |

Pass 3 builds one Python string per distinct key or value text per `details` call (keys interned as
before, values not, as they may hold scanned text) and passes `Bound` values, so no dropped
`PyObject` checks the GIL; span labels are shared the same way. A released layer with at least 64
`matched_rules` entries hands its details to a background thread through a bounded queue (the caller
frees them when the queue is full); smaller ones are freed in place, as waking the thread costs short
texts as much as the free. Measured and not in: a `RegexSet` of all PII rules as a shared pre-pass
(about 1 s per 100 KiB: the union does not fit the lazy DFA), and anchor gates that require every
lexicon word inside a literal instead of one (2–3 of about 60 zero-match rule searches gated).

M4 holds for ark-native (within the noise), not for ark (Python). Remaining hotspots, each ≥ 10 % of
the ark p95, for H06-4:

- The rule searches: 60–65 of the 93 searched PII rules find nothing in either workload and still
  scan the whole text, about 10 of 19 ms search CPU per call (about 1.7 ms wall on 6 threads). Most
  start with their value, not a keyword, so the lexicon gates do not apply; a shared value-shape
  pre-pass (one scan that records which value classes and lengths occur) would skip them.
- The `matched_rules` entries as `serde_json::Value`: about 16 allocations per match, built on the
  rayon workers and read cache-cold when Python converts them (3.8 ms after the scan vs 1.6 ms warm),
  and freed natively (about 1.5 ms of the ark-native call). A typed entry (a struct that serializes to
  the same JSON) would cut the allocations, the drop and the conversion; the JSON shape stays.
- The sequential preparation before the parallel step (lowercase view, lexical anchors, structure
  parse; 1.4–1.7 ms).

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
