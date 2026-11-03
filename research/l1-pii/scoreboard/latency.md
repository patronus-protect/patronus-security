# L1-PII latency: Ark vs. Presidio

Machine: Intel Core Processor (Haswell, no TSX), 6 usable CPUs, Linux x86_64. One call per sample, sequential, each engine in its own process. Workloads v1: DE + EN pooled per size class.

| Engine | Init ms | short p50 / p95 / p99 ms | 4kib p50 / p95 / p99 ms | 100kib p50 / p95 / p99 ms |
|---|---:|---:|---:|---:|
| ark | 521 | 0.287 / 0.402 / 0.488 | 1.882 / 2.461 / 2.858 | 20.282 / 24.651 / 24.882 |
| ark-native | 258 | 0.247 / 0.317 / 0.351 | 1.617 / 2.160 / 2.412 | 12.332 / 15.324 / 19.046 |
| presidio-default | 4565 | 10.151 / 13.928 / 16.559 | 212.486 / 338.831 / 390.239 | 10407.527 / 13634.609 / 15005.935 |
| presidio-tuned | 8764 | 12.540 / 30.829 / 33.890 | 200.656 / 259.931 / 290.922 | 9803.598 / 11978.768 / 12399.738 |

| p95 / Ark (Python) | short | 4kib | 100kib |
|---|---:|---:|---:|
| ark-native | 0.79× | 0.88× | 0.62× |
| presidio-default | 35× | 138× | 553× |
| presidio-tuned | 77× | 106× | 486× |

| Workload | Bytes | Chars | ark spans | ark-native spans | presidio-default spans | presidio-tuned spans |
|---|---:|---:|---:|---:|---:|---:|
| short-de | 115 | 115 | 2 | 2 | 7 | 3 |
| short-en | 98 | 98 | 2 | 2 | 5 | 5 |
| 4kib-de | 4096 | 4052 | 46 | 46 | 140 | 82 |
| 4kib-en | 4096 | 4096 | 42 | 42 | 117 | 109 |
| 100kib-de | 102400 | 101229 | 1173 | 1173 | 3613 | 2051 |
| 100kib-en | 102400 | 102400 | 1038 | 1038 | 2907 | 2701 |

M4 (ark 100kib p95 ≤ 10 ms): 24.651 ms, FAIL.
M4 (ark-native 100kib p95 ≤ 10 ms): 15.324 ms, FAIL.

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
