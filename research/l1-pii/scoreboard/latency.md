# L1-PII latency: Ark vs. Presidio

Machine: Intel Core Processor (Haswell, no TSX), 6 usable CPUs, Linux x86_64. One call per sample, sequential, each engine in its own process. Workloads v1: DE + EN pooled per size class.

| Engine | Init ms | short p50 / p95 / p99 ms | 4kib p50 / p95 / p99 ms | 100kib p50 / p95 / p99 ms |
|---|---:|---:|---:|---:|
| ark | 480 | 0.289 / 0.395 / 0.457 | 1.815 / 2.645 / 2.976 | 30.253 / 35.898 / 39.635 |
| ark-native | 267 | 0.227 / 0.337 / 0.366 | 1.505 / 2.099 / 2.291 | 23.280 / 28.441 / 29.123 |
| presidio-default | 4565 | 10.151 / 13.928 / 16.559 | 212.486 / 338.831 / 390.239 | 10407.527 / 13634.609 / 15005.935 |
| presidio-tuned | 8764 | 12.540 / 30.829 / 33.890 | 200.656 / 259.931 / 290.922 | 9803.598 / 11978.768 / 12399.738 |

| p95 / Ark (Python) | short | 4kib | 100kib |
|---|---:|---:|---:|
| ark-native | 0.86× | 0.79× | 0.79× |
| presidio-default | 35× | 128× | 380× |
| presidio-tuned | 78× | 98× | 334× |

| Workload | Bytes | Chars | ark spans | ark-native spans | presidio-default spans | presidio-tuned spans |
|---|---:|---:|---:|---:|---:|---:|
| short-de | 115 | 115 | 2 | 2 | 7 | 3 |
| short-en | 98 | 98 | 2 | 2 | 5 | 5 |
| 4kib-de | 4096 | 4052 | 46 | 46 | 140 | 82 |
| 4kib-en | 4096 | 4096 | 42 | 42 | 117 | 109 |
| 100kib-de | 102400 | 101229 | 1173 | 1173 | 3613 | 2051 |
| 100kib-en | 102400 | 102400 | 1038 | 1038 | 2907 | 2701 |

M4 (ark 100kib p95 ≤ 10 ms): 35.898 ms, FAIL.
M4 (ark-native 100kib p95 ≤ 10 ms): 28.441 ms, FAIL.
