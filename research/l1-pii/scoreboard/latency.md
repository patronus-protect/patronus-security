# L1-PII latency: Ark vs. Presidio

Machine: Intel Core Processor (Haswell, no TSX), 6 usable CPUs, Linux x86_64. One call per sample, sequential, each engine in its own process. Workloads v1: DE + EN pooled per size class.

| Engine | Init ms | short p50 / p95 / p99 ms | 4kib p50 / p95 / p99 ms | 100kib p50 / p95 / p99 ms |
|---|---:|---:|---:|---:|
| ark | 229 | 0.141 / 0.227 / 0.296 | 1.186 / 2.649 / 2.967 | 32.067 / 76.235 / 89.496 |
| ark-native | 58 | 0.097 / 0.164 / 0.223 | 0.954 / 2.451 / 3.090 | 24.285 / 67.786 / 77.698 |
| presidio-default | 3523 | 9.337 / 10.863 / 12.200 | 155.646 / 173.117 / 189.110 | 9633.301 / 10213.391 / 10527.409 |
| presidio-tuned | 6301 | 9.847 / 11.733 / 13.346 | 150.509 / 173.813 / 187.657 | 7328.866 / 10456.779 / 10466.779 |

| p95 / Ark (Python) | short | 4kib | 100kib |
|---|---:|---:|---:|
| ark-native | 0.72× | 0.93× | 0.89× |
| presidio-default | 48× | 65× | 134× |
| presidio-tuned | 52× | 66× | 137× |

| Workload | Bytes | Chars | ark spans | ark-native spans | presidio-default spans | presidio-tuned spans |
|---|---:|---:|---:|---:|---:|---:|
| short-de | 115 | 115 | 2 | 2 | 7 | 3 |
| short-en | 98 | 98 | 2 | 2 | 5 | 5 |
| 4kib-de | 4096 | 4052 | 42 | 42 | 140 | 82 |
| 4kib-en | 4096 | 4096 | 34 | 34 | 117 | 109 |
| 100kib-de | 102400 | 101229 | 1075 | 1075 | 3613 | 2051 |
| 100kib-en | 102400 | 102400 | 831 | 831 | 2907 | 2701 |

M4 (ark 100kib p95 ≤ 10 ms): 76.235 ms, FAIL.
M4 (ark-native 100kib p95 ≤ 10 ms): 67.786 ms, FAIL.
