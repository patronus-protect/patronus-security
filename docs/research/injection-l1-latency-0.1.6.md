# Injection L1 latency 0.1.6

Status: release-mode local gateway benchmark passed on macOS 14.8.7 arm64.

The benchmark used the freshly built `patronus-ark` release extension, one reused gateway,
10 warmup scans and 50 measured scans per case. Values are wall-clock **milliseconds**, not
seconds. Inputs are exact UTF-8 byte sizes. The positive case embeds the calibrated English
override-plus-system-prompt-disclosure relationship at the end of the document.

| Input | Case | Median (ms) | p95 (ms) | Max (ms) | Accepted runs |
|---:|---|---:|---:|---:|---:|
| 1 KiB | benign | 0.200 | 0.253 | 0.618 | 0/50 |
| 1 KiB | embedded attack | 0.773 | 1.068 | 1.233 | 50/50 |
| 10 KiB | benign | 0.826 | 1.258 | 1.362 | 0/50 |
| 10 KiB | embedded attack | 1.556 | 1.706 | 1.841 | 50/50 |
| 100 KiB | benign | 7.003 | 7.143 | 7.166 | 0/50 |
| 100 KiB | embedded attack | 9.240 | 9.463 | 9.517 | 50/50 |

The 100 KiB result is therefore approximately **7–9.5 ms**, not 7,000–9,500 ms. The full
machine-readable output for the release run was written outside the repository to
`/private/tmp/injection-l1-latency-0.1.6.json`; the reproducible runner is
`scripts/benchmark_injection_l1.py`.

These numbers are a branch regression baseline for the named host class, not a universal latency
SLA. The benchmark measures the public gateway path, including every internal native Injection
producer, candidate aggregation, scoring and result construction.
