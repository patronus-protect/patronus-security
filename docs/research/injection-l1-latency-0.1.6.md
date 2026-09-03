# Injection L1 latency 0.1.6

Status: release-mode local gateway benchmark passed on macOS 14.8.7 arm64.

The benchmark used the freshly built `patronus-ark` release extension after the final P0 catalog
execution fix, one reused gateway, 20 warmup scans and 100 measured scans per case. Values are wall-clock **milliseconds**, not
seconds. Inputs are exact UTF-8 byte sizes. The positive case embeds the calibrated English
override-plus-system-prompt-disclosure relationship at the end of the document.

| Input | Case | Median (ms) | p95 (ms) | Max (ms) | Accepted runs |
|---:|---|---:|---:|---:|---:|
| 1 KiB | benign | 0.221 | 0.243 | 0.342 | 0/100 |
| 1 KiB | embedded attack | 1.038 | 1.113 | 1.181 | 100/100 |
| 10 KiB | benign | 1.042 | 1.116 | 1.263 | 0/100 |
| 10 KiB | embedded attack | 2.121 | 2.355 | 5.903 | 100/100 |
| 100 KiB | benign | 9.136 | 9.342 | 10.082 | 0/100 |
| 100 KiB | embedded attack | 12.895 | 13.504 | 15.505 | 100/100 |

The 100 KiB result is therefore approximately **9–13.5 ms** at median/p95, not seconds. The
machine-readable output is intentionally kept outside the repository; the reproducible runner is
`scripts/benchmark_injection_l1.py`.

These numbers are a branch regression baseline for the named host class, not a universal latency
SLA. The benchmark measures the public gateway path, including every internal native Injection
producer, candidate aggregation, scoring and result construction.
