# Bounded worker overlap experiment

The worker already processes L1/L2 separately from its L3 worker. The entrypoint normally holds one submission slot until every job in that submission finishes, so it cannot feed another scan to that worker while L3 is pending.

`gateway.max_inflight_per_worker` retains the default of `1`. Setting it to `2` allows two outstanding submissions per physical worker; L1/L2 remains serial inside the worker, while its separate L3 worker can continue processing the preceding request. This does not add GPU instances or parallel L3 HTTP calls within a worker.

Each submission retains its admission permit until all constituent jobs finish. Multipart submissions can contain multiple jobs, so this is a submission limit, not a chunk limit. Waiting admission remains separately bounded by `max_waiting_requests`.

An uncertain completion quarantines every slot for that physical worker. Recovery requires all local leases to drain and a successful authenticated idle fence. A health response alone cannot restore capacity.

## Measurement protocol

Keep the GPU configuration at batch 16, one model instance and a maximum collection delay of 5 ms. Compare one and two outstanding submissions per worker using the same corpus, nonces, client counts and rolling cache reset protocol as the [batching study](l4-batching-latency.md).

Start with one worker host, check complete scan results and health, then run the full fleet comparison. Record request and original-input-token throughput, client p50/p95, L2 and L3 step timings, Triton queue and compute durations, mean GPU batch size, failures and degraded completions. Revert to one slot if overlap causes failures or does not improve sustained throughput.

The live experiment completed on 2026-09-13. All 12 entrypoints now use two slots per worker. Worker binaries and the GPU configuration were unchanged. The public deployment template retains the conservative default of one slot.

## Local validation

All 28 entrypoint tests passed, including bounded admission, overlapping cancellation, quarantine, authenticated recovery, and a permit already assigned to an awakened waiter. The experiment is restricted to one or two submission slots per worker.

## Fleet results

Each load level submitted 44,322 scans (14,774 corpus rows, three repetitions) with 8,819,613 original-content tokens. All 177,288 scans completed without failures or degraded completion; all four runs recorded zero L2 cache hits and zero Triton failures. Rolling worker restarts reset caches before each load level; ordinary within-run caching remained enabled. A preceding single-host canary completed 3,696 scans successfully.

| Clients | Requests/s | Original input tokens/s | Client p50 (ms) | Client p95 (ms) |
|---:|---:|---:|---:|---:|
| 36 | 2,638 | 524,979 | 6.71 | 36.79 |
| 144 | 3,889 | 773,956 | 26.91 | 72.38 |
| 288 | 4,216 | 838,883 | 59.31 | 110.87 |
| 432 | 4,281 | 851,874 | 86.72 | 169.50 |

## Comparison with one slot

The earlier one-slot measurements used the same corpus, nonces, cache-reset protocol, 5 ms GPU collection delay and one GPU model instance. They were separate runs, rather than a simultaneous comparison; the percentages below describe the observed runs, not confidence intervals.

| Clients | Slots | Requests/s | Input tokens/s | Client p50 (ms) | Client p95 (ms) |
|---:|---:|---:|---:|---:|---:|
| 288 | 1 | 3,904 | 776,905 | 68.34 | 107.05 |
| 288 | 2 | 4,216 | 838,883 | 59.31 | 110.87 |
| 432 | 1 | 3,901 | 776,301 | 97.22 | 161.06 |
| 432 | 2 | 4,281 | 851,874 | 86.72 | 169.50 |

At 288 clients, throughput increased by 8.0%, p50 decreased by 13.2%, and p95 increased by 3.6%. At 432 clients, throughput increased by 9.7%, p50 decreased by 10.8%, and p95 increased by 5.2%. Overlap therefore improves capacity and median latency but does not improve every latency percentile.

## Where the time goes

| Clients | L2 mean (ms) | L3 step mean (ms) | Entrypoint queue mean (ms) | Triton queue mean (ms) | GPU compute mean (ms) | Mean GPU batch | GPU chunks/s |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 36 | 1.31 | 11.53 | 0.00 | 3.22 | 4.76 | 6.27 | 814 |
| 144 | 1.29 | 16.64 | 5.87 | 4.65 | 8.12 | 10.74 | 1,198 |
| 288 | 1.24 | 19.00 | 23.18 | 5.85 | 9.30 | 13.02 | 1,298 |
| 432 | 1.22 | 19.81 | 39.20 | 6.37 | 9.68 | 13.73 | 1,321 |

L2 remains near 1.2 ms at high load. At 432 clients the average GPU batch grows from 9.35 to 13.73 chunks, and GPU chunk throughput grows from approximately 1,200 to 1,321 chunks/s. Entrypoint queue time decreases from 59.50 to 39.20 ms, while the L3 step rises from 14.71 to 19.81 ms. The additional outstanding work fills GPU batches more efficiently, but also spends longer waiting for L3.

The L3 step metric is category duration minus recorded L2 duration for final-L3 responses. Triton metrics describe actual GPU requests, a different population because of caching and aggregation. Their difference must not be interpreted as an exact network or local-L3 queue measurement. The experiment did not add per-request distributed tracing.

At 432 clients the summed batch compute duration occupies 88.7% of the benchmark interval. This is derived from Triton batch statistics, not a new hardware utilization measurement. The direct GPU test previously achieved approximately 1,500 chunks/s with full batches of 16; the overlapping fleet still averages fewer than 16. The observed input-token throughput remains below 900,000 tokens/s.

## Deployment and rollback

Only the entrypoint binary and its configuration changed. The fleet uses `max_inflight_per_worker: 2`; reverting that setting to `1` and restarting entrypoints restores sequential admission. Existing authentication and network bindings remain unchanged. Configuration and image references from before the experiment were retained privately for rollback.

Validation: all 28 entrypoint tests passed, Clippy with warnings denied passed. The public template defaults to one slot; accepted values are restricted to one or two.
