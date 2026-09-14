# Unified L3 fleet capacity — 2026-09-13

Measured through the private HTTP entrypoints of twelve Ubuntu worker hosts,
with three Ark workers per host and one NVIDIA L4 running Lion Warden through
TensorRT FP16. Each worker retains the normal synchronous admission behavior:
its capacity remains occupied while its dedicated L3 worker waits for inference.
No gateway concurrency optimization is included.

## Controlled results

| Clients | Requests/s | Input tokens/s | Client p50 | Client p95 |
| ---: | ---: | ---: | ---: | ---: |
| 36 | 2,313 | 460,324 | 6.48 ms | 42.45 ms |
| 144 | 3,270 | 650,777 | 37.40 ms | 78.76 ms |
| 288 | 3,454 | 687,301 | 78.33 ms | 116.16 ms |
| 432 | 3,502 | 696,954 | 106.73 ms | 173.68 ms |

Each row contains 44,322 successful requests with zero failed or degraded
responses, zero reported L2 cache hits, and zero Triton inference failures.
Increasing concurrency from 288 to 432 adds approximately 1.4% throughput
while increasing p95 latency from 116 ms to 174 ms.

## Workload and measurement

- Injection category only; L1 disabled, L2 and L3 enabled, `best_promote`
  operating point. This is not an all-category capacity measurement.
- The same 14,774-text validation selection used for the previous L2 fleet
  benchmark, repeated three times: 44,322 requests and 8,819,613 original
  content tokens per row.
- The same workload and nonce values are used for each client level. One
  private-use Unicode character per repetition prevents full-text cache reuse.
  Added nonce characters and GPU padding are excluded from input token rates.
- Workers are restarted incrementally before each row, outside the measured
  interval, to reset their in-memory caches. Normal cache reuse within each
  run remains enabled; this is not a cache-disabled microbenchmark.
- Clients are spread evenly across all twelve host entrypoints. Each client
  uses a persistent connection and claims its next text immediately after
  completion. Latency covers submission through the completed status response,
  including polling on the private LAN.
- Throughput divides completed requests and original input tokens by measured
  fleet wall time, using the same generator structure as the earlier L2 test.
- These are single runs per client level; short runs and normal production
  scheduling introduce measurement variation.

## GPU execution

The model revision is `30ea449339d1075a31fcffa9199ebee4f2cfaf9a`.
Inputs have 256 tokens; one GPU model instance uses batches up to 16 and a
maximum batching delay of 15 ms. Backlog time is additional to batching delay.

| Clients | GPU chunks | Observed GPU chunks/s |
| ---: | ---: | ---: |
| 36 | 13,664 | 713 |
| 144 | 13,671 | 1,009 |
| 288 | 13,610 | 1,061 |
| 432 | 13,714 | 1,084 |

These are differences in Triton's service counters around each measurement,
not counts of final L3 decisions or a measured promotion rate. Counters include
any concurrent service traffic. Ordinary per-worker cache reuse and routing
can change physical inference counts slightly between runs.

An initial series without resetting L3 caches reached approximately 3,700
requests/s at high concurrency. It is excluded from the main table because
later rows benefited from earlier cache contents.

## Correctness and security validation

A separate canary completed all ten configured categories over the private
GPU connection, including the independent tool-tag properties. Tool tags are
three sigmoid outputs, projected to their separate L2 property pipelines;
aggregation, promoted chunk selection, and joint-v3 context remain property
specific. Exact-cache and similarity-propagated outputs retain binary scores.

Regression tests cover row correspondence, malformed
responses, network failures/timeouts, independent property aggregation,
promoted chunk isolation, and selection of the correct joint-v3 context.

Public deployment instructions contain no live infrastructure inventory or
credentials. The GPU HTTP port was unreachable through the public endpoint;
it listens on the private VPN address, with metrics on loopback. Worker and
entrypoint scan requests without credentials returned HTTP 401. Triton itself
has no application authentication: authorized VPN peers are its trust boundary.
See the [deployment guide](https://github.com/patronus-protect/patronus-security/blob/main/ark-api/deploy/l3-triton/README.md).

The subsequent [batching-delay study](l4-batching-latency.md) measures shorter
collection times and records the new 5 ms default.
