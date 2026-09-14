# L4 batching latency study — 2026-09-13

This follow-up isolates the Triton batching delay. Ark worker admission, L1/L2
concurrency, GPU engine, model revision, instance count, and batch-size limit
remain unchanged. The deployed and documented default is now **5 ms**.

## Controlled fleet comparison

Each row uses 288 clients, the same injection workload and nonce values,
44,322 requests, L1 disabled, L2/L3 enabled, and `best_promote`. Workers are
restarted incrementally before each row to reset their in-memory caches.
Restart time is excluded from measurement; normal within-run caches remain
active. All rows completed without failed/degraded requests, reported L2 cache
hits, or Triton inference failures.

| Maximum collection delay | Requests/s | Input tokens/s | Client p50 | Client p95 |
| ---: | ---: | ---: | ---: | ---: |
| 15 ms | 3,470 | 690,443 | 78.31 ms | 115.70 ms |
| 8 ms | 3,762 | 748,559 | 70.48 ms | 108.93 ms |
| 5 ms | 3,904 | 776,905 | 68.34 ms | 107.05 ms |
| 1 ms | 3,871 | 770,334 | 68.10 ms | 108.46 ms |
| 0 ms | 3,833 | 762,772 | 68.88 ms | 109.24 ms |

These are individual runs per setting. The small differences between 5, 1, and
0 ms do not establish a universal optimum, but lowering collection time from
15 to 5 ms improved this measured workload by approximately 12.5%. A 432-client
confirmation at 5 ms reached 3,901 requests/s and 776,301 input tokens/s, with
97.22 ms client p50 and 161.06 ms p95. Additional clients did not improve capacity.

## Where time is spent

| Collection delay | Ark L3 step mean | Triton queue mean | GPU inference mean | Mean GPU batch |
| ---: | ---: | ---: | ---: | ---: |
| 15 ms | 18.66 ms | 6.69 ms | 8.47 ms | 15.05 |
| 8 ms | 15.84 ms | 4.41 ms | 7.72 ms | 11.13 |
| 5 ms | 14.49 ms | 3.79 ms | 7.02 ms | 9.07 |
| 1 ms | 14.32 ms | 3.57 ms | 7.01 ms | 8.24 |
| 0 ms | 14.62 ms | 3.63 ms | 7.10 ms | 8.31 |

Triton times are differences in its cumulative inference statistics, divided
by completed requests. Queue time includes intentional collection and waiting
for a busy model instance. Therefore zero collection delay does not imply zero
queue time. GPU times come from Triton's `compute_infer` measurements.

The Ark L3 step is derived from final L3 response duration minus reported L2
duration. It includes cached paths and client-side work; Triton statistics
cover actual inference calls. These populations differ, so subtracting the two
means is not an exact transport-latency measurement.

L2 remained approximately 1.2 ms on average. Mean gateway admission wait fell
from 47.25 ms at 15 ms collection to 38.62 ms at 5 ms. This upstream queue is a
consequence of occupied workers; it is not a measurement of the AWS queue.

## Direct GPU service and hardware checks

At each setting, a separate 36-client GPU-host test sent 8,640 single-chunk
requests after 360 warmup requests. All inputs had 256 active tokens. Direct
service throughput stayed between approximately 1,465 and 1,498 chunks/s.
Under sustained full batches, reducing the collection deadline did not improve
that throughput. The low-delay advantage appears in the fleet's intermittent
arrival pattern.

A separate instrumented 432-client run at 5 ms produced 3,913 requests/s and
778,663 input tokens/s without errors. In ten interior hardware samples
(excluding two seconds at each edge of the benchmark process window):

- Mean GPU utilization: 90.1%; whole-window mean 73.5%, peak 97%.
- Mean host CPU utilization: 18.8%; hottest CPU core mean 20.1%.
- Actual GPU throughput: approximately 1,202 chunks/s.
- Mean physical batch size: 9.14.

This does not indicate an AWS CPU capacity limit. Shorter collection reduces
latency but also reduces batch efficiency. At 15 ms the engine formed larger
batches while spending more time awaiting work; at short delays the GPU works
more continuously on smaller batches. The separate full-batch GPU throughput
is therefore not attained by the current coupled fleet workflow.

Using measured GPU request rate and mean server residence time gives an average
of approximately 14 requests inside the GPU service in the instrumented run.
This is an inference from Little's law, not an instantaneous concurrency trace.
Increasing external client count does not directly increase GPU concurrency
because each Ark worker remains occupied until its L3 work completes.

The tested collection-delay change alone reaches approximately 0.78 million
input tokens/s, not 0.9 million. No gateway concurrency change, additional GPU
model instance, or queue-capacity increase was included in this experiment.

The subsequent [bounded worker overlap experiment](l4-worker-overlap.md) measures two outstanding submissions per worker with the selected 5 ms GPU configuration.
