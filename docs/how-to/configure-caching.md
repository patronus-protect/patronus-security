# Configure and understand caching

Caching is configured once when a `SecurityGateway` is created. Requests cannot
change the cache path or write mode.

The short version:

- Do nothing for a bounded, process-local memory cache.
- Pass `cache_storage_location` in Python for persistent asynchronous writes.
- Use `ExactCacheConfig` in Rust to choose persistent asynchronous or
  write-through writes.
- Call `flush_cache()` before a durability boundary or controlled shutdown.

Runnable examples:

- Python: `python python/examples/09_caching.py`
- Rust: `cargo run --example 09_caching -- /tmp/patronus-cache.redb`

## The three cache paths

| Cache | Hit condition | Stored value | Effect |
| --- | --- | --- | --- |
| Exact classifier cache | Same immutable model SHA and exact chunk bytes | Raw model logits per head | Skips Dedicated or Unified L3 inference. Current policy and thresholds are applied again. |
| Historical similarity cache | Same L2 vector space and a close cosine match | Canonical decision per logical head, plus producer logits | Prioritizes historical non-safe chunks. At cosine similarity `> 0.985`, a non-safe/non-benign head can propagate without L3 inference. |
| Dynamic PII cache | Exact GLiNER chunk input, or a previously known normalized entity span | Raw chunk candidates; normalized cleartext span plus class | Exact chunks skip GLiNER. A known span such as `Alexandr Stone` can be recognized at new offsets in another text. |

Dedicated and Unified L3 share the historical vector index. Raw logits remain
model-specific, because their tensor layouts can differ. The additional
canonical logical-head decision allows a finding produced by Dedicated to
prioritize or propagate for Unified, and vice versa.

Dynamic PII intentionally stores normalized cleartext spans. It does not hash
names. The cache database must therefore be protected like other local
application data.

Persistent cache files are opened with `redb`. Ark creates missing parent directories and missing
database files on startup. If the database file is externally deleted while a gateway is still
alive, the next cache operation recreates an empty database rather than continuing to write through
a stale handle. Corrupt database files and active second-writer conflicts remain hard errors.

## Five concrete scenarios

The Python example executes these in order and asserts the observable result:

```bash
python python/examples/09_caching.py /tmp/patronus-cache.redb
```

### 1. PII found for the first time

```text
Customer Alexandr Stone opened an account.
```

GLiNER finds the `person` span. The raw chunk candidates enter the exact chunk
cache and `alexandr stone + person` enters the entity-span cache.

### 2. Same PII span in different text

```text
Please contact Alexandr Stone about the renewal.
```

The chunk is new, but the normalized span is known. The early partial result
therefore contains:

```json
{"partial_result": true, "entity_cache_hit": true}
```

Offsets are calculated against the new text.

### 3. Exact same text

Scanning the second text again resolves the identical GLiNER chunk from the
exact cache. The final Dynamic PII layer reports:

```json
{"chunk_cache_hits": 1}
```

### 4. Unified cache and irrelevant heads

The example scans one text that promotes both `injection` and
`sensitive_document`, then scans it again with `l3_strategy="multi"`.

It asserts:

- only the subscribed logical heads are published;
- all second-run logical decisions equal the first-run decisions;
- the second Unified run reports physical cache hits.

The Unified model may compute other physical heads internally, but those heads
cannot leak into aggregation or published results. This is also covered by:

```bash
cargo test unified_aggregation_ignores_heads_on_irrelevant_physical_chunks
```

### 5. Similarity propagation and priority

The example first stores a non-safe Injection decision, then scans a
near-duplicate whose exact bytes differ. It requires and prints:

```text
similarity_score > 0.985
non-safe decision propagated
```

Historical non-safe matches set `head_priority = 0` before normal promoted
chunks are scheduled. The deterministic vector-level test—independent of model
assets—is:

```bash
cargo test historical_non_safe_similarity_is_scheduled_first
```

Safe/benign decisions never propagate. A score equal to `0.985` is insufficient;
the comparison is strictly greater than.

## Storage variants

### Python: memory only

```python
from patronus_ark import SecurityGateway

scanner = SecurityGateway(
    categories=["injection"],
    max_level="l3",
)
```

No persistent file is created. Entries disappear with the gateway/process.

### Python: persistent async

```python
scanner = SecurityGateway(
    categories=["injection", "dynamic-pii"],
    max_level="l3",
    cache_storage_location="/var/lib/my-app/patronus-cache.redb",
    cache_entry_ttl_seconds=30 * 24 * 60 * 60,
    cache_memory_max_entries=100_000,
    cache_memory_max_bytes=128 * 1024 * 1024,
)

# Wait until queued writes are durable.
scanner.flush_cache()
```

The request path only enqueues persistent writes. A bounded queue and batched
`redb` transactions keep those writes off the inference path. Python always uses asynchronous
write-behind with the default queue and batch size; `CacheWriteMode` and `WriteBehindConfig` are
Rust-only, so write-through and custom queue sizing are not reachable from Python.

### Rust: memory only

```rust
use patronus_ark::{SecurityCategory, SecurityGateway, SecurityLevel};

let scanner = SecurityGateway::with_max_level(
    vec![SecurityCategory::Injection],
    SecurityLevel::L3,
    None,
    true,
);
```

### Rust: persistent async

```rust
use std::path::PathBuf;
use patronus_ark::{
    CacheWriteMode, ExactCacheConfig, PersistentCacheConfig,
    SecurityCategory, SecurityGateway, SecurityLevel, WriteBehindConfig,
};

let config = ExactCacheConfig {
    persistent: Some(PersistentCacheConfig {
        storage_location: PathBuf::from("/var/lib/my-app/patronus-cache.redb"),
        write_mode: CacheWriteMode::Async,
        write_behind: WriteBehindConfig::default(),
    }),
    ..ExactCacheConfig::default()
};

let scanner = SecurityGateway::try_with_download_categories_and_cache(
    vec![SecurityCategory::Injection],
    SecurityLevel::L3,
    None,
    true,
    None,
    config,
).expect("cache initialization");

scanner.flush_cache().expect("durable cache flush");
```

For write-through persistence, change only:

```rust
write_mode: CacheWriteMode::WriteThrough,
```

Write-through is useful only when every new entry must be durable immediately;
it adds millisecond-scale storage latency to misses.

**Write-behind back-pressure.** Under `Async`, if the bounded write queue fills faster than the
background writer drains it, the overflowing writes are **dropped silently** — no error, no
exposed counter — so the cache never blocks a miss or an inference. Entries dropped this way are
simply recomputed the next time. Call `flush_cache()` before a durability boundary rather than
relying on back-pressure, and raise `WriteBehindConfig.queue_capacity` (Rust) if you see repeated
misses under sustained write bursts.

## What happens during two scans

For the exact same promoted classifier chunk:

```text
first scan:  RAM miss → persistent miss → L3 inference → RAM write → persistent write
second scan: RAM hit → decode raw logits → apply current policy
after restart: RAM miss → persistent hit → repopulate RAM → apply current policy
```

For a near duplicate:

```text
exact miss → reuse L2 embedding → cosine lookup
           → historical non-safe match raises priority
           → if cosine > 0.985: propagate that logical head
           → otherwise: run L3 normally
```

Similarity uses the same two tiers as every other cache path. The hot tier is
bounded by the configured entry and byte limits. The persistent tier stores
individual binary vector records plus redb multimap bucket entries and has no
entry-count limit; expiry is controlled only by the shared TTL. A persistent
hit is admitted to the hot tier. Evicting a hot vector never removes its
persistent record.

The bucket index is approximate, but every candidate is verified with exact
cosine similarity before propagation. A missed bucket match causes normal L3
inference; it cannot create a false propagated decision.

There is no text-to-token conversion inside the similarity cache. L2 already
produced the embedding. If an L3 window overlaps multiple L2 chunks, their
vectors are averaged by byte overlap and normalized.

## Dynamic PII and early result events

Dynamic PII has two reuse levels:

1. An exact chunk hit reuses raw GLiNER candidates.
2. The entity cache finds a known normalized cleartext span in different
   surrounding text and recalculates byte/character offsets.

As soon as the first entity is available—from either cache or fresh
inference—the queue publishes a `result` event containing:

```json
{
  "event_type": "result",
  "result": {
    "class_name": "entities",
    "layers": [{
      "layer_type": "dynamic_pii_first_entity",
      "details": {
        "partial_result": true,
        "first_entity": true,
        "entity_cache_hit": true
      }
    }]
  }
}
```

This event does not complete the request and does not increment final result
accounting. The complete result follows after all chunks finish. Blocking APIs
such as `scan_all()` filter out the partial event.

## Metadata to inspect

Classifier L3 layers expose fields such as:

- `exact_cache_source`: `memory`, `persistent`, or `computed`
- `cache_hit`: `similarity` for an accepted historical propagation
- `similarity_method`: `l2_cosine`
- `similarity_score`
- `source_model_sha`
- `cache_authoritative`

Dynamic PII final layers expose `chunk_cache_hits` and `entity_cache_hits`.

## Expected local storage latency

The checked-in release microbenchmark measured:

| Operation | p50 |
| --- | ---: |
| RAM read | 1.42 µs |
| Warm `redb` read | 2.29 µs |
| Async write enqueue | 0.58 µs |
| Durable single write | 4.04 ms |
| Batched durable write, amortized | 90.01 µs/entry |

These are storage microbenchmarks, not end-to-end model latencies. Reproduce
them with:

```bash
cargo test --release cache::benchmark::cache_latency_microbenchmark \
  --lib -- --ignored --nocapture --test-threads=1
```

The exact-store scaling benchmark verifies Hot and Persistent operations at
100, 1,000, and 10,000 stored records:

| Exact-store operation p50 | 100 | 1,000 | 10,000 |
| --- | ---: | ---: | ---: |
| Hot read | 1.46 µs | 1.67 µs | 1.46 µs |
| Hot write | 1.04 µs | 1.21 µs | 1.42 µs |
| Persistent read | 4.71 µs | 2.38 µs | 2.42 µs |
| Persistent durable write | 4.03 ms | 4.02 ms | 4.03 ms |

```bash
cargo test --release --lib exact_cache_scaling_microbenchmark \
  -- --ignored --nocapture
```

The similarity scaling benchmark uses 128-dimensional vectors and the same
record counts:

| Operation p50 | 100 | 1,000 | 10,000 |
| --- | ---: | ---: | ---: |
| Hot read | 77.8 µs | 80.0 µs | 93.7 µs |
| Hot write | 81.8 µs | 82.5 µs | 84.8 µs |
| Persistent read | 84.0 µs | 93.5 µs | 156.0 µs |
| Persistent async write | 80.5 µs | 88.1 µs | 80.9 µs |
| Persistent durable write | 4.01 ms | 4.13 ms | 4.08 ms |

The 100× larger persistent dataset does not produce proportional latency
growth. Reproduce it with:

```bash
cargo test --release --lib similarity_cache_scaling_microbenchmark \
  -- --ignored --nocapture
```
