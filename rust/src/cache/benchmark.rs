// SPDX-License-Identifier: GPL-3.0-only
use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::{
    decision_output, CacheCoordinator, CacheEncryptionConfig, CacheKey, CacheNamespace,
    CacheWriteMode, CachedHeadOutput, CachedModelOutput, ExactCacheConfig, ExactCacheStore,
    HistoricalSimilarityCache, MemoryCacheConfig, MemoryCacheStore, PersistentCacheConfig,
    RedbCacheStore, WriteBehindConfig, WriteBehindStore,
};

#[test]
#[ignore = "release-mode cache latency microbenchmark"]
fn cache_latency_microbenchmark() {
    let path = temp_path();
    let output = representative_output();
    let read_key = key("read");
    let memory = MemoryCacheStore::new(MemoryCacheConfig::default());
    let redb = Arc::new(RedbCacheStore::open(&path).unwrap());
    let encrypted_path = temp_path();
    let encrypted_redb = Arc::new(
        RedbCacheStore::open_with_encryption(&encrypted_path, Some(encryption_config())).unwrap(),
    );
    memory.put(read_key, output.clone()).unwrap();
    redb.put(read_key, output.clone()).unwrap();
    encrypted_redb.put(read_key, output.clone()).unwrap();

    for _ in 0..1_000 {
        black_box(memory.get(&read_key, 10).unwrap().unwrap());
        black_box(redb.get(&read_key, 10).unwrap().unwrap());
        black_box(encrypted_redb.get(&read_key, 10).unwrap().unwrap());
    }
    report(
        "ram_read",
        measure(50_000, || {
            black_box(memory.get(&read_key, 10).unwrap().unwrap());
        }),
    );
    report(
        "redb_plain_read",
        measure(20_000, || {
            black_box(redb.get(&read_key, 10).unwrap().unwrap());
        }),
    );
    report(
        "redb_encrypted_read",
        measure(20_000, || {
            black_box(encrypted_redb.get(&read_key, 10).unwrap().unwrap());
        }),
    );

    let write_keys = (0..500)
        .map(|index| key(&format!("single-{index}")))
        .collect::<Vec<_>>();
    let mut write_index = 0;
    report(
        "redb_plain_durable_single_write",
        measure(write_keys.len(), || {
            redb.put(write_keys[write_index], output.clone()).unwrap();
            write_index += 1;
        }),
    );
    let encrypted_write_keys = (0..500)
        .map(|index| key(&format!("encrypted-single-{index}")))
        .collect::<Vec<_>>();
    let mut encrypted_write_index = 0;
    report(
        "redb_encrypted_durable_single_write",
        measure(encrypted_write_keys.len(), || {
            encrypted_redb
                .put(encrypted_write_keys[encrypted_write_index], output.clone())
                .unwrap();
            encrypted_write_index += 1;
        }),
    );

    let batches = (0..100)
        .map(|batch| {
            (0..64)
                .map(|entry| (key(&format!("batch-{batch}-{entry}")), output.clone()))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut batch_index = 0;
    let batch_times = measure(batches.len(), || {
        redb.put_batch(batches[batch_index].clone()).unwrap();
        batch_index += 1;
    });
    report(
        "redb_plain_durable_batch_64_transaction",
        batch_times.clone(),
    );
    let batch_mean_per_entry_ns =
        batch_times.iter().map(Duration::as_nanos).sum::<u128>() / (batch_times.len() as u128 * 64);
    println!(
        "redb_plain_durable_batch_64_amortized mean_us={:.3}",
        batch_mean_per_entry_ns as f64 / 1_000.0
    );
    let encrypted_batches = (0..100)
        .map(|batch| {
            (0..64)
                .map(|entry| {
                    (
                        key(&format!("encrypted-batch-{batch}-{entry}")),
                        output.clone(),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut encrypted_batch_index = 0;
    let encrypted_batch_times = measure(encrypted_batches.len(), || {
        encrypted_redb
            .put_batch(encrypted_batches[encrypted_batch_index].clone())
            .unwrap();
        encrypted_batch_index += 1;
    });
    report(
        "redb_encrypted_durable_batch_64_transaction",
        encrypted_batch_times.clone(),
    );
    let encrypted_batch_mean_per_entry_ns = encrypted_batch_times
        .iter()
        .map(Duration::as_nanos)
        .sum::<u128>()
        / (encrypted_batch_times.len() as u128 * 64);
    println!(
        "redb_encrypted_durable_batch_64_amortized mean_us={:.3}",
        encrypted_batch_mean_per_entry_ns as f64 / 1_000.0
    );

    let write_behind = WriteBehindStore::new(
        redb.clone(),
        WriteBehindConfig {
            queue_capacity: 20_000,
            max_batch_size: 64,
        },
    );
    let enqueue_keys = (0..10_000)
        .map(|index| key(&format!("async-{index}")))
        .collect::<Vec<_>>();
    let mut enqueue_index = 0;
    let enqueue_started = Instant::now();
    let enqueue_times = measure(enqueue_keys.len(), || {
        write_behind
            .put(enqueue_keys[enqueue_index], output.clone())
            .unwrap();
        enqueue_index += 1;
    });
    let flush_started = Instant::now();
    write_behind.flush().unwrap();
    let flush_time = flush_started.elapsed();
    let enqueue_and_flush = enqueue_started.elapsed();
    report("write_behind_plain_enqueue", enqueue_times);
    println!(
        "write_behind_plain_flush total_ms={:.3} enqueue_and_flush_ms={:.3} written={} dropped={}",
        flush_time.as_secs_f64() * 1_000.0,
        enqueue_and_flush.as_secs_f64() * 1_000.0,
        write_behind.stats().snapshot().written,
        write_behind.stats().snapshot().dropped,
    );

    let encrypted_write_behind = WriteBehindStore::new(
        encrypted_redb.clone(),
        WriteBehindConfig {
            queue_capacity: 20_000,
            max_batch_size: 64,
        },
    );
    let encrypted_enqueue_keys = (0..10_000)
        .map(|index| key(&format!("encrypted-async-{index}")))
        .collect::<Vec<_>>();
    let mut encrypted_enqueue_index = 0;
    let encrypted_enqueue_started = Instant::now();
    let encrypted_enqueue_times = measure(encrypted_enqueue_keys.len(), || {
        encrypted_write_behind
            .put(
                encrypted_enqueue_keys[encrypted_enqueue_index],
                output.clone(),
            )
            .unwrap();
        encrypted_enqueue_index += 1;
    });
    let encrypted_flush_started = Instant::now();
    encrypted_write_behind.flush().unwrap();
    let encrypted_flush_time = encrypted_flush_started.elapsed();
    let encrypted_enqueue_and_flush = encrypted_enqueue_started.elapsed();
    report("write_behind_encrypted_enqueue", encrypted_enqueue_times);
    println!(
        "write_behind_encrypted_flush total_ms={:.3} enqueue_and_flush_ms={:.3} written={} dropped={}",
        encrypted_flush_time.as_secs_f64() * 1_000.0,
        encrypted_enqueue_and_flush.as_secs_f64() * 1_000.0,
        encrypted_write_behind.stats().snapshot().written,
        encrypted_write_behind.stats().snapshot().dropped,
    );

    drop(encrypted_write_behind);
    drop(write_behind);
    drop(encrypted_redb);
    drop(redb);
    std::fs::remove_file(encrypted_path).unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
#[ignore = "release-mode hot/persistent similarity scaling benchmark"]
fn similarity_cache_scaling_microbenchmark() {
    const SIZES: &[usize] = &[100, 1_000, 10_000];
    const READS: usize = 500;
    const WRITES: usize = 100;
    const DURABLE_WRITES: usize = 20;

    for &size in SIZES {
        let hot = HistoricalSimilarityCache::new(Arc::new(
            CacheCoordinator::from_config(ExactCacheConfig {
                memory: MemoryCacheConfig {
                    max_entries: size + WRITES,
                    max_bytes: 256 * 1024 * 1024,
                },
                ..ExactCacheConfig::default()
            })
            .unwrap(),
        ));
        for index in 0..size {
            remember_similarity(&hot, index);
        }
        let query = benchmark_embedding(size / 2);
        report(
            &format!("similarity_hot_read_entries_{size}"),
            measure(READS, || {
                black_box(
                    hot.find_best_for_head("benchmark-space", &query, "injection")
                        .unwrap(),
                );
            }),
        );
        let mut next = size;
        report(
            &format!("similarity_hot_write_entries_{size}"),
            measure(WRITES, || {
                remember_similarity(&hot, next);
                next += 1;
            }),
        );

        let path = temp_path();
        let persistent = Arc::new(
            CacheCoordinator::from_config(ExactCacheConfig {
                memory: MemoryCacheConfig {
                    max_entries: 0,
                    max_bytes: 0,
                },
                persistent: Some(PersistentCacheConfig {
                    storage_location: path.clone(),
                    write_mode: CacheWriteMode::WriteThrough,
                    write_behind: WriteBehindConfig::default(),
                    encryption: None,
                }),
                ..ExactCacheConfig::default()
            })
            .unwrap(),
        );
        let cache = HistoricalSimilarityCache::new(Arc::clone(&persistent));
        for index in 0..size {
            remember_similarity(&cache, index);
        }
        report(
            &format!("similarity_persistent_read_entries_{size}"),
            measure(READS, || {
                cache.clear_hot_for_benchmark();
                black_box(
                    cache
                        .find_best_for_head("benchmark-space", &query, "injection")
                        .unwrap(),
                );
            }),
        );
        let mut next = size;
        report(
            &format!("similarity_persistent_durable_write_entries_{size}"),
            measure(DURABLE_WRITES, || {
                remember_similarity(&cache, next);
                next += 1;
            }),
        );
        persistent.flush().unwrap();
        drop(cache);
        drop(persistent);
        std::fs::remove_file(path).unwrap();

        let encrypted_path = temp_path();
        let encrypted_persistent = Arc::new(
            CacheCoordinator::from_config(ExactCacheConfig {
                memory: MemoryCacheConfig {
                    max_entries: 0,
                    max_bytes: 0,
                },
                persistent: Some(PersistentCacheConfig {
                    storage_location: encrypted_path.clone(),
                    write_mode: CacheWriteMode::WriteThrough,
                    write_behind: WriteBehindConfig::default(),
                    encryption: Some(encryption_config()),
                }),
                ..ExactCacheConfig::default()
            })
            .unwrap(),
        );
        let encrypted_cache = HistoricalSimilarityCache::new(Arc::clone(&encrypted_persistent));
        for index in 0..size {
            remember_similarity(&encrypted_cache, index);
        }
        report(
            &format!("similarity_encrypted_persistent_read_entries_{size}"),
            measure(READS, || {
                encrypted_cache.clear_hot_for_benchmark();
                black_box(
                    encrypted_cache
                        .find_best_for_head("benchmark-space", &query, "injection")
                        .unwrap(),
                );
            }),
        );
        let mut next = size;
        report(
            &format!("similarity_encrypted_persistent_durable_write_entries_{size}"),
            measure(DURABLE_WRITES, || {
                remember_similarity(&encrypted_cache, next);
                next += 1;
            }),
        );
        encrypted_persistent.flush().unwrap();
        drop(encrypted_cache);
        drop(encrypted_persistent);
        std::fs::remove_file(encrypted_path).unwrap();

        let async_path = temp_path();
        let async_persistent = Arc::new(
            CacheCoordinator::from_config(ExactCacheConfig {
                memory: MemoryCacheConfig {
                    max_entries: 0,
                    max_bytes: 0,
                },
                persistent: Some(PersistentCacheConfig {
                    storage_location: async_path.clone(),
                    write_mode: CacheWriteMode::Async,
                    write_behind: WriteBehindConfig {
                        queue_capacity: 1_024,
                        max_batch_size: 64,
                    },
                    encryption: None,
                }),
                ..ExactCacheConfig::default()
            })
            .unwrap(),
        );
        let async_cache = HistoricalSimilarityCache::new(Arc::clone(&async_persistent));
        let mut next = size + DURABLE_WRITES;
        report(
            &format!("similarity_persistent_async_write_entries_{size}"),
            measure(WRITES, || {
                remember_similarity(&async_cache, next);
                next += 1;
            }),
        );
        let flush_started = Instant::now();
        async_persistent.flush().unwrap();
        println!(
            "similarity_persistent_async_flush_entries_{size} total_ms={:.3} amortized_us={:.3}",
            flush_started.elapsed().as_secs_f64() * 1_000.0,
            flush_started.elapsed().as_secs_f64() * 1_000_000.0 / WRITES as f64,
        );
        drop(async_cache);
        drop(async_persistent);
        std::fs::remove_file(async_path).unwrap();

        let encrypted_async_path = temp_path();
        let encrypted_async_persistent = Arc::new(
            CacheCoordinator::from_config(ExactCacheConfig {
                memory: MemoryCacheConfig {
                    max_entries: 0,
                    max_bytes: 0,
                },
                persistent: Some(PersistentCacheConfig {
                    storage_location: encrypted_async_path.clone(),
                    write_mode: CacheWriteMode::Async,
                    write_behind: WriteBehindConfig {
                        queue_capacity: 1_024,
                        max_batch_size: 64,
                    },
                    encryption: Some(encryption_config()),
                }),
                ..ExactCacheConfig::default()
            })
            .unwrap(),
        );
        let encrypted_async_cache =
            HistoricalSimilarityCache::new(Arc::clone(&encrypted_async_persistent));
        let mut next = size + DURABLE_WRITES;
        report(
            &format!("similarity_encrypted_persistent_async_write_entries_{size}"),
            measure(WRITES, || {
                remember_similarity(&encrypted_async_cache, next);
                next += 1;
            }),
        );
        let flush_started = Instant::now();
        encrypted_async_persistent.flush().unwrap();
        println!(
            "similarity_encrypted_persistent_async_flush_entries_{size} total_ms={:.3} amortized_us={:.3}",
            flush_started.elapsed().as_secs_f64() * 1_000.0,
            flush_started.elapsed().as_secs_f64() * 1_000_000.0 / WRITES as f64,
        );
        drop(encrypted_async_cache);
        drop(encrypted_async_persistent);
        std::fs::remove_file(encrypted_async_path).unwrap();
    }
}

#[test]
#[ignore = "release-mode hot/persistent exact-store scaling benchmark"]
fn exact_cache_scaling_microbenchmark() {
    const SIZES: &[usize] = &[100, 1_000, 10_000];
    const READS: usize = 1_000;
    const WRITES: usize = 100;
    const DURABLE_WRITES: usize = 20;

    for &size in SIZES {
        let output = representative_output();
        let read_key = key(&format!("exact-read-{size}"));
        let hot = MemoryCacheStore::new(MemoryCacheConfig {
            max_entries: size + WRITES + 1,
            max_bytes: 256 * 1024 * 1024,
        });
        for index in 0..size {
            hot.put(key(&format!("exact-hot-{size}-{index}")), output.clone())
                .unwrap();
        }
        hot.put(read_key, output.clone()).unwrap();
        report(
            &format!("exact_hot_read_entries_{size}"),
            measure(READS, || {
                black_box(hot.get(&read_key, 10).unwrap().unwrap());
            }),
        );
        let mut next = size;
        report(
            &format!("exact_hot_write_entries_{size}"),
            measure(WRITES, || {
                hot.put(
                    key(&format!("exact-hot-write-{size}-{next}")),
                    output.clone(),
                )
                .unwrap();
                next += 1;
            }),
        );

        let path = temp_path();
        let redb = RedbCacheStore::open(&path).unwrap();
        for batch_start in (0..size).step_by(64) {
            let batch_end = (batch_start + 64).min(size);
            redb.put_batch(
                (batch_start..batch_end)
                    .map(|index| (key(&format!("exact-redb-{size}-{index}")), output.clone()))
                    .collect(),
            )
            .unwrap();
        }
        redb.put(read_key, output.clone()).unwrap();
        report(
            &format!("exact_persistent_read_entries_{size}"),
            measure(READS, || {
                black_box(redb.get(&read_key, 10).unwrap().unwrap());
            }),
        );
        let mut next = size;
        report(
            &format!("exact_persistent_durable_write_entries_{size}"),
            measure(DURABLE_WRITES, || {
                redb.put(
                    key(&format!("exact-redb-write-{size}-{next}")),
                    output.clone(),
                )
                .unwrap();
                next += 1;
            }),
        );

        drop(redb);
        std::fs::remove_file(path).unwrap();

        let encrypted_path = temp_path();
        let encrypted_redb =
            RedbCacheStore::open_with_encryption(&encrypted_path, Some(encryption_config()))
                .unwrap();
        for batch_start in (0..size).step_by(64) {
            let batch_end = (batch_start + 64).min(size);
            encrypted_redb
                .put_batch(
                    (batch_start..batch_end)
                        .map(|index| {
                            (
                                key(&format!("exact-encrypted-redb-{size}-{index}")),
                                output.clone(),
                            )
                        })
                        .collect(),
                )
                .unwrap();
        }
        encrypted_redb.put(read_key, output.clone()).unwrap();
        report(
            &format!("exact_encrypted_persistent_read_entries_{size}"),
            measure(READS, || {
                black_box(encrypted_redb.get(&read_key, 10).unwrap().unwrap());
            }),
        );
        let mut next = size;
        report(
            &format!("exact_encrypted_persistent_durable_write_entries_{size}"),
            measure(DURABLE_WRITES, || {
                encrypted_redb
                    .put(
                        key(&format!("exact-encrypted-redb-write-{size}-{next}")),
                        output.clone(),
                    )
                    .unwrap();
                next += 1;
            }),
        );

        drop(encrypted_redb);
        std::fs::remove_file(encrypted_path).unwrap();
    }
}

fn remember_similarity(cache: &HistoricalSimilarityCache, index: usize) {
    cache.remember(
        "benchmark-space",
        &benchmark_embedding(index),
        "benchmark-model-sha",
        vec![decision_output("injection", "attack", 0.99)],
    );
}

fn benchmark_embedding(index: usize) -> Vec<f32> {
    let mut state = (index as u64).wrapping_add(1);
    (0..128)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            ((state >> 40) as i32 - (1 << 23)) as f32 / (1 << 23) as f32
        })
        .collect()
}

fn measure(iterations: usize, mut operation: impl FnMut()) -> Vec<Duration> {
    let mut durations = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        operation();
        durations.push(started.elapsed());
    }
    durations
}

fn report(name: &str, mut durations: Vec<Duration>) {
    durations.sort_unstable();
    let mean_ns = durations.iter().map(Duration::as_nanos).sum::<u128>() / durations.len() as u128;
    println!(
        "{name} p50_us={:.3} p95_us={:.3} p99_us={:.3} mean_us={:.3}",
        percentile(&durations, 50).as_nanos() as f64 / 1_000.0,
        percentile(&durations, 95).as_nanos() as f64 / 1_000.0,
        percentile(&durations, 99).as_nanos() as f64 / 1_000.0,
        mean_ns as f64 / 1_000.0,
    );
}

fn percentile(durations: &[Duration], percentile: usize) -> Duration {
    durations[(durations.len() - 1) * percentile / 100]
}

fn representative_output() -> CachedModelOutput {
    let heads = [
        ("injection", 1),
        ("sensitive_document", 7),
        ("tool_class", 14),
        ("tool_action", 6),
        ("tool_tags", 3),
        ("routing", 5),
        ("threat", 7),
    ]
    .into_iter()
    .map(|(head, logits)| CachedHeadOutput {
        head: head.to_string(),
        logits: (0..logits).map(|index| index as f32 / 10.0).collect(),
    })
    .collect();
    CachedModelOutput {
        schema_version: 1,
        heads,
        created_at_unix_ms: 0,
        expires_at_unix_ms: u64::MAX,
    }
}

fn key(value: &str) -> CacheKey {
    CacheKey::for_chunk(
        CacheNamespace::from_components(1, &[b"latency-benchmark"]),
        value.as_bytes(),
    )
}

fn temp_path() -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("patronus-cache-benchmark-{unique}.redb"))
}

fn encryption_config() -> CacheEncryptionConfig {
    CacheEncryptionConfig::from_key([42; 32])
}
