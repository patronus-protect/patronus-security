// SPDX-License-Identifier: GPL-3.0-only
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    CacheError, CacheKey, CacheWriteMode, CachedModelOutput, ExactCacheConfig, ExactCacheStore,
    MemoryCacheConfig, MemoryCacheStore, RedbCacheStore, SimilarityStoreRecord, WriteBehindStats,
    WriteBehindStatsSnapshot, WriteBehindStore,
};

pub(crate) trait Clock: Send + Sync {
    fn now_unix_ms(&self) -> u64;
}

pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheSource {
    Memory,
    Persistent,
    Computed,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CacheLookup {
    pub(crate) output: CachedModelOutput,
    pub(crate) source: CacheSource,
}

pub(crate) struct CacheCoordinator {
    memory: Arc<dyn ExactCacheStore>,
    persistent: Mutex<Option<Arc<dyn ExactCacheStore>>>,
    persistent_config: Option<super::PersistentCacheConfig>,
    storage_location: Option<PathBuf>,
    write_stats: Mutex<Option<Arc<WriteBehindStats>>>,
    clock: Arc<dyn Clock>,
    entry_ttl_ms: u64,
    memory_config: MemoryCacheConfig,
    in_flight: Mutex<HashSet<CacheKey>>,
    completed: Condvar,
}

impl CacheCoordinator {
    pub(crate) fn new(
        memory: Arc<dyn ExactCacheStore>,
        persistent: Option<Arc<dyn ExactCacheStore>>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            memory,
            persistent: Mutex::new(persistent),
            persistent_config: None,
            storage_location: None,
            write_stats: Mutex::new(None),
            clock,
            entry_ttl_ms: ExactCacheConfig::default().entry_ttl.as_millis() as u64,
            memory_config: MemoryCacheConfig::default(),
            in_flight: Mutex::new(HashSet::new()),
            completed: Condvar::new(),
        }
    }

    pub(crate) fn from_config(config: ExactCacheConfig) -> Result<Self, CacheError> {
        Self::from_config_with_clock(config, Arc::new(SystemClock))
    }

    fn from_config_with_clock(
        config: ExactCacheConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, CacheError> {
        let memory_config = config.memory;
        let memory: Arc<dyn ExactCacheStore> = Arc::new(MemoryCacheStore::new(memory_config));
        let entry_ttl_ms = config.entry_ttl.as_millis().min(u128::from(u64::MAX)) as u64;
        let Some(persistent_config) = config.persistent else {
            let mut coordinator = Self::new(memory, None, clock);
            coordinator.entry_ttl_ms = entry_ttl_ms;
            coordinator.memory_config = memory_config;
            return Ok(coordinator);
        };

        let storage_location = persistent_config.storage_location.clone();
        let (persistent, write_stats) = open_persistent_store(&persistent_config)?;

        Ok(Self {
            memory,
            persistent: Mutex::new(Some(persistent)),
            persistent_config: Some(persistent_config),
            storage_location: Some(storage_location),
            write_stats: Mutex::new(write_stats),
            clock,
            entry_ttl_ms,
            memory_config,
            in_flight: Mutex::new(HashSet::new()),
            completed: Condvar::new(),
        })
    }

    pub(crate) fn storage_location(&self) -> Option<&Path> {
        self.storage_location.as_deref()
    }

    pub(crate) fn write_stats(&self) -> Option<WriteBehindStatsSnapshot> {
        self.write_stats
            .lock()
            .expect("cache write stats mutex poisoned")
            .as_ref()
            .map(|stats| stats.snapshot())
    }

    pub(crate) fn flush(&self) -> Result<(), CacheError> {
        match self.persistent_store()? {
            Some(persistent) => persistent.flush(),
            None => Ok(()),
        }
    }

    pub(crate) fn reset_persistent_connections(&self) -> Result<(), CacheError> {
        let persistent = self
            .persistent
            .lock()
            .map_err(|_| CacheError::Storage("cache connection mutex poisoned".to_string()))?
            .take();
        self.write_stats
            .lock()
            .map_err(|_| CacheError::Storage("cache write stats mutex poisoned".to_string()))?
            .take();
        if let Some(persistent) = persistent {
            persistent.flush()?;
        }
        Ok(())
    }

    pub(crate) fn reset_cache(&self, until_unix_ms: u64) -> Result<usize, CacheError> {
        let mut removed = self.memory.remove_created_before(until_unix_ms)?;
        if let Some(persistent) = self.persistent_store()? {
            removed += persistent.remove_created_before(until_unix_ms)?;
        }
        Ok(removed)
    }

    pub(crate) fn memory_config(&self) -> MemoryCacheConfig {
        self.memory_config
    }

    pub(crate) fn similarity_candidates(
        &self,
        bucket_keys: &[Vec<u8>],
        limit: usize,
    ) -> Vec<SimilarityStoreRecord> {
        self.persistent_store()
            .ok()
            .flatten()
            .and_then(|store| {
                store
                    .similarity_candidates(bucket_keys, self.clock.now_unix_ms(), limit)
                    .ok()
            })
            .unwrap_or_default()
    }

    pub(crate) fn put_similarity(
        &self,
        mut record: SimilarityStoreRecord,
    ) -> Result<(), CacheError> {
        let now = self.clock.now_unix_ms();
        record.created_at_unix_ms = now;
        record.expires_at_unix_ms = now.saturating_add(self.entry_ttl_ms);
        match self.persistent_store()? {
            Some(store) => store.put_similarity(record),
            None => Ok(()),
        }
    }

    pub(crate) fn get_or_compute<E>(
        &self,
        key: CacheKey,
        compute: impl FnOnce() -> Result<CachedModelOutput, E>,
    ) -> Result<CacheLookup, E> {
        let mut compute = Some(compute);
        loop {
            if let Some(hit) = self.lookup(&key) {
                return Ok(hit);
            }

            let mut in_flight = self.in_flight.lock().expect("cache flight mutex poisoned");
            if in_flight.insert(key) {
                drop(in_flight);
                break;
            }
            drop(
                self.completed
                    .wait(in_flight)
                    .expect("cache flight mutex poisoned"),
            );
        }

        let _flight = FlightGuard {
            coordinator: self,
            key,
        };

        // Close the race between the first lookup and claiming the flight.
        if let Some(hit) = self.lookup(&key) {
            return Ok(hit);
        }

        let output = compute.take().expect("compute closure already used")()?;
        let _ = self.memory.put(key, output.clone());
        if let Ok(Some(persistent)) = self.persistent_store() {
            let _ = persistent.put(key, output.clone());
        }
        Ok(CacheLookup {
            output,
            source: CacheSource::Computed,
        })
    }

    pub(crate) fn get_or_compute_heads<E>(
        &self,
        key: CacheKey,
        compute: impl FnOnce() -> Result<Vec<super::CachedHeadOutput>, E>,
    ) -> Result<CacheLookup, E> {
        self.get_or_compute(key, || {
            let heads = compute()?;
            let created_at_unix_ms = self.clock.now_unix_ms();
            Ok(CachedModelOutput {
                schema_version: 1,
                heads,
                created_at_unix_ms,
                expires_at_unix_ms: created_at_unix_ms.saturating_add(self.entry_ttl_ms),
            })
        })
    }

    pub(crate) fn lookup_exact(&self, key: &CacheKey) -> Option<CacheLookup> {
        self.lookup(key)
    }

    pub(crate) fn put_heads(
        &self,
        key: CacheKey,
        heads: Vec<super::CachedHeadOutput>,
    ) -> Result<(), CacheError> {
        let created_at_unix_ms = self.clock.now_unix_ms();
        let output = CachedModelOutput {
            schema_version: 1,
            heads,
            created_at_unix_ms,
            expires_at_unix_ms: created_at_unix_ms.saturating_add(self.entry_ttl_ms),
        };
        self.memory.put(key, output.clone())?;
        if let Some(persistent) = self.persistent_store()? {
            persistent.put(key, output)?;
        }
        Ok(())
    }

    fn lookup(&self, key: &CacheKey) -> Option<CacheLookup> {
        let now = self.clock.now_unix_ms();
        if let Ok(Some(output)) = self.memory.get(key, now) {
            return Some(CacheLookup {
                output,
                source: CacheSource::Memory,
            });
        }

        let output = self.persistent_store().ok()??.get(key, now).ok()??;
        let _ = self.memory.put(*key, output.clone());
        Some(CacheLookup {
            output,
            source: CacheSource::Persistent,
        })
    }

    fn persistent_store(&self) -> Result<Option<Arc<dyn ExactCacheStore>>, CacheError> {
        let mut persistent = self
            .persistent
            .lock()
            .map_err(|_| CacheError::Storage("cache connection mutex poisoned".to_string()))?;
        if persistent.is_none() {
            if let Some(config) = &self.persistent_config {
                let (store, stats) = open_persistent_store(config)?;
                *persistent = Some(store);
                *self.write_stats.lock().map_err(|_| {
                    CacheError::Storage("cache write stats mutex poisoned".to_string())
                })? = stats;
            }
        }
        Ok(persistent.clone())
    }
}

fn open_persistent_store(
    config: &super::PersistentCacheConfig,
) -> Result<(Arc<dyn ExactCacheStore>, Option<Arc<WriteBehindStats>>), CacheError> {
    let redb: Arc<dyn ExactCacheStore> =
        RedbCacheStore::open_shared(&config.storage_location, config.encryption.clone())?;
    Ok(match config.write_mode {
        CacheWriteMode::WriteThrough => (redb, None),
        CacheWriteMode::Async => {
            let store = Arc::new(WriteBehindStore::new(redb, config.write_behind));
            let stats = Some(store.stats());
            (store, stats)
        }
    })
}

struct FlightGuard<'a> {
    coordinator: &'a CacheCoordinator,
    key: CacheKey,
}

impl Drop for FlightGuard<'_> {
    fn drop(&mut self) {
        let mut in_flight = self
            .coordinator
            .in_flight
            .lock()
            .expect("cache flight mutex poisoned");
        in_flight.remove(&self.key);
        self.coordinator.completed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    use super::*;
    use crate::cache::{
        CacheNamespace, CachedHeadOutput, MemoryCacheConfig, PersistentCacheConfig,
        WriteBehindConfig,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestClock(AtomicU64);

    impl Clock for TestClock {
        fn now_unix_ms(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
    }

    fn key() -> CacheKey {
        key_for(b"chunk")
    }

    fn key_for(value: &[u8]) -> CacheKey {
        CacheKey::for_chunk(CacheNamespace::from_components(1, &[b"model"]), value)
    }

    fn output() -> CachedModelOutput {
        CachedModelOutput {
            schema_version: 1,
            heads: vec![CachedHeadOutput {
                head: "head".to_string(),
                logits: vec![0.2, 0.8],
            }],
            created_at_unix_ms: 10,
            expires_at_unix_ms: 100,
        }
    }

    fn coordinator(
        memory: Arc<dyn ExactCacheStore>,
        persistent: Option<Arc<dyn ExactCacheStore>>,
    ) -> CacheCoordinator {
        CacheCoordinator::new(memory, persistent, Arc::new(TestClock(AtomicU64::new(10))))
    }

    fn temp_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("patronus-config-{name}-{unique}.redb"))
    }

    fn persistent_config(path: PathBuf) -> ExactCacheConfig {
        ExactCacheConfig {
            memory: MemoryCacheConfig::default(),
            persistent: Some(PersistentCacheConfig {
                storage_location: path,
                write_mode: CacheWriteMode::Async,
                write_behind: WriteBehindConfig::default(),
                encryption: None,
            }),
            entry_ttl: Duration::from_secs(60),
        }
    }

    #[test]
    fn default_config_does_not_create_persistent_storage() {
        let cache = CacheCoordinator::from_config_with_clock(
            ExactCacheConfig::default(),
            Arc::new(TestClock(AtomicU64::new(10))),
        )
        .unwrap();

        assert!(cache.storage_location().is_none());
        assert!(cache.write_stats().is_none());
    }

    #[test]
    fn configured_storage_location_survives_coordinator_reopen() {
        let path = temp_path("reopen");
        let config = persistent_config(path.clone());
        {
            let cache = CacheCoordinator::from_config_with_clock(
                config.clone(),
                Arc::new(TestClock(AtomicU64::new(10))),
            )
            .unwrap();
            let lookup = cache
                .get_or_compute(key(), || -> Result<_, ()> { Ok(output()) })
                .unwrap();
            assert_eq!(lookup.source, CacheSource::Computed);
            assert_eq!(cache.storage_location(), Some(path.as_path()));
            cache.flush().unwrap();
            assert_eq!(cache.write_stats().unwrap().written, 1);
        }
        let reopened = CacheCoordinator::from_config_with_clock(
            config,
            Arc::new(TestClock(AtomicU64::new(10))),
        )
        .unwrap();
        let lookup = reopened
            .get_or_compute(key(), || -> Result<_, ()> { panic!("must not compute") })
            .unwrap();

        assert_eq!(lookup.source, CacheSource::Persistent);
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn shared_storage_location_allows_concurrent_coordinators() {
        let path = temp_path("shared-open");
        let config = persistent_config(path.clone());

        let first = CacheCoordinator::from_config_with_clock(
            config.clone(),
            Arc::new(TestClock(AtomicU64::new(10))),
        )
        .unwrap();
        let second = CacheCoordinator::from_config_with_clock(
            config,
            Arc::new(TestClock(AtomicU64::new(10))),
        )
        .unwrap();

        first
            .get_or_compute(key(), || -> Result<_, ()> { Ok(output()) })
            .unwrap();
        first.flush().unwrap();
        assert_eq!(
            second
                .get_or_compute(key(), || -> Result<_, ()> { panic!("must not compute") })
                .unwrap()
                .source,
            CacheSource::Persistent
        );

        drop(second);
        drop(first);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn reset_persistent_connections_preserves_storage_and_reopens() {
        let path = temp_path("reset-connections");
        let config = persistent_config(path.clone());
        let cache = CacheCoordinator::from_config_with_clock(
            config,
            Arc::new(TestClock(AtomicU64::new(10))),
        )
        .unwrap();
        cache
            .get_or_compute(key(), || -> Result<_, ()> { Ok(output()) })
            .unwrap();
        cache.flush().unwrap();

        cache.reset_persistent_connections().unwrap();

        assert!(path.exists());
        cache.flush().unwrap();
        drop(cache);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn reset_cache_removes_records_created_before_cutoff() {
        let path = temp_path("reset-cache-cutoff");
        let config = persistent_config(path.clone());
        let clock = Arc::new(TestClock(AtomicU64::new(10)));
        let cache = CacheCoordinator::from_config_with_clock(config, clock.clone()).unwrap();
        let old_key = key_for(b"old");
        let new_key = key_for(b"new");

        cache
            .get_or_compute_heads(old_key, || -> Result<_, ()> { Ok(output().heads) })
            .unwrap();
        clock.0.store(20, Ordering::Relaxed);
        cache
            .get_or_compute_heads(new_key, || -> Result<_, ()> { Ok(output().heads) })
            .unwrap();
        cache.flush().unwrap();

        assert!(cache.reset_cache(20).unwrap() >= 1);

        assert_eq!(
            cache
                .get_or_compute_heads(old_key, || -> Result<_, ()> { Ok(output().heads) })
                .unwrap()
                .source,
            CacheSource::Computed
        );
        assert_ne!(
            cache
                .get_or_compute_heads(new_key, || -> Result<_, ()> { panic!("must not compute") })
                .unwrap()
                .source,
            CacheSource::Computed
        );
        drop(cache);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn persistent_hit_repopulates_memory() {
        let memory = Arc::new(MemoryCacheStore::new(MemoryCacheConfig::default()));
        let persistent = Arc::new(MemoryCacheStore::new(MemoryCacheConfig::default()));
        persistent.put(key(), output()).unwrap();
        let cache = coordinator(memory, Some(persistent));

        let first = cache
            .get_or_compute(key(), || -> Result<_, ()> { panic!("must not compute") })
            .unwrap();
        let second = cache
            .get_or_compute(key(), || -> Result<_, ()> { panic!("must not compute") })
            .unwrap();

        assert_eq!(first.source, CacheSource::Persistent);
        assert_eq!(second.source, CacheSource::Memory);
    }

    #[test]
    fn store_errors_are_treated_as_cache_misses() {
        struct FailingStore;

        impl ExactCacheStore for FailingStore {
            fn get(
                &self,
                _key: &CacheKey,
                _now_unix_ms: u64,
            ) -> Result<Option<CachedModelOutput>, CacheError> {
                Err(CacheError::Storage("read failed".to_string()))
            }

            fn put(&self, _key: CacheKey, _value: CachedModelOutput) -> Result<(), CacheError> {
                Err(CacheError::Storage("write failed".to_string()))
            }

            fn remove_expired(&self, _now_unix_ms: u64) -> Result<usize, CacheError> {
                Err(CacheError::Storage("cleanup failed".to_string()))
            }

            fn remove_created_before(&self, _until_unix_ms: u64) -> Result<usize, CacheError> {
                Err(CacheError::Storage("cleanup failed".to_string()))
            }
        }

        let cache = coordinator(Arc::new(FailingStore), None);
        let lookup = cache
            .get_or_compute(key(), || -> Result<_, ()> { Ok(output()) })
            .unwrap();

        assert_eq!(lookup.source, CacheSource::Computed);
    }

    #[test]
    fn compute_error_releases_singleflight_slot() {
        let cache = coordinator(
            Arc::new(MemoryCacheStore::new(MemoryCacheConfig::default())),
            None,
        );

        assert!(cache
            .get_or_compute(key(), || -> Result<_, &'static str> {
                Err("inference failed")
            })
            .is_err());
        let retry = cache
            .get_or_compute(key(), || -> Result<_, &'static str> { Ok(output()) })
            .unwrap();

        assert_eq!(retry.source, CacheSource::Computed);
    }

    #[test]
    fn concurrent_misses_compute_once() {
        let cache = Arc::new(coordinator(
            Arc::new(MemoryCacheStore::new(MemoryCacheConfig::default())),
            None,
        ));
        let computes = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();

        for _ in 0..8 {
            let cache = Arc::clone(&cache);
            let computes = Arc::clone(&computes);
            workers.push(thread::spawn(move || {
                cache
                    .get_or_compute(key(), || -> Result<_, ()> {
                        computes.fetch_add(1, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(20));
                        Ok(output())
                    })
                    .unwrap()
            }));
        }

        let lookups = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(computes.load(Ordering::SeqCst), 1);
        assert_eq!(
            lookups
                .iter()
                .filter(|lookup| lookup.source == CacheSource::Computed)
                .count(),
            1
        );
    }
}
