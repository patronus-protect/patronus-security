// SPDX-License-Identifier: GPL-3.0-only
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use super::{CacheError, CacheKey, CachedModelOutput, ExactCacheStore, SimilarityStoreRecord};

#[derive(Debug, Clone, Copy)]
pub struct WriteBehindConfig {
    pub queue_capacity: usize,
    pub max_batch_size: usize,
}

impl Default for WriteBehindConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 1_024,
            max_batch_size: 64,
        }
    }
}

#[derive(Default)]
pub(crate) struct WriteBehindStats {
    queued: AtomicU64,
    written: AtomicU64,
    dropped: AtomicU64,
    write_errors: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WriteBehindStatsSnapshot {
    pub(crate) queued: u64,
    pub(crate) written: u64,
    pub(crate) dropped: u64,
    pub(crate) write_errors: u64,
}

impl WriteBehindStats {
    pub(crate) fn snapshot(&self) -> WriteBehindStatsSnapshot {
        WriteBehindStatsSnapshot {
            queued: self.queued.load(Ordering::Relaxed),
            written: self.written.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            write_errors: self.write_errors.load(Ordering::Relaxed),
        }
    }
}

enum Command {
    Put(CacheKey, CachedModelOutput),
    PutSimilarity(SimilarityStoreRecord),
    Flush(mpsc::Sender<Result<(), CacheError>>),
    Shutdown,
}

pub(crate) struct WriteBehindStore {
    inner: Arc<dyn ExactCacheStore>,
    sender: SyncSender<Command>,
    worker: Mutex<Option<JoinHandle<()>>>,
    stats: Arc<WriteBehindStats>,
}

impl WriteBehindStore {
    pub(crate) fn new(inner: Arc<dyn ExactCacheStore>, config: WriteBehindConfig) -> Self {
        let (sender, receiver) = mpsc::sync_channel(config.queue_capacity.max(1));
        let stats = Arc::new(WriteBehindStats::default());
        let worker_inner = Arc::clone(&inner);
        let worker_stats = Arc::clone(&stats);
        let max_batch_size = config.max_batch_size.max(1);
        let worker = thread::Builder::new()
            .name("patronus-cache-writer".to_string())
            .spawn(move || {
                writer_loop(worker_inner, receiver, worker_stats, max_batch_size);
            })
            .expect("failed to start cache writer thread");
        Self {
            inner,
            sender,
            worker: Mutex::new(Some(worker)),
            stats,
        }
    }

    pub(crate) fn stats(&self) -> Arc<WriteBehindStats> {
        Arc::clone(&self.stats)
    }
}

impl ExactCacheStore for WriteBehindStore {
    fn get(
        &self,
        key: &CacheKey,
        now_unix_ms: u64,
    ) -> Result<Option<CachedModelOutput>, CacheError> {
        self.inner.get(key, now_unix_ms)
    }

    fn put(&self, key: CacheKey, value: CachedModelOutput) -> Result<(), CacheError> {
        match self.sender.try_send(Command::Put(key, value)) {
            Ok(()) => {
                self.stats.queued.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(TrySendError::Full(_)) => {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(TrySendError::Disconnected(_)) => Err(CacheError::Storage(
                "cache writer thread is not running".to_string(),
            )),
        }
    }

    fn put_batch(&self, entries: Vec<(CacheKey, CachedModelOutput)>) -> Result<(), CacheError> {
        for (key, value) in entries {
            self.put(key, value)?;
        }
        Ok(())
    }

    fn remove_expired(&self, now_unix_ms: u64) -> Result<usize, CacheError> {
        self.flush()?;
        self.inner.remove_expired(now_unix_ms)
    }

    fn remove_created_before(&self, until_unix_ms: u64) -> Result<usize, CacheError> {
        self.flush()?;
        self.inner.remove_created_before(until_unix_ms)
    }

    fn similarity_candidates(
        &self,
        bucket_keys: &[Vec<u8>],
        now_unix_ms: u64,
        limit: usize,
    ) -> Result<Vec<SimilarityStoreRecord>, CacheError> {
        self.inner
            .similarity_candidates(bucket_keys, now_unix_ms, limit)
    }

    fn put_similarity(&self, record: SimilarityStoreRecord) -> Result<(), CacheError> {
        match self.sender.try_send(Command::PutSimilarity(record)) {
            Ok(()) => {
                self.stats.queued.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(TrySendError::Full(_)) => {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(TrySendError::Disconnected(_)) => Err(CacheError::Storage(
                "cache writer thread is not running".to_string(),
            )),
        }
    }

    fn flush(&self) -> Result<(), CacheError> {
        let (sender, receiver) = mpsc::channel();
        self.sender
            .send(Command::Flush(sender))
            .map_err(|_| CacheError::Storage("cache writer thread is not running".to_string()))?;
        receiver.recv().map_err(|_| {
            CacheError::Storage("cache writer thread stopped during flush".to_string())
        })?
    }
}

impl Drop for WriteBehindStore {
    fn drop(&mut self) {
        let _ = self.sender.send(Command::Shutdown);
        if let Some(worker) = self
            .worker
            .lock()
            .expect("cache writer mutex poisoned")
            .take()
        {
            let _ = worker.join();
        }
    }
}

fn writer_loop(
    inner: Arc<dyn ExactCacheStore>,
    receiver: Receiver<Command>,
    stats: Arc<WriteBehindStats>,
    max_batch_size: usize,
) {
    let mut pending_error = None;
    while let Ok(command) = receiver.recv() {
        match command {
            Command::Put(key, value) => {
                let mut batch = vec![(key, value)];
                let mut control = None;
                while batch.len() < max_batch_size {
                    match receiver.try_recv() {
                        Ok(Command::Put(key, value)) => batch.push((key, value)),
                        Ok(command) => {
                            control = Some(command);
                            break;
                        }
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => {
                            control = Some(Command::Shutdown);
                            break;
                        }
                    }
                }
                let batch_len = batch.len() as u64;
                match inner.put_batch(batch) {
                    Ok(()) => {
                        stats.written.fetch_add(batch_len, Ordering::Relaxed);
                    }
                    Err(error) => {
                        stats.write_errors.fetch_add(batch_len, Ordering::Relaxed);
                        pending_error = Some(error.to_string());
                    }
                }
                if process_control(control, &inner, &stats, &mut pending_error) {
                    break;
                }
            }
            Command::PutSimilarity(record) => {
                let mut batch = vec![record];
                let mut control = None;
                while batch.len() < max_batch_size {
                    match receiver.try_recv() {
                        Ok(Command::PutSimilarity(record)) => batch.push(record),
                        Ok(command) => {
                            control = Some(command);
                            break;
                        }
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => {
                            control = Some(Command::Shutdown);
                            break;
                        }
                    }
                }
                let batch_len = batch.len() as u64;
                match inner.put_similarity_batch(batch) {
                    Ok(()) => {
                        stats.written.fetch_add(batch_len, Ordering::Relaxed);
                    }
                    Err(error) => {
                        stats.write_errors.fetch_add(batch_len, Ordering::Relaxed);
                        pending_error = Some(error.to_string());
                    }
                }
                if process_control(control, &inner, &stats, &mut pending_error) {
                    break;
                }
            }
            command => {
                if process_control(Some(command), &inner, &stats, &mut pending_error) {
                    break;
                }
            }
        }
    }
}

fn process_control(
    command: Option<Command>,
    inner: &Arc<dyn ExactCacheStore>,
    stats: &Arc<WriteBehindStats>,
    pending_error: &mut Option<String>,
) -> bool {
    match command {
        Some(Command::Flush(sender)) => {
            let result = match pending_error.take() {
                Some(error) => Err(CacheError::Storage(error)),
                None => inner.flush(),
            };
            let _ = sender.send(result);
            false
        }
        Some(Command::Shutdown) => {
            let _ = inner.flush();
            true
        }
        Some(Command::Put(key, value)) => {
            match inner.put(key, value) {
                Ok(()) => {
                    stats.written.fetch_add(1, Ordering::Relaxed);
                }
                Err(error) => {
                    stats.write_errors.fetch_add(1, Ordering::Relaxed);
                    *pending_error = Some(error.to_string());
                }
            }
            false
        }
        Some(Command::PutSimilarity(record)) => {
            match inner.put_similarity(record) {
                Ok(()) => {
                    stats.written.fetch_add(1, Ordering::Relaxed);
                }
                Err(error) => {
                    stats.write_errors.fetch_add(1, Ordering::Relaxed);
                    *pending_error = Some(error.to_string());
                }
            }
            false
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::cache::{
        CacheNamespace, CachedHeadOutput, MemoryCacheConfig, MemoryCacheStore, RedbCacheStore,
    };

    fn key(value: &str) -> CacheKey {
        CacheKey::for_chunk(
            CacheNamespace::from_components(1, &[b"write-behind"]),
            value.as_bytes(),
        )
    }

    fn output() -> CachedModelOutput {
        CachedModelOutput {
            schema_version: 1,
            heads: vec![CachedHeadOutput {
                head: "head".to_string(),
                logits: vec![0.1, 0.9],
            }],
            created_at_unix_ms: 10,
            expires_at_unix_ms: 100,
        }
    }

    #[test]
    fn flush_makes_queued_redb_writes_visible_and_durable() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("patronus-write-behind-{unique}.redb"));
        {
            let redb = Arc::new(RedbCacheStore::open(&path).unwrap());
            let store = WriteBehindStore::new(redb, WriteBehindConfig::default());
            store.put(key("chunk"), output()).unwrap();
            store.flush().unwrap();
            assert_eq!(store.stats().snapshot().written, 1);
        }
        let reopened = RedbCacheStore::open(&path).unwrap();
        assert!(reopened.get(&key("chunk"), 10).unwrap().is_some());
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn writer_batches_adjacent_entries() {
        struct BatchCountingStore {
            memory: MemoryCacheStore,
            largest_batch: AtomicUsize,
            calls: AtomicUsize,
            first_started: Arc<(Mutex<bool>, Condvar)>,
            release_first: Arc<(Mutex<bool>, Condvar)>,
        }

        impl ExactCacheStore for BatchCountingStore {
            fn get(
                &self,
                key: &CacheKey,
                now_unix_ms: u64,
            ) -> Result<Option<CachedModelOutput>, CacheError> {
                self.memory.get(key, now_unix_ms)
            }

            fn put(&self, key: CacheKey, value: CachedModelOutput) -> Result<(), CacheError> {
                self.memory.put(key, value)
            }

            fn put_batch(
                &self,
                entries: Vec<(CacheKey, CachedModelOutput)>,
            ) -> Result<(), CacheError> {
                if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
                    let (started, started_cv) = &*self.first_started;
                    *started.lock().unwrap() = true;
                    started_cv.notify_one();
                    let (release, release_cv) = &*self.release_first;
                    let guard = release.lock().unwrap();
                    drop(release_cv.wait_while(guard, |released| !*released).unwrap());
                }
                self.largest_batch
                    .fetch_max(entries.len(), Ordering::Relaxed);
                self.memory.put_batch(entries)
            }

            fn remove_expired(&self, now_unix_ms: u64) -> Result<usize, CacheError> {
                self.memory.remove_expired(now_unix_ms)
            }

            fn remove_created_before(&self, until_unix_ms: u64) -> Result<usize, CacheError> {
                self.memory.remove_created_before(until_unix_ms)
            }
        }

        let first_started = Arc::new((Mutex::new(false), Condvar::new()));
        let release_first = Arc::new((Mutex::new(false), Condvar::new()));
        let inner = Arc::new(BatchCountingStore {
            memory: MemoryCacheStore::new(MemoryCacheConfig::default()),
            largest_batch: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
            first_started: Arc::clone(&first_started),
            release_first: Arc::clone(&release_first),
        });
        let store = WriteBehindStore::new(
            inner.clone(),
            WriteBehindConfig {
                queue_capacity: 16,
                max_batch_size: 16,
            },
        );
        store.put(key("0"), output()).unwrap();
        let (started, started_cv) = &*first_started;
        let guard = started.lock().unwrap();
        drop(started_cv.wait_while(guard, |started| !*started).unwrap());
        for index in 1..8 {
            store.put(key(&index.to_string()), output()).unwrap();
        }
        let (release, release_cv) = &*release_first;
        *release.lock().unwrap() = true;
        release_cv.notify_one();
        store.flush().unwrap();

        assert_eq!(store.stats().snapshot().written, 8);
        assert!(inner.largest_batch.load(Ordering::Relaxed) > 1);
    }

    #[test]
    fn full_queue_drops_writes_without_blocking() {
        struct BlockingStore {
            started: Arc<(Mutex<bool>, Condvar)>,
            release: Arc<(Mutex<bool>, Condvar)>,
        }

        impl ExactCacheStore for BlockingStore {
            fn get(
                &self,
                _key: &CacheKey,
                _now_unix_ms: u64,
            ) -> Result<Option<CachedModelOutput>, CacheError> {
                Ok(None)
            }

            fn put(&self, _key: CacheKey, _value: CachedModelOutput) -> Result<(), CacheError> {
                unreachable!()
            }

            fn put_batch(
                &self,
                _entries: Vec<(CacheKey, CachedModelOutput)>,
            ) -> Result<(), CacheError> {
                let (started, started_cv) = &*self.started;
                *started.lock().unwrap() = true;
                started_cv.notify_one();
                let (release, release_cv) = &*self.release;
                let guard = release.lock().unwrap();
                drop(release_cv.wait_while(guard, |released| !*released).unwrap());
                Ok(())
            }

            fn remove_expired(&self, _now_unix_ms: u64) -> Result<usize, CacheError> {
                Ok(0)
            }

            fn remove_created_before(&self, _until_unix_ms: u64) -> Result<usize, CacheError> {
                Ok(0)
            }
        }

        let started = Arc::new((Mutex::new(false), Condvar::new()));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let inner = Arc::new(BlockingStore {
            started: Arc::clone(&started),
            release: Arc::clone(&release),
        });
        let store = WriteBehindStore::new(
            inner,
            WriteBehindConfig {
                queue_capacity: 1,
                max_batch_size: 1,
            },
        );
        store.put(key("first"), output()).unwrap();
        let (started_lock, started_cv) = &*started;
        let guard = started_lock.lock().unwrap();
        drop(started_cv.wait_while(guard, |started| !*started).unwrap());

        store.put(key("queued"), output()).unwrap();
        store.put(key("dropped"), output()).unwrap();
        assert_eq!(store.stats().snapshot().dropped, 1);

        let (release_lock, release_cv) = &*release;
        *release_lock.lock().unwrap() = true;
        release_cv.notify_one();
        store.flush().unwrap();
        assert_eq!(store.stats().snapshot().written, 2);
    }

    #[test]
    fn flush_reports_background_write_errors() {
        struct FailingStore;

        impl ExactCacheStore for FailingStore {
            fn get(
                &self,
                _key: &CacheKey,
                _now_unix_ms: u64,
            ) -> Result<Option<CachedModelOutput>, CacheError> {
                Ok(None)
            }

            fn put(&self, _key: CacheKey, _value: CachedModelOutput) -> Result<(), CacheError> {
                Err(CacheError::Storage("write failed".to_string()))
            }

            fn remove_expired(&self, _now_unix_ms: u64) -> Result<usize, CacheError> {
                Ok(0)
            }

            fn remove_created_before(&self, _until_unix_ms: u64) -> Result<usize, CacheError> {
                Ok(0)
            }
        }

        let store = WriteBehindStore::new(Arc::new(FailingStore), WriteBehindConfig::default());
        store.put(key("chunk"), output()).unwrap();

        assert!(store.flush().is_err());
        assert_eq!(store.stats().snapshot().write_errors, 1);
    }
}
