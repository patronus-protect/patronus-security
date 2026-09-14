// SPDX-License-Identifier: GPL-3.0-only
use std::collections::HashMap;
use std::sync::Mutex;

use super::{CacheError, CacheKey, CachedModelOutput, ExactCacheStore};

#[derive(Debug, Clone, Copy)]
pub struct MemoryCacheConfig {
    pub max_entries: usize,
    pub max_bytes: usize,
}

impl Default for MemoryCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_bytes: 128 * 1024 * 1024,
        }
    }
}

struct Entry {
    output: CachedModelOutput,
    previous: Option<CacheKey>,
    next: Option<CacheKey>,
    estimated_bytes: usize,
}

#[derive(Default)]
struct State {
    entries: HashMap<CacheKey, Entry>,
    used_bytes: usize,
    oldest: Option<CacheKey>,
    newest: Option<CacheKey>,
}

impl State {
    fn unlink(&mut self, key: CacheKey) {
        let entry = &self.entries[&key];
        let (previous, next) = (entry.previous, entry.next);
        if let Some(previous) = previous {
            self.entries.get_mut(&previous).unwrap().next = next;
        } else {
            self.oldest = next;
        }
        if let Some(next) = next {
            self.entries.get_mut(&next).unwrap().previous = previous;
        } else {
            self.newest = previous;
        }
    }

    fn touch(&mut self, key: CacheKey) {
        if self.newest == Some(key) {
            return;
        }
        self.unlink(key);
        self.append(key);
    }

    fn append(&mut self, key: CacheKey) {
        if let Some(newest) = self.newest {
            self.entries.get_mut(&newest).unwrap().next = Some(key);
        } else {
            self.oldest = Some(key);
        }
        let entry = self.entries.get_mut(&key).unwrap();
        entry.previous = self.newest;
        entry.next = None;
        self.newest = Some(key);
    }

    fn remove(&mut self, key: &CacheKey) {
        if !self.entries.contains_key(key) {
            return;
        }
        self.unlink(*key);
        let entry = self.entries.remove(key).unwrap();
        self.used_bytes = self.used_bytes.saturating_sub(entry.estimated_bytes);
    }
}

pub(crate) struct MemoryCacheStore {
    config: MemoryCacheConfig,
    state: Mutex<State>,
}

impl MemoryCacheStore {
    pub(crate) fn new(config: MemoryCacheConfig) -> Self {
        Self {
            config,
            state: Mutex::new(State::default()),
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.state
            .lock()
            .expect("cache mutex poisoned")
            .entries
            .len()
    }
}

impl ExactCacheStore for MemoryCacheStore {
    fn get(
        &self,
        key: &CacheKey,
        now_unix_ms: u64,
    ) -> Result<Option<CachedModelOutput>, CacheError> {
        let mut state = self.state.lock().expect("cache mutex poisoned");
        if state
            .entries
            .get(key)
            .is_some_and(|entry| entry.output.is_expired(now_unix_ms))
        {
            state.remove(key);
            return Ok(None);
        }

        let Some(entry) = state.entries.get(key) else {
            return Ok(None);
        };
        let output = entry.output.clone();
        state.touch(*key);
        Ok(Some(output))
    }

    fn put(&self, key: CacheKey, output: CachedModelOutput) -> Result<(), CacheError> {
        let estimated_bytes = output.estimated_bytes();
        if self.config.max_entries == 0
            || self.config.max_bytes == 0
            || estimated_bytes > self.config.max_bytes
        {
            return Ok(());
        }

        let mut state = self.state.lock().expect("cache mutex poisoned");
        state.remove(&key);
        state.used_bytes = state.used_bytes.saturating_add(estimated_bytes);
        state.entries.insert(
            key,
            Entry {
                output,
                previous: None,
                next: None,
                estimated_bytes,
            },
        );
        state.append(key);
        prune(&mut state, self.config);
        Ok(())
    }

    fn remove_expired(&self, now_unix_ms: u64) -> Result<usize, CacheError> {
        let mut state = self.state.lock().expect("cache mutex poisoned");
        let expired = state
            .entries
            .iter()
            .filter_map(|(key, entry)| entry.output.is_expired(now_unix_ms).then_some(*key))
            .collect::<Vec<_>>();
        let removed = expired.len();
        for key in expired {
            state.remove(&key);
        }
        Ok(removed)
    }

    fn remove_created_before(&self, until_unix_ms: u64) -> Result<usize, CacheError> {
        let mut state = self.state.lock().expect("cache mutex poisoned");
        let stale = state
            .entries
            .iter()
            .filter_map(|(key, entry)| {
                (entry.output.created_at_unix_ms < until_unix_ms).then_some(*key)
            })
            .collect::<Vec<_>>();
        let removed = stale.len();
        for key in stale {
            state.remove(&key);
        }
        Ok(removed)
    }
}

fn prune(state: &mut State, config: MemoryCacheConfig) {
    while state.entries.len() > config.max_entries || state.used_bytes > config.max_bytes {
        let key = state.oldest.expect("nonempty cache has an oldest entry");
        state.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{CacheNamespace, CachedHeadOutput};

    fn key(value: &str) -> CacheKey {
        CacheKey::for_chunk(
            CacheNamespace::from_components(1, &[b"test"]),
            value.as_bytes(),
        )
    }

    fn output(expires_at_unix_ms: u64) -> CachedModelOutput {
        output_created(10, expires_at_unix_ms)
    }

    fn output_created(created_at_unix_ms: u64, expires_at_unix_ms: u64) -> CachedModelOutput {
        CachedModelOutput {
            schema_version: 1,
            heads: vec![CachedHeadOutput {
                head: "test".to_string(),
                logits: vec![0.1, 0.9],
            }],
            created_at_unix_ms,
            expires_at_unix_ms,
        }
    }

    #[test]
    fn expired_entries_are_misses_and_removed() {
        let store = MemoryCacheStore::new(MemoryCacheConfig::default());
        store.put(key("expired"), output(20)).unwrap();

        assert!(store.get(&key("expired"), 20).unwrap().is_none());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn cleanup_removes_only_expired_entries() {
        let store = MemoryCacheStore::new(MemoryCacheConfig::default());
        store.put(key("expired"), output(20)).unwrap();
        store.put(key("current"), output(30)).unwrap();

        assert_eq!(store.remove_expired(20).unwrap(), 1);
        assert!(store.get(&key("expired"), 20).unwrap().is_none());
        assert!(store.get(&key("current"), 20).unwrap().is_some());
    }

    #[test]
    fn cleanup_removes_entries_created_before_cutoff() {
        let store = MemoryCacheStore::new(MemoryCacheConfig::default());
        store.put(key("old"), output_created(10, 100)).unwrap();
        store.put(key("new"), output_created(20, 100)).unwrap();

        assert_eq!(store.remove_created_before(20).unwrap(), 1);
        assert!(store.get(&key("old"), 20).unwrap().is_none());
        assert!(store.get(&key("new"), 20).unwrap().is_some());
    }

    #[test]
    fn least_recently_used_entry_is_evicted() {
        let store = MemoryCacheStore::new(MemoryCacheConfig {
            max_entries: 2,
            max_bytes: usize::MAX,
        });
        store.put(key("first"), output(100)).unwrap();
        store.put(key("second"), output(100)).unwrap();
        store.get(&key("first"), 10).unwrap();
        store.put(key("third"), output(100)).unwrap();

        assert!(store.get(&key("first"), 10).unwrap().is_some());
        assert!(store.get(&key("second"), 10).unwrap().is_none());
        assert!(store.get(&key("third"), 10).unwrap().is_some());
    }

    #[test]
    fn oversized_entry_is_not_inserted() {
        let store = MemoryCacheStore::new(MemoryCacheConfig {
            max_entries: 10,
            max_bytes: 1,
        });

        store.put(key("large"), output(100)).unwrap();

        assert_eq!(store.len(), 0);
    }

    #[test]
    fn replacements_and_cleanup_preserve_recency_and_byte_accounting() {
        let bytes = output(100).estimated_bytes();
        let store = MemoryCacheStore::new(MemoryCacheConfig {
            max_entries: 10,
            max_bytes: bytes * 3,
        });
        store.put(key("first"), output(20)).unwrap();
        store.put(key("second"), output(100)).unwrap();
        store.put(key("third"), output(100)).unwrap();
        store.put(key("second"), output(100)).unwrap();
        assert_eq!(store.remove_expired(20).unwrap(), 1);
        store.put(key("fourth"), output(100)).unwrap();
        store.put(key("fifth"), output(100)).unwrap();
        assert!(store.get(&key("third"), 20).unwrap().is_none());
        assert!(store.get(&key("second"), 20).unwrap().is_some());
        let state = store.state.lock().unwrap();
        assert_eq!(state.used_bytes, bytes * 3);
        assert_eq!(state.oldest, Some(key("fourth")));
        assert_eq!(state.newest, Some(key("second")));
    }

    #[test]
    fn byte_limit_can_evict_multiple_entries_and_empty_cache_can_be_reused() {
        let small = output(100);
        let bytes = small.estimated_bytes();
        let mut large = small.clone();
        large.heads[0].logits.resize(bytes / 4 + 4, 0.0);
        let large_bytes = large.estimated_bytes();
        assert!(large_bytes > bytes * 2);
        let store = MemoryCacheStore::new(MemoryCacheConfig {
            max_entries: 10,
            max_bytes: large_bytes,
        });
        store.put(key("first"), small.clone()).unwrap();
        store.put(key("second"), small.clone()).unwrap();
        store.put(key("large"), large).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.remove_expired(100).unwrap(), 1);
        store.put(key("fresh"), small).unwrap();
        assert!(store.get(&key("fresh"), 20).unwrap().is_some());
        let state = store.state.lock().unwrap();
        assert_eq!(state.oldest, Some(key("fresh")));
        assert_eq!(state.newest, state.oldest);
        assert_eq!(state.used_bytes, bytes);
    }
}
