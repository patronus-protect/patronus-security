// SPDX-License-Identifier: GPL-3.0-only
//! Two-tier historical similarity over the embeddings already produced by L2.
//! A bounded LSH index serves hot RAM lookups; redb persists compact records and
//! bucket membership without imposing a persistent entry-count limit.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use super::{CacheCoordinator, CachedHeadOutput, SimilarityStoreRecord};

const LSH_BANDS: usize = 8;
const LSH_BITS_PER_BAND: usize = 12;
const MAX_CANDIDATES_PER_LOOKUP: usize = 1_024;
const MIN_PRIORITY_SIMILARITY: f64 = 0.70;

pub(crate) struct HistoricalSimilarityCache {
    coordinator: Arc<CacheCoordinator>,
    hot: Mutex<HotState>,
    hot_max_entries: usize,
    hot_max_bytes: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SimilarityMatch {
    pub(crate) priority_similarity: f64,
    pub(crate) propagation_similarity: f64,
    pub(crate) producer_model_sha: String,
    pub(crate) heads: Vec<CachedHeadOutput>,
    pub(crate) decision: Option<SimilarityDecision>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SimilarityDecision {
    pub(crate) head: String,
    pub(crate) class_name: String,
    pub(crate) confidence: f64,
}

struct HotEntry {
    record: SimilarityStoreRecord,
    estimated_bytes: usize,
}

#[derive(Default)]
struct HotState {
    entries: HashMap<[u8; 32], HotEntry>,
    buckets: HashMap<Vec<u8>, Vec<[u8; 32]>>,
    insertion_order: VecDeque<[u8; 32]>,
    used_bytes: usize,
}

impl HistoricalSimilarityCache {
    pub(crate) fn new(coordinator: Arc<CacheCoordinator>) -> Self {
        let limits = coordinator.memory_config();
        Self {
            coordinator,
            hot: Mutex::new(HotState::default()),
            hot_max_entries: limits.max_entries,
            hot_max_bytes: limits.max_bytes,
        }
    }

    pub(crate) fn find_best(
        &self,
        vector_space: &str,
        embedding: &[f32],
        producer_model_sha: Option<&str>,
    ) -> Option<SimilarityMatch> {
        self.find(
            vector_space,
            embedding,
            |record| {
                producer_model_sha
                    .map(|expected| record.producer_model_sha == expected)
                    .unwrap_or(true)
            },
            None,
        )
    }

    pub(crate) fn find_best_for_head(
        &self,
        vector_space: &str,
        embedding: &[f32],
        logical_head: &str,
    ) -> Option<SimilarityMatch> {
        self.find(
            vector_space,
            embedding,
            |record| decode_decision(&record.heads, logical_head).is_some(),
            Some(logical_head),
        )
    }

    fn find(
        &self,
        vector_space: &str,
        embedding: &[f32],
        accepts: impl Fn(&SimilarityStoreRecord) -> bool,
        logical_head: Option<&str>,
    ) -> Option<SimilarityMatch> {
        if vector_space.is_empty() || embedding.is_empty() {
            return None;
        }
        let bucket_keys = lsh_bucket_keys(vector_space, embedding);
        {
            let hot = self.hot.lock().expect("similarity hot cache poisoned");
            let ids = hot.candidate_ids(&bucket_keys);
            if let Some(matched) = best_match(
                ids.iter().filter_map(|id| hot.entries.get(id)),
                embedding,
                &accepts,
                logical_head,
            ) {
                return Some(matched.1);
            }
        }

        let records = self
            .coordinator
            .similarity_candidates(&bucket_keys, MAX_CANDIDATES_PER_LOOKUP);
        let matched = best_match_records(records.iter(), embedding, &accepts, logical_head);
        if !records.is_empty() {
            let mut hot = self.hot.lock().expect("similarity hot cache poisoned");
            for record in records {
                hot.insert(record, self.hot_max_entries, self.hot_max_bytes);
            }
        }
        matched.map(|(_, matched)| matched)
    }

    pub(crate) fn remember(
        &self,
        vector_space: &str,
        embedding: &[f32],
        producer_model_sha: &str,
        heads: Vec<CachedHeadOutput>,
    ) {
        if vector_space.is_empty() || embedding.is_empty() || heads.is_empty() {
            return;
        }
        let Some(embedding) = normalized(embedding) else {
            return;
        };
        let bucket_keys = lsh_bucket_keys(vector_space, &embedding);
        let id = record_id(vector_space, producer_model_sha, &embedding);
        let record = SimilarityStoreRecord {
            id,
            vector_space: vector_space.to_string(),
            producer_model_sha: producer_model_sha.to_string(),
            embedding,
            heads,
            bucket_keys,
            created_at_unix_ms: 0,
            expires_at_unix_ms: u64::MAX,
        };
        self.hot
            .lock()
            .expect("similarity hot cache poisoned")
            .insert(record.clone(), self.hot_max_entries, self.hot_max_bytes);
        let _ = self.coordinator.put_similarity(record);
    }

    #[cfg(test)]
    fn hot_len(&self) -> usize {
        self.hot
            .lock()
            .expect("similarity hot cache poisoned")
            .entries
            .len()
    }

    #[cfg(test)]
    pub(super) fn clear_hot_for_benchmark(&self) {
        *self.hot.lock().expect("similarity hot cache poisoned") = HotState::default();
    }
}

impl HotState {
    fn candidate_ids(&self, bucket_keys: &[Vec<u8>]) -> Vec<[u8; 32]> {
        let mut seen = HashSet::new();
        let mut ids = Vec::new();
        'buckets: for bucket in bucket_keys {
            let Some(bucket_ids) = self.buckets.get(bucket) else {
                continue;
            };
            for id in bucket_ids {
                if seen.insert(*id) {
                    ids.push(*id);
                    if ids.len() >= MAX_CANDIDATES_PER_LOOKUP {
                        break 'buckets;
                    }
                }
            }
        }
        ids
    }

    fn insert(&mut self, record: SimilarityStoreRecord, max_entries: usize, max_bytes: usize) {
        let estimated_bytes = estimate_record_bytes(&record);
        if max_entries == 0 || max_bytes == 0 || estimated_bytes > max_bytes {
            return;
        }
        let replacing = self.entries.contains_key(&record.id);
        if let Some(existing) = self.entries.remove(&record.id) {
            self.used_bytes = self.used_bytes.saturating_sub(existing.estimated_bytes);
            self.remove_from_buckets(existing.record.id, &existing.record.bucket_keys);
        }
        let id = record.id;
        for bucket in &record.bucket_keys {
            self.buckets.entry(bucket.clone()).or_default().push(id);
        }
        self.used_bytes = self.used_bytes.saturating_add(estimated_bytes);
        self.entries.insert(
            id,
            HotEntry {
                record,
                estimated_bytes,
            },
        );
        if !replacing {
            self.insertion_order.push_back(id);
        }
        while self.entries.len() > max_entries || self.used_bytes > max_bytes {
            let Some(victim) = self.insertion_order.pop_front() else {
                break;
            };
            if let Some(entry) = self.entries.remove(&victim) {
                self.used_bytes = self.used_bytes.saturating_sub(entry.estimated_bytes);
                self.remove_from_buckets(victim, &entry.record.bucket_keys);
            }
        }
    }

    fn remove_from_buckets(&mut self, id: [u8; 32], bucket_keys: &[Vec<u8>]) {
        for bucket in bucket_keys {
            let remove_bucket = if let Some(ids) = self.buckets.get_mut(bucket) {
                ids.retain(|candidate| *candidate != id);
                ids.is_empty()
            } else {
                false
            };
            if remove_bucket {
                self.buckets.remove(bucket);
            }
        }
    }
}

fn best_match<'a>(
    records: impl Iterator<Item = &'a HotEntry>,
    embedding: &[f32],
    accepts: &impl Fn(&SimilarityStoreRecord) -> bool,
    logical_head: Option<&str>,
) -> Option<([u8; 32], SimilarityMatch)> {
    records
        .filter(|entry| accepts(&entry.record))
        .filter_map(|entry| {
            let similarity = cosine_similarity(embedding, &entry.record.embedding)?;
            (similarity >= MIN_PRIORITY_SIMILARITY).then(|| {
                (
                    entry.record.id,
                    similarity_match(&entry.record, similarity, logical_head),
                )
            })
        })
        .max_by(|left, right| {
            left.1
                .propagation_similarity
                .total_cmp(&right.1.propagation_similarity)
        })
}

fn best_match_records<'a>(
    records: impl Iterator<Item = &'a SimilarityStoreRecord>,
    embedding: &[f32],
    accepts: &impl Fn(&SimilarityStoreRecord) -> bool,
    logical_head: Option<&str>,
) -> Option<([u8; 32], SimilarityMatch)> {
    records
        .filter(|record| accepts(record))
        .filter_map(|record| {
            let similarity = cosine_similarity(embedding, &record.embedding)?;
            (similarity >= MIN_PRIORITY_SIMILARITY).then(|| {
                (
                    record.id,
                    similarity_match(record, similarity, logical_head),
                )
            })
        })
        .max_by(|left, right| {
            left.1
                .propagation_similarity
                .total_cmp(&right.1.propagation_similarity)
        })
}

fn similarity_match(
    record: &SimilarityStoreRecord,
    similarity: f64,
    logical_head: Option<&str>,
) -> SimilarityMatch {
    SimilarityMatch {
        priority_similarity: similarity,
        propagation_similarity: similarity,
        producer_model_sha: record.producer_model_sha.clone(),
        heads: record.heads.clone(),
        decision: logical_head.and_then(|head| decode_decision(&record.heads, head)),
    }
}

fn estimate_record_bytes(record: &SimilarityStoreRecord) -> usize {
    32 + record.vector_space.len()
        + record.producer_model_sha.len()
        + record.embedding.len() * std::mem::size_of::<f32>()
        + record
            .heads
            .iter()
            .map(|head| head.head.len() + head.logits.len() * std::mem::size_of::<f32>())
            .sum::<usize>()
        + record.bucket_keys.iter().map(Vec::len).sum::<usize>()
}

fn record_id(vector_space: &str, producer_model_sha: &str, embedding: &[f32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(vector_space.as_bytes());
    hasher.update(&[0]);
    hasher.update(producer_model_sha.as_bytes());
    hasher.update(&[0]);
    for value in embedding {
        hasher.update(&value.to_bits().to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn lsh_bucket_keys(vector_space: &str, embedding: &[f32]) -> Vec<Vec<u8>> {
    let space_hash = blake3::hash(vector_space.as_bytes());
    let base_seed = u64::from_le_bytes(space_hash.as_bytes()[..8].try_into().unwrap());
    (0..LSH_BANDS)
        .map(|band| {
            let mut signature = 0u16;
            for bit in 0..LSH_BITS_PER_BAND {
                let plane = band * LSH_BITS_PER_BAND + bit;
                let mut state =
                    splitmix64(base_seed ^ (plane as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15));
                let projection = embedding.iter().fold(0.0f64, |sum, value| {
                    state = splitmix64(state);
                    if state & 1 == 0 {
                        sum + f64::from(*value)
                    } else {
                        sum - f64::from(*value)
                    }
                });
                if projection >= 0.0 {
                    signature |= 1 << bit;
                }
            }
            let mut key = Vec::with_capacity(11);
            key.extend_from_slice(&space_hash.as_bytes()[..8]);
            key.push(band as u8);
            key.extend_from_slice(&signature.to_le_bytes());
            key
        })
        .collect()
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

pub(crate) fn decision_output(
    logical_head: &str,
    class_name: &str,
    confidence: f64,
) -> CachedHeadOutput {
    CachedHeadOutput {
        head: format!("decision\0{logical_head}\0{class_name}"),
        logits: vec![confidence.clamp(0.0, 1.0) as f32],
    }
}

fn decode_decision(heads: &[CachedHeadOutput], logical_head: &str) -> Option<SimilarityDecision> {
    heads.iter().find_map(|output| {
        let mut parts = output.head.split('\0');
        (parts.next()? == "decision").then_some(())?;
        let head = parts.next()?;
        let class_name = parts.next()?;
        if head != logical_head || parts.next().is_some() {
            return None;
        }
        Some(SimilarityDecision {
            head: head.to_string(),
            class_name: class_name.to_string(),
            confidence: f64::from(*output.logits.first()?),
        })
    })
}

pub(crate) fn cosine_similarity(left: &[f32], right: &[f32]) -> Option<f64> {
    if left.is_empty() || left.len() != right.len() {
        return None;
    }
    let dot = left
        .iter()
        .zip(right)
        .map(|(left, right)| f64::from(*left) * f64::from(*right))
        .sum::<f64>();
    let left_norm = left
        .iter()
        .map(|value| f64::from(*value).powi(2))
        .sum::<f64>()
        .sqrt();
    let right_norm = right
        .iter()
        .map(|value| f64::from(*value).powi(2))
        .sum::<f64>()
        .sqrt();
    (left_norm > f64::EPSILON && right_norm > f64::EPSILON)
        .then_some((dot / (left_norm * right_norm)).clamp(-1.0, 1.0))
}

fn normalized(values: &[f32]) -> Option<Vec<f32>> {
    let norm = values
        .iter()
        .map(|value| f64::from(*value).powi(2))
        .sum::<f64>()
        .sqrt();
    (norm > f64::EPSILON).then(|| {
        values
            .iter()
            .map(|value| (f64::from(*value) / norm) as f32)
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{
        CacheWriteMode, ExactCacheConfig, MemoryCacheConfig, PersistentCacheConfig,
        WriteBehindConfig,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("patronus-similarity-{name}-{unique}.redb"))
    }

    #[test]
    fn cosine_uses_vector_geometry() {
        assert_eq!(cosine_similarity(&[1.0, 0.0], &[1.0, 0.0]), Some(1.0));
        assert_eq!(cosine_similarity(&[1.0, 0.0], &[0.0, 1.0]), Some(0.0));
    }

    #[test]
    fn shared_vector_index_remains_model_and_head_scoped() {
        let coordinator =
            Arc::new(CacheCoordinator::from_config(ExactCacheConfig::default()).unwrap());
        let cache = HistoricalSimilarityCache::new(coordinator);
        cache.remember(
            "shared-encoder-sha",
            &[1.0, 0.0],
            "dedicated-sha",
            vec![
                CachedHeadOutput {
                    head: "classification".to_string(),
                    logits: vec![0.1, 0.9],
                },
                decision_output("injection", "attack", 0.9),
            ],
        );
        cache.remember(
            "shared-encoder-sha",
            &[0.999, 0.01],
            "unified-sha",
            vec![
                CachedHeadOutput {
                    head: "threat".to_string(),
                    logits: vec![0.2, 0.8],
                },
                decision_output("threat", "exfiltration_attempt", 0.8),
            ],
        );

        let dedicated = cache
            .find_best("shared-encoder-sha", &[1.0, 0.0], Some("dedicated-sha"))
            .unwrap();
        let unified = cache
            .find_best("shared-encoder-sha", &[1.0, 0.0], Some("unified-sha"))
            .unwrap();

        assert_eq!(dedicated.heads[0].head, "classification");
        assert_eq!(unified.heads[0].head, "threat");
        let cross_mode = cache
            .find_best_for_head("shared-encoder-sha", &[1.0, 0.0], "threat")
            .unwrap();
        assert_eq!(
            cross_mode.decision.unwrap().class_name,
            "exfiltration_attempt"
        );
        assert_eq!(cross_mode.producer_model_sha, "unified-sha");
        assert!(cache
            .find_best("other-encoder", &[1.0, 0.0], None)
            .is_none());
    }

    #[test]
    fn hot_eviction_does_not_remove_persistent_similarity() {
        let path = temp_path("hot-eviction");
        let config = ExactCacheConfig {
            memory: MemoryCacheConfig {
                max_entries: 1,
                max_bytes: 1024,
            },
            persistent: Some(PersistentCacheConfig {
                storage_location: path.clone(),
                write_mode: CacheWriteMode::WriteThrough,
                write_behind: WriteBehindConfig::default(),
            }),
            ..ExactCacheConfig::default()
        };
        let coordinator = Arc::new(CacheCoordinator::from_config(config).unwrap());
        let cache = HistoricalSimilarityCache::new(Arc::clone(&coordinator));
        cache.remember(
            "space",
            &[1.0, 0.0],
            "model",
            vec![decision_output("injection", "attack", 0.9)],
        );
        cache.remember(
            "space",
            &[0.0, 1.0],
            "model",
            vec![decision_output("injection", "benign", 0.9)],
        );
        assert_eq!(cache.hot_len(), 1);
        assert!(cache
            .find_best_for_head("space", &[1.0, 0.0], "injection")
            .is_some());
        coordinator.flush().unwrap();
        drop(cache);
        drop(coordinator);

        let reopened = Arc::new(
            CacheCoordinator::from_config(ExactCacheConfig {
                memory: MemoryCacheConfig {
                    max_entries: 1,
                    max_bytes: 1024,
                },
                persistent: Some(PersistentCacheConfig {
                    storage_location: path.clone(),
                    write_mode: CacheWriteMode::WriteThrough,
                    write_behind: WriteBehindConfig::default(),
                }),
                ..ExactCacheConfig::default()
            })
            .unwrap(),
        );
        let cache = HistoricalSimilarityCache::new(reopened);
        assert!(cache
            .find_best_for_head("space", &[1.0, 0.0], "injection")
            .is_some());
        drop(cache);
        std::fs::remove_file(path).unwrap();
    }
}
