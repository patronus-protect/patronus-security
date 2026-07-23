// SPDX-License-Identifier: GPL-3.0-only
//! Pipeline-neutral exact model-output caching.

#[cfg(test)]
mod benchmark;
mod config;
mod coordinator;
mod memory;
mod pii_chunk;
mod pii_entity;
mod redb;
mod similarity;
mod store;
mod types;
mod write_behind;

pub use config::{CacheWriteMode, ExactCacheConfig, PersistentCacheConfig};
pub(crate) use coordinator::{CacheCoordinator, CacheLookup, CacheSource, Clock, SystemClock};
pub use memory::MemoryCacheConfig;
pub(crate) use memory::MemoryCacheStore;
pub(crate) use pii_chunk::PiiChunkCache;
pub(crate) use pii_entity::{merge_pii_spans, PiiEntityCache};
pub(crate) use redb::RedbCacheStore;
pub(crate) use similarity::{
    cosine_similarity, decision_output, HistoricalSimilarityCache, SimilarityDecision,
    SimilarityMatch,
};
pub use store::CacheError;
pub(crate) use store::{ExactCacheStore, SimilarityStoreRecord};
pub(crate) use types::{CacheKey, CacheNamespace, CachedHeadOutput, CachedModelOutput};
pub use write_behind::WriteBehindConfig;
pub(crate) use write_behind::{WriteBehindStats, WriteBehindStatsSnapshot, WriteBehindStore};
