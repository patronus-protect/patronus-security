// SPDX-License-Identifier: GPL-3.0-only
//! Pipeline-neutral exact model-output caching.

#[cfg(test)]
mod benchmark;
mod config;
mod coordinator;
mod crypto;
mod memory;
mod pii_chunk;
mod pii_entity;
mod redb;
mod similarity;
mod store;
mod types;
mod write_behind;

pub use config::{CacheEncryptionConfig, CacheWriteMode, ExactCacheConfig, PersistentCacheConfig};
pub(crate) use coordinator::{CacheCoordinator, CacheSource};
pub(crate) use crypto::CacheCrypto;
pub use memory::MemoryCacheConfig;
pub(crate) use memory::MemoryCacheStore;
pub(crate) use pii_chunk::PiiChunkCache;
pub(crate) use pii_entity::merge_pii_spans;
pub(crate) use redb::RedbCacheStore;
pub(crate) use similarity::{
    decision_output, HistoricalSimilarityCache, SimilarityDecision, SimilarityMatch,
};
pub use store::CacheError;
pub(crate) use store::{ExactCacheStore, SimilarityStoreRecord};
pub(crate) use types::{CacheKey, CacheNamespace, CachedHeadOutput, CachedModelOutput};
pub use write_behind::WriteBehindConfig;
pub(crate) use write_behind::WriteBehindStore;
