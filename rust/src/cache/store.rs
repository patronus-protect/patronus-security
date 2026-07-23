// SPDX-License-Identifier: GPL-3.0-only
use thiserror::Error;

use super::{CacheKey, CachedHeadOutput, CachedModelOutput};

#[derive(Debug, Clone)]
pub(crate) struct SimilarityStoreRecord {
    pub(crate) id: [u8; 32],
    pub(crate) vector_space: String,
    pub(crate) producer_model_sha: String,
    pub(crate) embedding: Vec<f32>,
    pub(crate) heads: Vec<CachedHeadOutput>,
    pub(crate) bucket_keys: Vec<Vec<u8>>,
    pub(crate) created_at_unix_ms: u64,
    pub(crate) expires_at_unix_ms: u64,
}

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("cache storage error: {0}")]
    Storage(String),
    #[error("invalid cache record: {0}")]
    InvalidRecord(String),
}

pub(crate) trait ExactCacheStore: Send + Sync {
    fn get(
        &self,
        key: &CacheKey,
        now_unix_ms: u64,
    ) -> Result<Option<CachedModelOutput>, CacheError>;

    fn put(&self, key: CacheKey, value: CachedModelOutput) -> Result<(), CacheError>;

    fn put_batch(&self, entries: Vec<(CacheKey, CachedModelOutput)>) -> Result<(), CacheError> {
        for (key, value) in entries {
            self.put(key, value)?;
        }
        Ok(())
    }

    fn remove_expired(&self, now_unix_ms: u64) -> Result<usize, CacheError>;

    fn similarity_candidates(
        &self,
        _bucket_keys: &[Vec<u8>],
        _now_unix_ms: u64,
        _limit: usize,
    ) -> Result<Vec<SimilarityStoreRecord>, CacheError> {
        Ok(Vec::new())
    }

    fn put_similarity(&self, _record: SimilarityStoreRecord) -> Result<(), CacheError> {
        Ok(())
    }

    fn put_similarity_batch(&self, records: Vec<SimilarityStoreRecord>) -> Result<(), CacheError> {
        for record in records {
            self.put_similarity(record)?;
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), CacheError> {
        Ok(())
    }
}
