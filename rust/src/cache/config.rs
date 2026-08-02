// SPDX-License-Identifier: GPL-3.0-only
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use super::{MemoryCacheConfig, WriteBehindConfig};

#[derive(Debug, Clone)]
pub struct ExactCacheConfig {
    pub memory: MemoryCacheConfig,
    pub persistent: Option<PersistentCacheConfig>,
    pub entry_ttl: Duration,
}

impl Default for ExactCacheConfig {
    fn default() -> Self {
        Self {
            memory: MemoryCacheConfig::default(),
            persistent: None,
            entry_ttl: Duration::from_secs(30 * 24 * 60 * 60),
        }
    }
}

#[derive(Clone)]
pub struct CacheEncryptionConfig {
    pub key: [u8; 32],
}

impl CacheEncryptionConfig {
    pub fn from_key(key: [u8; 32]) -> Self {
        Self { key }
    }
}

impl fmt::Debug for CacheEncryptionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CacheEncryptionConfig")
            .field("key", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct PersistentCacheConfig {
    pub storage_location: PathBuf,
    pub write_mode: CacheWriteMode,
    pub write_behind: WriteBehindConfig,
    pub encryption: Option<CacheEncryptionConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheWriteMode {
    WriteThrough,
    Async,
}
