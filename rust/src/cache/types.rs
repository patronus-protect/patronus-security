// SPDX-License-Identifier: GPL-3.0-only
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct CacheNamespace([u8; 32]);

impl CacheNamespace {
    pub(crate) fn from_model_sha(schema_version: u32, model_sha: &str) -> Self {
        Self::from_components(schema_version, &[model_sha.as_bytes()])
    }

    pub(crate) fn from_components(schema_version: u32, components: &[&[u8]]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&schema_version.to_le_bytes());
        for component in components {
            hasher.update(&(component.len() as u64).to_le_bytes());
            hasher.update(component);
        }
        Self(*hasher.finalize().as_bytes())
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct CacheKey {
    namespace: CacheNamespace,
    chunk_hash: [u8; 32],
    chunk_len: u64,
}

impl CacheKey {
    pub(crate) fn for_chunk(namespace: CacheNamespace, chunk: &[u8]) -> Self {
        Self {
            namespace,
            chunk_hash: *blake3::hash(chunk).as_bytes(),
            chunk_len: chunk.len() as u64,
        }
    }

    pub(crate) fn namespace(&self) -> CacheNamespace {
        self.namespace
    }

    pub(crate) fn chunk_hash(&self) -> &[u8; 32] {
        &self.chunk_hash
    }

    pub(crate) fn chunk_len(&self) -> u64 {
        self.chunk_len
    }

    pub(crate) fn to_bytes(self) -> [u8; 72] {
        let mut bytes = [0u8; 72];
        bytes[..32].copy_from_slice(self.namespace.as_bytes());
        bytes[32..64].copy_from_slice(&self.chunk_hash);
        bytes[64..].copy_from_slice(&self.chunk_len.to_le_bytes());
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct CachedHeadOutput {
    pub(crate) head: String,
    pub(crate) logits: Vec<f32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct CachedModelOutput {
    pub(crate) schema_version: u32,
    pub(crate) heads: Vec<CachedHeadOutput>,
    pub(crate) created_at_unix_ms: u64,
    pub(crate) expires_at_unix_ms: u64,
}

impl CachedModelOutput {
    pub(crate) fn is_expired(&self, now_unix_ms: u64) -> bool {
        self.expires_at_unix_ms <= now_unix_ms
    }

    pub(crate) fn estimated_bytes(&self) -> usize {
        let heads = self
            .heads
            .iter()
            .map(|head| head.head.len() + head.logits.len() * size_of::<f32>())
            .sum::<usize>();
        64 + heads
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_components_are_length_delimited() {
        let first = CacheNamespace::from_components(1, &[b"ab", b"c"]);
        let second = CacheNamespace::from_components(1, &[b"a", b"bc"]);

        assert_ne!(first, second);
    }

    #[test]
    fn model_namespace_depends_only_on_schema_and_model_sha() {
        let namespace = CacheNamespace::from_model_sha(1, "abc123");

        assert_eq!(namespace, CacheNamespace::from_components(1, &[b"abc123"]));
        assert_ne!(namespace, CacheNamespace::from_model_sha(2, "abc123"));
        assert_ne!(namespace, CacheNamespace::from_model_sha(1, "def456"));
    }

    #[test]
    fn key_changes_with_namespace_or_exact_chunk_bytes() {
        let first_namespace = CacheNamespace::from_components(1, &[b"model-a"]);
        let second_namespace = CacheNamespace::from_components(1, &[b"model-b"]);

        assert_ne!(
            CacheKey::for_chunk(first_namespace, b"same chunk"),
            CacheKey::for_chunk(second_namespace, b"same chunk")
        );
        assert_ne!(
            CacheKey::for_chunk(first_namespace, b"same chunk"),
            CacheKey::for_chunk(first_namespace, b"same chunk ")
        );
    }

    #[test]
    fn key_binary_representation_contains_namespace_hash_and_length() {
        let namespace = CacheNamespace::from_components(1, &[b"model"]);
        let key = CacheKey::for_chunk(namespace, b"chunk");
        let bytes = key.to_bytes();

        assert_eq!(&bytes[..32], namespace.as_bytes());
        assert_eq!(&bytes[32..64], key.chunk_hash());
        assert_eq!(u64::from_le_bytes(bytes[64..].try_into().unwrap()), 5);
    }
}
