// SPDX-License-Identifier: GPL-3.0-only
//! Exact raw GLiNER chunk-output cache. The namespace is only the immutable
//! model SHA; inference inputs that change raw output are part of the exact key.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::gliner_onnx_engine::Entity;

use super::{CacheCoordinator, CacheKey, CacheNamespace, CachedHeadOutput, CachedModelOutput};

const CACHE_SCHEMA_VERSION: u32 = 1;

pub(crate) struct PiiChunkCache {
    coordinator: Arc<CacheCoordinator>,
}

#[derive(Serialize, Deserialize)]
struct StoredEntity {
    label: String,
    text: String,
    start_byte: usize,
    end_byte: usize,
    start_char: usize,
    end_char: usize,
}

impl PiiChunkCache {
    pub(crate) fn new(coordinator: Arc<CacheCoordinator>) -> Self {
        Self { coordinator }
    }

    pub(crate) fn get(
        &self,
        model_sha: &str,
        chunk: &str,
        labels: &[String],
        inference_threshold: f32,
    ) -> Option<Vec<Entity>> {
        let key = key(model_sha, chunk, labels, inference_threshold);
        decode(&self.coordinator.lookup_exact(&key)?.output)
    }

    pub(crate) fn put(
        &self,
        model_sha: &str,
        chunk: &str,
        labels: &[String],
        inference_threshold: f32,
        entities: &[Entity],
    ) {
        let key = key(model_sha, chunk, labels, inference_threshold);
        let heads = entities
            .iter()
            .filter_map(|entity| {
                serde_json::to_string(&StoredEntity {
                    label: entity.label.clone(),
                    text: entity.text.clone(),
                    start_byte: entity.start_byte,
                    end_byte: entity.end_byte,
                    start_char: entity.start_char,
                    end_char: entity.end_char,
                })
                .ok()
                .map(|head| CachedHeadOutput {
                    head,
                    logits: vec![entity.score],
                })
            })
            .collect();
        let _ = self.coordinator.put_heads(key, heads);
    }
}

fn key(model_sha: &str, chunk: &str, labels: &[String], inference_threshold: f32) -> CacheKey {
    let namespace = CacheNamespace::from_model_sha(CACHE_SCHEMA_VERSION, model_sha);
    let mut material = Vec::new();
    material.extend_from_slice(b"dynamic-pii-chunk-v1\0");
    for label in labels {
        material.extend_from_slice(&(label.len() as u64).to_le_bytes());
        material.extend_from_slice(label.as_bytes());
    }
    material.extend_from_slice(&inference_threshold.to_bits().to_le_bytes());
    material.extend_from_slice(chunk.as_bytes());
    CacheKey::for_chunk(namespace, &material)
}

fn decode(output: &CachedModelOutput) -> Option<Vec<Entity>> {
    (output.schema_version == CACHE_SCHEMA_VERSION).then(|| {
        output
            .heads
            .iter()
            .filter_map(|head| {
                let stored = serde_json::from_str::<StoredEntity>(&head.head).ok()?;
                let score = *head.logits.first()?;
                Some(Entity {
                    label: stored.label,
                    text: stored.text,
                    score,
                    start_byte: stored.start_byte,
                    end_byte: stored.end_byte,
                    start_char: stored.start_char,
                    end_char: stored.end_char,
                })
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::ExactCacheConfig;

    #[test]
    fn exact_chunk_hit_is_scoped_by_model_labels_and_threshold() {
        let cache = PiiChunkCache::new(Arc::new(
            CacheCoordinator::from_config(ExactCacheConfig::default()).unwrap(),
        ));
        let labels = vec!["person".to_string()];
        cache.put(
            "model-a",
            "Alexandr Stone",
            &labels,
            0.2,
            &[Entity {
                label: "person".to_string(),
                text: "Alexandr Stone".to_string(),
                score: 0.91,
                start_byte: 0,
                end_byte: 14,
                start_char: 0,
                end_char: 14,
            }],
        );

        let hit = cache
            .get("model-a", "Alexandr Stone", &labels, 0.2)
            .unwrap();
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].label, "person");
        assert!(cache
            .get("model-b", "Alexandr Stone", &labels, 0.2)
            .is_none());
        assert!(cache
            .get("model-a", "Alexandr Stone", &["location".to_string()], 0.2)
            .is_none());
        assert!(cache
            .get("model-a", "Alexandr Stone", &labels, 0.3)
            .is_none());
    }
}
