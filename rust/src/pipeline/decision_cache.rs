// SPDX-License-Identifier: AGPL-3.0-only
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::{EvaluationResult, LayerResult, ScanExecution, SecurityLevel};

const DEFAULT_MAX_ENTRIES: usize = 100_000;
const DEFAULT_MAX_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct DecisionCacheConfig {
    pub max_entries: usize,
    pub max_bytes: usize,
}

impl Default for DecisionCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_ENTRIES,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq)]
struct DecisionCacheKey {
    scope_hash: [u8; 32],
    text_hash: [u8; 32],
    text_len: usize,
}

impl PartialEq for DecisionCacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.scope_hash == other.scope_hash
            && self.text_hash == other.text_hash
            && self.text_len == other.text_len
    }
}

impl Hash for DecisionCacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.scope_hash.hash(state);
        self.text_hash.hash(state);
        self.text_len.hash(state);
    }
}

#[derive(Clone)]
struct DecisionCacheEntry {
    result: EvaluationResult,
    layers: Vec<LayerResult>,
    expires_at: Instant,
    last_access: u64,
    estimated_bytes: usize,
}

#[derive(Default)]
struct DecisionCacheInner {
    entries: HashMap<DecisionCacheKey, DecisionCacheEntry>,
    used_bytes: usize,
    access_counter: u64,
}

#[derive(Default)]
pub struct DecisionCache {
    config: DecisionCacheConfig,
    inner: Mutex<DecisionCacheInner>,
}

impl DecisionCache {
    #[cfg(feature = "test-util")]
    pub fn with_config(config: DecisionCacheConfig) -> Self {
        Self {
            config,
            inner: Mutex::new(DecisionCacheInner::default()),
        }
    }

    pub fn get(
        &self,
        namespace: &str,
        text: &str,
        execution: &ScanExecution,
    ) -> Option<(EvaluationResult, Vec<LayerResult>)> {
        let started = Instant::now();
        let now = Instant::now();
        let key = cache_key(namespace, text, execution);
        let mut inner = self.inner.lock().expect("decision cache mutex poisoned");
        let next_access = inner.access_counter.wrapping_add(1);
        inner.access_counter = next_access;

        let entry = match inner.entries.get_mut(&key) {
            Some(entry) if entry.expires_at > now => entry,
            Some(entry) => {
                let estimated_bytes = entry.estimated_bytes;
                inner.entries.remove(&key);
                inner.used_bytes = inner.used_bytes.saturating_sub(estimated_bytes);
                return None;
            }
            None => return None,
        };
        entry.last_access = next_access;
        let mut layers = entry.layers.clone();
        let lookup_ms = started.elapsed().as_secs_f64() * 1000.0;
        mark_cache_hit(&mut layers, lookup_ms, text.len());
        Some((entry.result.clone(), layers))
    }

    pub fn insert(
        &self,
        namespace: &str,
        text: &str,
        execution: &ScanExecution,
        result: &EvaluationResult,
        layers: &[LayerResult],
    ) {
        if !cacheable_layers(layers) {
            return;
        }

        let key = cache_key(namespace, text, execution);
        let ttl = ttl_for_len(text.len());
        let estimated_bytes = estimate_entry_bytes(result, layers);
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("decision cache mutex poisoned");
        let next_access = inner.access_counter.wrapping_add(1);
        inner.access_counter = next_access;

        if let Some(old) = inner.entries.remove(&key) {
            inner.used_bytes = inner.used_bytes.saturating_sub(old.estimated_bytes);
        }

        inner.used_bytes = inner.used_bytes.saturating_add(estimated_bytes);
        inner.entries.insert(
            key,
            DecisionCacheEntry {
                result: result.clone(),
                layers: zero_duration_layers(layers),
                expires_at: now + ttl,
                last_access: next_access,
                estimated_bytes,
            },
        );
        prune(&mut inner, self.config, now);
    }
}

fn cache_key(namespace: &str, text: &str, execution: &ScanExecution) -> DecisionCacheKey {
    let mut scope = blake3::Hasher::new();
    scope.update(namespace.as_bytes());
    scope.update(&[0]);
    scope.update(execution.max_level().as_str().as_bytes());
    scope.update(&[
        execution.allows_level(SecurityLevel::L1) as u8,
        execution.allows_level(SecurityLevel::L2) as u8,
        execution.allows_level(SecurityLevel::L3) as u8,
        execution.defer_l3() as u8,
    ]);
    scope.update(execution.backend().as_str().as_bytes());
    scope.update(execution.onnx_batch_mode().as_str().as_bytes());
    scope.update(execution.ntdb_operating_point().as_str().as_bytes());
    scope.update(execution.l3_strategy().as_str().as_bytes());
    DecisionCacheKey {
        scope_hash: *scope.finalize().as_bytes(),
        text_hash: *blake3::hash(text.as_bytes()).as_bytes(),
        text_len: text.len(),
    }
}

fn ttl_for_len(len: usize) -> Duration {
    let hours = if len < 256 {
        1
    } else if len < 2 * 1024 {
        2
    } else if len < 4 * 1024 {
        6
    } else if len < 10 * 1024 {
        24
    } else {
        48
    };
    Duration::from_secs(hours * 60 * 60)
}

fn cacheable_layers(layers: &[LayerResult]) -> bool {
    !layers.iter().any(|layer| {
        layer.layer_type == "onnx_error"
            || layer.layer_type == "ntdb_error"
            || layer.layer_type == "l3_pending"
            || layer.layer_type == "degraded_timeout"
            || layer.layer_type == "degraded_error"
            || layer
                .details
                .get("fallback_due_to_error")
                .and_then(|value| value.as_bool())
                .unwrap_or(false)
            || layer
                .details
                .get("fallback_due_to_timeout")
                .and_then(|value| value.as_bool())
                .unwrap_or(false)
    })
}

fn zero_duration_layers(layers: &[LayerResult]) -> Vec<LayerResult> {
    let mut layers = layers.to_vec();
    for layer in &mut layers {
        layer.duration_ms = 0.0;
    }
    layers
}

fn mark_cache_hit(layers: &mut [LayerResult], lookup_ms: f64, text_len: usize) {
    let Some(index) = layers
        .iter()
        .position(|layer| layer.matched)
        .or_else(|| (!layers.is_empty()).then_some(0))
    else {
        return;
    };
    let layer = &mut layers[index];
    layer.duration_ms = lookup_ms;
    layer
        .details
        .insert("decision_cache_hit".to_string(), serde_json::json!(true));
    layer.details.insert(
        "decision_cache_lookup_ms".to_string(),
        serde_json::json!(lookup_ms),
    );
    layer.details.insert(
        "decision_cache_text_len".to_string(),
        serde_json::json!(text_len),
    );
}

fn estimate_entry_bytes(result: &EvaluationResult, layers: &[LayerResult]) -> usize {
    let mut bytes = 128 + result.class_name.len() + result.level.len();
    for layer in layers {
        bytes += 192
            + layer.level.len()
            + layer.layer_type.len()
            + layer.class_name.len()
            + serde_json::to_string(&layer.thresholds)
                .map(|value| value.len())
                .unwrap_or(0)
            + serde_json::to_string(&layer.details)
                .map(|value| value.len())
                .unwrap_or(0);
    }
    bytes
}

fn prune(inner: &mut DecisionCacheInner, config: DecisionCacheConfig, now: Instant) {
    let expired: Vec<_> = inner
        .entries
        .iter()
        .filter_map(|(key, entry)| (entry.expires_at <= now).then_some(*key))
        .collect();
    for key in expired {
        if let Some(entry) = inner.entries.remove(&key) {
            inner.used_bytes = inner.used_bytes.saturating_sub(entry.estimated_bytes);
        }
    }

    if inner.entries.len() <= config.max_entries && inner.used_bytes <= config.max_bytes {
        return;
    }

    let mut victims: Vec<_> = inner
        .entries
        .iter()
        .map(|(key, entry)| (*key, entry.last_access))
        .collect();
    victims.sort_by_key(|(_, last_access)| *last_access);

    for (key, _) in victims {
        if inner.entries.len() <= config.max_entries && inner.used_bytes <= config.max_bytes {
            break;
        }
        if let Some(entry) = inner.entries.remove(&key) {
            inner.used_bytes = inner.used_bytes.saturating_sub(entry.estimated_bytes);
        }
    }
}
