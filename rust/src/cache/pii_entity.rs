// SPDX-License-Identifier: GPL-3.0-only
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

use regex::{Regex, RegexBuilder};

use crate::{DynamicPiiConfig, EvidenceSpan};

use super::{CacheCoordinator, CacheKey, CacheNamespace, CachedHeadOutput, CachedModelOutput};

const CACHE_SCHEMA_VERSION: u32 = 1;
const CATALOG_SEPARATOR: char = '\0';

pub(crate) struct PiiEntityCache {
    coordinator: Arc<CacheCoordinator>,
    update: Mutex<()>,
}

#[derive(Debug, Clone, PartialEq)]
struct CachedEntity {
    label: String,
    normalized_span: String,
    score: f32,
}

impl PiiEntityCache {
    pub(crate) fn new(coordinator: Arc<CacheCoordinator>) -> Self {
        Self {
            coordinator,
            update: Mutex::new(()),
        }
    }

    pub(crate) fn find(
        &self,
        model_sha: &str,
        text: &str,
        config: &DynamicPiiConfig,
    ) -> Vec<EvidenceSpan> {
        let namespace = CacheNamespace::from_model_sha(CACHE_SCHEMA_VERSION, model_sha);
        let active_labels = config
            .inference_labels()
            .into_iter()
            .filter_map(|label| config.canonical_label_for(&label).map(str::to_string))
            .collect::<HashSet<_>>();
        let mut entities = Vec::new();
        for token in unique_normalized_tokens(text) {
            let key = bucket_key(namespace, &token);
            let Some(lookup) = self.coordinator.lookup_exact(&key) else {
                continue;
            };
            for entity in decode_catalog(&lookup.output) {
                if !active_labels.contains(&entity.label)
                    || entity.score < config.threshold_for(&entity.label)
                {
                    continue;
                }
                entities.extend(find_occurrences(text, &entity));
            }
        }
        select_non_overlapping(entities)
    }

    pub(crate) fn remember(&self, model_sha: &str, spans: &[EvidenceSpan]) {
        let namespace = CacheNamespace::from_model_sha(CACHE_SCHEMA_VERSION, model_sha);
        let mut additions = HashMap::<String, Vec<CachedEntity>>::new();
        for span in spans {
            let normalized_span = normalize_span(&span.text);
            let Some(token) = first_normalized_token(&normalized_span) else {
                continue;
            };
            additions.entry(token).or_default().push(CachedEntity {
                label: span.label.clone(),
                normalized_span,
                score: span.score as f32,
            });
        }

        let _guard = self.update.lock().expect("PII cache update mutex poisoned");
        for (token, new_entities) in additions {
            let key = bucket_key(namespace, &token);
            let mut entities = self
                .coordinator
                .lookup_exact(&key)
                .map(|lookup| decode_catalog(&lookup.output))
                .unwrap_or_default();
            for new_entity in new_entities {
                if let Some(existing) = entities.iter_mut().find(|existing| {
                    existing.label == new_entity.label
                        && existing.normalized_span == new_entity.normalized_span
                }) {
                    existing.score = existing.score.max(new_entity.score);
                } else {
                    entities.push(new_entity);
                }
            }
            let heads = entities.into_iter().map(encode_entity).collect();
            let _ = self.coordinator.put_heads(key, heads);
        }
    }
}

fn bucket_key(namespace: CacheNamespace, first_token: &str) -> CacheKey {
    CacheKey::for_chunk(
        namespace,
        format!("dynamic-pii-entity-v1{CATALOG_SEPARATOR}{first_token}").as_bytes(),
    )
}

fn encode_entity(entity: CachedEntity) -> CachedHeadOutput {
    CachedHeadOutput {
        head: format!(
            "{}{CATALOG_SEPARATOR}{}",
            entity.label, entity.normalized_span
        ),
        logits: vec![entity.score],
    }
}

fn decode_catalog(output: &CachedModelOutput) -> Vec<CachedEntity> {
    if output.schema_version != CACHE_SCHEMA_VERSION {
        return Vec::new();
    }
    output
        .heads
        .iter()
        .filter_map(|head| {
            let (label, normalized_span) = head.head.split_once(CATALOG_SEPARATOR)?;
            let score = *head.logits.first()?;
            (!label.is_empty() && !normalized_span.is_empty() && score.is_finite()).then(|| {
                CachedEntity {
                    label: label.to_string(),
                    normalized_span: normalized_span.to_string(),
                    score,
                }
            })
        })
        .collect()
}

fn normalize_span(span: &str) -> String {
    span.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn token_regex() -> &'static Regex {
    static TOKEN_REGEX: OnceLock<Regex> = OnceLock::new();
    TOKEN_REGEX.get_or_init(|| Regex::new(r"\w+(?:[-_]\w+)*|\S").expect("valid token regex"))
}

fn first_normalized_token(text: &str) -> Option<String> {
    token_regex()
        .find(text)
        .map(|matched| normalize_span(matched.as_str()))
        .filter(|token| !token.is_empty())
}

fn unique_normalized_tokens(text: &str) -> HashSet<String> {
    token_regex()
        .find_iter(text)
        .map(|matched| normalize_span(matched.as_str()))
        .filter(|token| !token.is_empty())
        .collect()
}

fn find_occurrences(text: &str, entity: &CachedEntity) -> Vec<EvidenceSpan> {
    let pattern = entity
        .normalized_span
        .split_whitespace()
        .map(regex::escape)
        .collect::<Vec<_>>()
        .join(r"\s+");
    let Ok(regex) = RegexBuilder::new(&pattern)
        .case_insensitive(true)
        .unicode(true)
        .build()
    else {
        return Vec::new();
    };
    regex
        .find_iter(text)
        .filter(|matched| has_entity_boundaries(text, matched.start(), matched.end()))
        .map(|matched| EvidenceSpan {
            label: entity.label.clone(),
            text: matched.as_str().to_string(),
            score: f64::from(entity.score),
            start_byte: matched.start(),
            end_byte: matched.end(),
            start_char: text[..matched.start()].chars().count(),
            end_char: text[..matched.end()].chars().count(),
        })
        .collect()
}

fn has_entity_boundaries(text: &str, start: usize, end: usize) -> bool {
    let left = text[..start].chars().next_back();
    let right = text[end..].chars().next();
    left.is_none_or(|value| !is_word_char(value)) && right.is_none_or(|value| !is_word_char(value))
}

fn is_word_char(value: char) -> bool {
    value.is_alphanumeric() || value == '_'
}

fn select_non_overlapping(mut spans: Vec<EvidenceSpan>) -> Vec<EvidenceSpan> {
    spans.sort_by(|left, right| {
        right.score.total_cmp(&left.score).then_with(|| {
            (right.end_byte - right.start_byte).cmp(&(left.end_byte - left.start_byte))
        })
    });
    let mut selected = Vec::new();
    for span in spans {
        if selected.iter().all(|existing: &EvidenceSpan| {
            span.end_byte <= existing.start_byte || span.start_byte >= existing.end_byte
        }) {
            selected.push(span);
        }
    }
    selected.sort_by_key(|span| (span.start_byte, span.end_byte));
    selected
}

pub(crate) fn merge_pii_spans(spans: Vec<EvidenceSpan>) -> Vec<EvidenceSpan> {
    select_non_overlapping(spans)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::cache::{
        CacheWriteMode, ExactCacheConfig, MemoryCacheConfig, PersistentCacheConfig,
        WriteBehindConfig,
    };

    fn config() -> DynamicPiiConfig {
        DynamicPiiConfig {
            labels: vec!["person".to_string(), "organization".to_string()],
            threshold: 0.5,
            ..DynamicPiiConfig::default()
        }
        .validated()
        .unwrap()
    }

    fn span(label: &str, text: &str, score: f64) -> EvidenceSpan {
        EvidenceSpan {
            label: label.to_string(),
            text: text.to_string(),
            score,
            start_byte: 0,
            end_byte: text.len(),
            start_char: 0,
            end_char: text.chars().count(),
        }
    }

    fn temp_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("patronus-pii-{name}-{unique}.redb"))
    }

    #[test]
    fn remembered_entity_matches_new_occurrences_with_current_offsets() {
        let coordinator =
            Arc::new(CacheCoordinator::from_config(ExactCacheConfig::default()).unwrap());
        let cache = PiiEntityCache::new(coordinator);
        cache.remember("model-sha", &[span("person", "Alexandr Stone", 0.96)]);

        let text = "Der Name ist ALEXANDR   STONE.";
        let hits = cache.find("model-sha", text, &config());

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].label, "person");
        assert_eq!(hits[0].text, "ALEXANDR   STONE");
        assert_eq!(&text[hits[0].start_byte..hits[0].end_byte], hits[0].text);
    }

    #[test]
    fn model_sha_label_threshold_and_word_boundaries_are_enforced() {
        let coordinator =
            Arc::new(CacheCoordinator::from_config(ExactCacheConfig::default()).unwrap());
        let cache = PiiEntityCache::new(coordinator);
        cache.remember("model-a", &[span("person", "Ann", 0.8)]);

        assert!(cache.find("model-b", "Ann", &config()).is_empty());
        assert!(cache.find("model-a", "Joann", &config()).is_empty());

        let mut strict = config();
        strict.label_thresholds.insert("person".to_string(), 0.9);
        assert!(cache.find("model-a", "Ann", &strict).is_empty());
        assert_eq!(cache.find("model-a", "Ann", &config()).len(), 1);
    }

    #[test]
    fn entity_catalog_survives_persistent_cache_reopen() {
        let path = temp_path("restart");
        let persistent_config = || ExactCacheConfig {
            memory: MemoryCacheConfig::default(),
            persistent: Some(PersistentCacheConfig {
                storage_location: path.clone(),
                write_mode: CacheWriteMode::WriteThrough,
                write_behind: WriteBehindConfig::default(),
            }),
            entry_ttl: Duration::from_secs(60),
        };
        {
            let coordinator = Arc::new(CacheCoordinator::from_config(persistent_config()).unwrap());
            let cache = PiiEntityCache::new(Arc::clone(&coordinator));
            cache.remember("model-sha", &[span("person", "Alexandr Stone", 0.96)]);
            coordinator.flush().unwrap();
        }
        {
            let coordinator = Arc::new(CacheCoordinator::from_config(persistent_config()).unwrap());
            let cache = PiiEntityCache::new(coordinator);
            assert_eq!(
                cache
                    .find("model-sha", "Hallo Alexandr Stone", &config())
                    .len(),
                1
            );
        }
        std::fs::remove_file(path).unwrap();
    }
}
