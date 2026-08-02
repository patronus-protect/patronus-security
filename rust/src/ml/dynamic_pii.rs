// SPDX-License-Identifier: GPL-3.0-only
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use regex::Regex;

use crate::{
    cache::PiiChunkCache,
    dynamic_pii::{DynamicPiiConfig, EvidenceSpan},
    gliner_onnx_engine::{Entity, GlinerEngine},
};

use super::onnx::l3_ttl;

pub(crate) struct DynamicPiiRuntime {
    model_dir: PathBuf,
    engine: Option<GlinerEngine>,
    splitter: Regex,
    ttl: Duration,
    last_used: Option<Instant>,
}

pub(crate) struct DynamicPiiOutput {
    pub evidence_spans: Vec<EvidenceSpan>,
    pub duration_ms: f64,
    pub model_path: PathBuf,
    pub chunk_cache_hits: usize,
}

impl DynamicPiiRuntime {
    pub(crate) fn from_path(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let model_dir = path.as_ref().to_path_buf();
        GlinerEngine::validate_path(&model_dir)?;
        Ok(Self {
            model_dir,
            engine: None,
            splitter: Regex::new(r"\w+(?:[-_]\w+)*|\S")?,
            ttl: l3_ttl(),
            last_used: None,
        })
    }

    pub(crate) fn warmup(
        &mut self,
        config: &DynamicPiiConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.initialize_engine()?;
        self.engine
            .as_mut()
            .expect("GLiNER engine was initialized")
            .extract_entity_candidates(
                "Patronus security runtime warmup.",
                &config.possible_inference_labels(),
                config.inference_threshold(),
            )?;
        self.last_used = Some(Instant::now());
        Ok(())
    }

    pub(crate) fn infer_with_callback(
        &mut self,
        text: &str,
        config: &DynamicPiiConfig,
        chunk_cache: Arc<PiiChunkCache>,
        mut on_entity: impl FnMut(&EvidenceSpan),
    ) -> Result<DynamicPiiOutput, Box<dyn std::error::Error>> {
        self.evict_expired();
        if text.len() > config.max_text_bytes {
            return Err(format!(
                "dynamic-pii input has {} bytes; configured maximum is {}",
                text.len(),
                config.max_text_bytes
            )
            .into());
        }
        let started = Instant::now();
        self.initialize_engine()?;
        self.last_used = Some(Instant::now());
        let ranges = chunk_ranges(
            &self.splitter,
            text,
            config.chunk_size_words,
            config.chunk_overlap_words,
        );
        let labels = config.inference_labels();
        let inference_threshold = config.inference_threshold();
        let engine = self.engine.as_mut().expect("GLiNER engine was initialized");
        let mut candidates = Vec::new();
        let mut chunk_cache_hits = 0usize;
        for range in ranges {
            let chunk_text = &text[range.clone()];
            let chunk_entities = if let Some(entities) = chunk_cache.get(
                crate::assets::DYNAMIC_PII_ASSET.revision,
                chunk_text,
                &labels,
                inference_threshold,
            ) {
                chunk_cache_hits += 1;
                entities
            } else {
                let entities =
                    engine.extract_entity_candidates(chunk_text, &labels, inference_threshold)?;
                chunk_cache.put(
                    crate::assets::DYNAMIC_PII_ASSET.revision,
                    chunk_text,
                    &labels,
                    inference_threshold,
                    &entities,
                );
                entities
            };
            for mut entity in chunk_entities {
                let canonical_label = config
                    .canonical_label_for(&entity.label)
                    .ok_or_else(|| format!("GLiNER returned unknown label {:?}", entity.label))?;
                if entity.score < config.threshold_for(canonical_label) {
                    continue;
                }
                entity.label = canonical_label.to_string();
                entity.start_byte += range.start;
                entity.end_byte += range.start;
                entity.start_char = text[..entity.start_byte].chars().count();
                entity.end_char = text[..entity.end_byte].chars().count();
                entity.text = text[entity.start_byte..entity.end_byte].to_string();
                on_entity(&EvidenceSpan {
                    label: entity.label.clone(),
                    text: entity.text.clone(),
                    score: f64::from(entity.score),
                    start_byte: entity.start_byte,
                    end_byte: entity.end_byte,
                    start_char: entity.start_char,
                    end_char: entity.end_char,
                });
                candidates.push(entity);
            }
        }
        let evidence_spans = merge_flat_entities(candidates)
            .into_iter()
            .map(|entity| EvidenceSpan {
                label: entity.label,
                text: entity.text,
                score: f64::from(entity.score),
                start_byte: entity.start_byte,
                end_byte: entity.end_byte,
                start_char: entity.start_char,
                end_char: entity.end_char,
            })
            .collect();
        self.last_used = Some(Instant::now());
        Ok(DynamicPiiOutput {
            evidence_spans,
            duration_ms: started.elapsed().as_secs_f64() * 1_000.0,
            model_path: self.model_dir.clone(),
            chunk_cache_hits,
        })
    }

    fn initialize_engine(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.engine.is_none() {
            self.engine = Some(GlinerEngine::from_path(&self.model_dir)?);
        }
        Ok(())
    }

    pub(crate) fn evict_expired(&mut self) {
        if self
            .last_used
            .is_some_and(|last_used| last_used.elapsed() > self.ttl)
        {
            self.force_unload();
        }
    }

    pub(crate) fn force_unload(&mut self) {
        self.engine = None;
        self.last_used = None;
    }
}

fn chunk_ranges(
    splitter: &Regex,
    text: &str,
    chunk_size: usize,
    overlap: usize,
) -> Vec<std::ops::Range<usize>> {
    let words = splitter
        .find_iter(text)
        .map(|matched| (matched.start(), matched.end()))
        .collect::<Vec<_>>();
    if words.is_empty() {
        return Vec::new();
    }
    let mut ranges = Vec::new();
    let mut start = 0;
    loop {
        let end = (start + chunk_size).min(words.len());
        ranges.push(words[start].0..words[end - 1].1);
        if end == words.len() {
            break;
        }
        start = end - overlap;
    }
    ranges
}

fn merge_flat_entities(mut candidates: Vec<Entity>) -> Vec<Entity> {
    candidates.sort_by(|left, right| right.score.total_cmp(&left.score));
    let mut entities = Vec::new();
    for candidate in candidates {
        let overlaps = entities.iter().any(|selected: &Entity| {
            candidate.start_byte < selected.end_byte && candidate.end_byte > selected.start_byte
        });
        if !overlaps {
            entities.push(candidate);
        }
    }
    entities.sort_by_key(|entity| (entity.start_byte, entity.end_byte));
    entities
}
