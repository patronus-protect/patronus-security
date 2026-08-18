// SPDX-License-Identifier: GPL-3.0-only
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{diagnostics::PhaseMetricScope, NtdbOperatingPoint};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use super::{
    encoder::{StaticEncoder, StaticEncoderStore},
    heuristics::{
        local_text_heuristics, shared_global_text_heuristics_from_token_stats,
        SharedGlobalTextHeuristics, TokenIdStats,
    },
    manifest::PackageManifest,
    ntdb_error,
    runtime::{AggregatorRuntime, HeadRuntime},
    tokenizer::RuntimeTokenizer,
    NtdbResult,
};

const LOCAL_FEATURE_COUNT: usize = 11;

#[derive(Debug, Serialize)]
pub struct ScoreOutput {
    pub aggregator_id: String,
    pub task: String,
    pub labels: Vec<String>,
    pub predicted_label: String,
    pub predicted_index: usize,
    pub class_scores: Vec<f32>,
    pub class_logits: Vec<f32>,
    pub chunks: usize,
    pub attack_threshold: Option<f32>,
    pub promote_score: Option<f32>,
    pub promote_threshold: Option<f32>,
    pub chunk_promote_scores: Vec<Option<f32>>,
    pub l3_candidate_spans: Vec<ByteSpan>,
    pub l3_candidates: Vec<L3Candidate>,
    pub l2_chunk_outputs: Vec<L2ChunkOutput>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub struct ByteSpan {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
/// Scored L2 evidence used to select and prioritize L3 text windows.
pub struct L3Candidate {
    pub span: ByteSpan,
    pub promote_score: f32,
    pub promote_threshold: f32,
    pub source_pipeline: String,
    pub source_model: String,
    pub l2_class: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
/// Per-chunk L2 output retained so promoted L3 documents can aggregate with
/// non-promoted L2 chunk decisions.
pub struct L2ChunkOutput {
    pub span: ByteSpan,
    pub class_name: String,
    pub confidence: f32,
    pub promoted: bool,
    pub promote_score: Option<f32>,
    pub promote_threshold: Option<f32>,
    pub source_pipeline: String,
    pub source_model: String,
    /// Internal L2 vector reused by L3 scheduling. It is removed from the
    /// externally published L2 result after the L3 job has been created.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub embedding: Vec<f32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub embedding_space: String,
    /// Pre-computed token IDs from L2 chunk tokenization passed to L3 to eliminate
    /// redundant re-tokenization.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub token_ids: Vec<u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tokenizer_family: String,
}

#[derive(Debug, Serialize)]
pub struct MultiScoreOutput {
    pub model_id: String,
    pub outputs: Vec<ScoreOutput>,
}

#[derive(Debug, Clone)]
pub struct NtdbPackageSpec {
    pub id: String,
    pub package_dir: PathBuf,
}

impl NtdbPackageSpec {
    pub fn new(id: impl Into<String>, package_dir: impl Into<PathBuf>) -> Self {
        Self {
            id: id.into(),
            package_dir: package_dir.into(),
        }
    }
}

pub struct NtdbPackage {
    manifest: PackageManifest,
    tokenizer: RuntimeTokenizer,
    encoder: Arc<StaticEncoder>,
    heads: Vec<HeadRuntime>,
    aggregators: Vec<AggregatorRuntime>,
}

pub struct NtdbMultiPackage {
    packages: Vec<NamedPackage>,
}

struct NamedPackage {
    id: String,
    package: NtdbPackage,
}

pub(super) struct PreparedDocument {
    pub(super) chunks: Vec<TokenChunk>,
    pub(super) chunk_width: usize,
    pub(super) raw_embeddings: Vec<f32>,
    pub(super) local_features: Vec<f32>,
    pub(super) global_text_features: SharedGlobalTextHeuristics,
}

pub(super) struct TokenChunk {
    pub(super) token_ids: Vec<u32>,
    pub(super) byte_span: ByteSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PreparationKey {
    tokenizer_dir: String,
    tokenizer_family: Option<String>,
    vocab_size: usize,
    embedding_dim: usize,
    content_tokens_per_chunk: usize,
    encoder_ptr: usize,
    local_feature_order: Vec<String>,
}

impl NtdbPackage {
    pub fn load(
        package_dir: impl AsRef<Path>,
        encoders: &mut StaticEncoderStore,
    ) -> NtdbResult<Self> {
        let package_dir = package_dir.as_ref().to_path_buf();
        let mut manifest: PackageManifest = serde_json::from_str(
            &fs::read_to_string(package_dir.join("manifest.json")).map_err(|err| {
                ntdb_error(format!(
                    "failed to read NTDB manifest {}: {err}",
                    package_dir.join("manifest.json").display()
                ))
            })?,
        )
        .map_err(|err| ntdb_error(format!("failed to parse NTDB manifest: {err}")))?;
        manifest.normalize_runtime_defaults();
        manifest.validate()?;

        let tokenizer = RuntimeTokenizer::load(package_dir.join(&manifest.tokenizer_dir))?;

        let encoder = encoders.load_for_package(&package_dir, &manifest)?;
        if encoder.vocab_size() != manifest.minilm.vocab_size {
            return Err(ntdb_error(
                "NTDB encoder vocab size does not match manifest",
            ));
        }
        if encoder.embedding_dim() != manifest.minilm.embedding_dim {
            return Err(ntdb_error(
                "NTDB encoder embedding dim does not match manifest",
            ));
        }

        let heads = manifest
            .heads
            .iter()
            .map(|head| HeadRuntime::load(&package_dir, head))
            .collect::<NtdbResult<Vec<_>>>()?;
        let aggregators = manifest
            .aggregators
            .iter()
            .map(|aggregator| AggregatorRuntime::load(&package_dir, aggregator))
            .collect::<NtdbResult<Vec<_>>>()?;

        Ok(Self {
            manifest,
            tokenizer,
            encoder,
            heads,
            aggregators,
        })
    }

    fn score_prepared(
        &mut self,
        model_id: &str,
        text: &str,
        prepared: &PreparedDocument,
        operating_point: NtdbOperatingPoint,
    ) -> NtdbResult<Vec<ScoreOutput>> {
        let chunk_count = prepared.chunks.len();
        let embedding_dim = self.manifest.minilm.embedding_dim;
        let mut metrics = PhaseMetricScope::new(
            "ntdb_score_prepared",
            format!("model_id={model_id} chunks={chunk_count} embedding_dim={embedding_dim}"),
        );

        let per_head = self
            .heads
            .par_iter_mut()
            .map(|head| head.score(&prepared, chunk_count, embedding_dim))
            .collect::<NtdbResult<Vec<_>>>()?;
        metrics.checkpoint("after_heads", "");
        let mut feature_by_name: HashMap<String, Vec<f32>> = HashMap::new();
        for (head, scores) in self.heads.iter().zip(per_head.into_iter()) {
            let names = head.output_feature_names();
            if scores.len() != chunk_count || scores.first().map_or(0, Vec::len) != names.len() {
                return Err(ntdb_error(format!(
                    "NTDB head {} produced a shape that does not match its manifest",
                    head.id
                )));
            }
            for (feature_index, name) in names.into_iter().enumerate() {
                feature_by_name.insert(
                    name,
                    scores
                        .iter()
                        .map(|row| row[feature_index])
                        .collect::<Vec<_>>(),
                );
            }
        }
        metrics.checkpoint(
            "after_head_features",
            format!("features={}", feature_by_name.len()),
        );
        for chunk_index in 0..chunk_count {
            for (local_index, name) in self
                .manifest
                .feature_contract
                .local_feature_order
                .iter()
                .enumerate()
            {
                if local_index >= LOCAL_FEATURE_COUNT {
                    return Err(ntdb_error(format!(
                        "NTDB local feature index {local_index} exceeds runtime feature count"
                    )));
                }
                feature_by_name
                    .entry(name.clone())
                    .or_insert_with(|| vec![0.0; chunk_count])[chunk_index] =
                    prepared.local_features[chunk_index * LOCAL_FEATURE_COUNT + local_index];
            }
        }
        metrics.checkpoint(
            "after_local_features",
            format!("features={}", feature_by_name.len()),
        );
        let outputs = self
            .aggregators
            .par_iter_mut()
            .map(|aggregator| {
                let aggregator_id = aggregator.id().to_string();
                let mut aggregator_metrics = PhaseMetricScope::new(
                    "ntdb_aggregator_score",
                    format!(
                        "model_id={model_id} aggregator_id={aggregator_id} chunks={chunk_count}"
                    ),
                );
                let mut output = aggregator.score(
                    &self.manifest.task.kind,
                    &self.manifest.task.labels,
                    text,
                    &prepared,
                    &feature_by_name,
                    operating_point,
                )?;
                aggregator_metrics.checkpoint(
                    "after_score",
                    format!("model_id={model_id} aggregator_id={aggregator_id}"),
                );
                if output
                    .promote_score
                    .zip(output.promote_threshold)
                    .is_some_and(|(score, threshold)| score >= threshold)
                {
                    let (scores, candidates, chunk_outputs) = chunk_promotions(
                        aggregator,
                        &self.manifest.task.kind,
                        &self.manifest.task.labels,
                        text,
                        &prepared,
                        &feature_by_name,
                        embedding_dim,
                        self.manifest
                            .minilm
                            .shared_embedder_identity()
                            .unwrap_or("unknown-l2-encoder"),
                        self.manifest.minilm.is_l3_tokenizer_compatible(),
                        self.manifest.minilm.tokenizer_family.as_deref(),
                        operating_point,
                    )?;
                    output.chunk_promote_scores = scores;
                    output.l3_candidate_spans =
                        candidates.iter().map(|candidate| candidate.span).collect();
                    output.l3_candidates = candidates;
                    output.l2_chunk_outputs = chunk_outputs;
                    aggregator_metrics.checkpoint(
                        "after_chunk_promotions",
                        format!("model_id={model_id} aggregator_id={aggregator_id}"),
                    );
                }
                Ok(output)
            })
            .collect();
        metrics.checkpoint("after_aggregators", "");
        outputs
    }

    fn preparation_key(&self) -> PreparationKey {
        PreparationKey {
            tokenizer_dir: self.manifest.tokenizer_dir.clone(),
            tokenizer_family: self.manifest.minilm.tokenizer_family.clone(),
            vocab_size: self.manifest.minilm.vocab_size,
            embedding_dim: self.manifest.minilm.embedding_dim,
            content_tokens_per_chunk: self.manifest.minilm.content_tokens_per_chunk,
            encoder_ptr: Arc::as_ptr(&self.encoder) as usize,
            local_feature_order: self.manifest.feature_contract.local_feature_order.clone(),
        }
    }

    fn prepare_document(&self, text: &str) -> NtdbResult<PreparedDocument> {
        let mut metrics = PhaseMetricScope::new(
            "ntdb_prepare_document",
            format!("text_bytes={}", text.len()),
        );
        let chunks = self
            .tokenizer
            .encode_token_chunks(text, self.manifest.minilm.content_tokens_per_chunk)?
            .into_iter()
            .map(|chunk| TokenChunk {
                token_ids: chunk.ids,
                byte_span: ByteSpan {
                    start: chunk.byte_span.0,
                    end: chunk.byte_span.1,
                },
            })
            .collect::<Vec<_>>();
        let mut token_stats = TokenIdStats::default();
        for chunk in &chunks {
            token_stats.observe_all(&chunk.token_ids);
        }
        metrics.checkpoint(
            "after_tokenize",
            format!(
                "doc_tokens={} chunks={}",
                chunks
                    .iter()
                    .map(|chunk| chunk.token_ids.len())
                    .sum::<usize>(),
                chunks.len()
            ),
        );
        let global_text_features =
            shared_global_text_heuristics_from_token_stats(text, token_stats);
        metrics.checkpoint("after_global_text_features", "");
        let raw_embeddings = self.embed_chunks(&chunks)?;
        metrics.checkpoint(
            "after_embeddings",
            format!("embedding_values={}", raw_embeddings.len()),
        );
        let local_features = self.local_features(text, &chunks)?;
        metrics.checkpoint(
            "after_local_features",
            format!("feature_values={}", local_features.len()),
        );
        Ok(PreparedDocument {
            chunks,
            chunk_width: self.manifest.minilm.content_tokens_per_chunk,
            raw_embeddings,
            local_features,
            global_text_features,
        })
    }

    fn embed_chunks(&self, chunks: &[TokenChunk]) -> NtdbResult<Vec<f32>> {
        let embedding_dim = self.manifest.minilm.embedding_dim;
        let mut metrics = PhaseMetricScope::new(
            "ntdb_embed_chunks",
            format!("chunks={} embedding_dim={embedding_dim}", chunks.len()),
        );
        let mut output = vec![0.0_f32; chunks.len() * embedding_dim];
        metrics.checkpoint("after_output_alloc", format!("values={}", output.len()));
        output
            .par_chunks_mut(embedding_dim)
            .zip(chunks.par_iter())
            .try_for_each(|(target, chunk)| -> NtdbResult<()> {
                if chunk.token_ids.is_empty() {
                    return Ok(());
                }
                for token_id in &chunk.token_ids {
                    let token_index = *token_id as usize;
                    if token_index >= self.encoder.vocab_size() {
                        return Err(ntdb_error(format!(
                            "token id {token_index} exceeds embedding matrix vocab size"
                        )));
                    }
                    self.encoder.accumulate_token_embedding(token_index, target);
                }
                let denom = chunk.token_ids.len() as f32;
                for value in target {
                    *value /= denom;
                }
                Ok(())
            })?;
        metrics.checkpoint("after_fill", "");
        Ok(output)
    }

    fn local_features(&self, text: &str, chunks: &[TokenChunk]) -> NtdbResult<Vec<f32>> {
        let mut output = Vec::with_capacity(chunks.len() * LOCAL_FEATURE_COUNT);
        for chunk in chunks {
            let chunk_text = text
                .get(chunk.byte_span.start..chunk.byte_span.end)
                .unwrap_or_default();
            output.extend_from_slice(&local_text_heuristics(chunk_text, &chunk.token_ids));
        }
        Ok(output)
    }
}

impl NtdbMultiPackage {
    pub fn load_specs<I>(specs: I) -> NtdbResult<Self>
    where
        I: IntoIterator<Item = NtdbPackageSpec>,
    {
        let specs = specs.into_iter().collect::<Vec<_>>();
        if specs.is_empty() {
            return Err(ntdb_error(
                "NTDB multi package loader requires at least one package",
            ));
        }
        let mut seen = HashSet::new();
        for spec in &specs {
            if spec.id.is_empty() {
                return Err(ntdb_error("NTDB multi package model id must not be empty"));
            }
            if !seen.insert(spec.id.clone()) {
                return Err(ntdb_error(format!(
                    "duplicate NTDB multi package model id: {}",
                    spec.id
                )));
            }
        }
        let mut encoders = StaticEncoderStore::default();
        let packages = specs
            .into_iter()
            .map(|spec| {
                Ok(NamedPackage {
                    id: spec.id,
                    package: NtdbPackage::load(spec.package_dir, &mut encoders)?,
                })
            })
            .collect::<NtdbResult<Vec<_>>>()?;
        Ok(Self { packages })
    }

    pub fn load<I, P>(packages: I) -> NtdbResult<Self>
    where
        I: IntoIterator<Item = (String, P)>,
        P: AsRef<Path>,
    {
        Self::load_specs(
            packages
                .into_iter()
                .map(|(id, path)| NtdbPackageSpec::new(id, path.as_ref())),
        )
    }

    pub fn len(&self) -> usize {
        self.packages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }

    pub fn model_ids(&self) -> impl Iterator<Item = &str> {
        self.packages.iter().map(|entry| entry.id.as_str())
    }

    pub fn model_aggregator_ids(&self, model_id: &str) -> Option<Vec<String>> {
        self.packages
            .iter()
            .find(|entry| entry.id == model_id)
            .map(|entry| {
                entry
                    .package
                    .aggregators
                    .iter()
                    .map(|aggregator| aggregator.id.clone())
                    .collect()
            })
    }

    pub fn score_all_models(
        &mut self,
        text: &str,
        operating_point: NtdbOperatingPoint,
    ) -> NtdbResult<Vec<MultiScoreOutput>> {
        let prepared = self.shared_prepared_documents(text, None)?;
        self.packages
            .par_iter_mut()
            .map(|entry| {
                let key = entry.package.preparation_key();
                let prepared = prepared.get(&key).ok_or_else(|| {
                    ntdb_error(format!(
                        "missing shared NTDB prepared document for model {}",
                        entry.id
                    ))
                })?;
                Ok(MultiScoreOutput {
                    model_id: entry.id.clone(),
                    outputs: entry.package.score_prepared(
                        &entry.id,
                        text,
                        prepared.as_ref(),
                        operating_point,
                    )?,
                })
            })
            .collect()
    }

    pub fn score_models<I, S>(
        &mut self,
        model_ids: I,
        text: &str,
        operating_point: NtdbOperatingPoint,
    ) -> NtdbResult<Vec<MultiScoreOutput>>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut metrics =
            PhaseMetricScope::new("ntdb_score_models", format!("text_bytes={}", text.len()));
        let requested = model_ids
            .into_iter()
            .map(|id| id.as_ref().to_string())
            .collect::<HashSet<_>>();
        if requested.is_empty() {
            return Ok(Vec::new());
        }

        let available = self
            .packages
            .iter()
            .map(|entry| entry.id.clone())
            .collect::<HashSet<_>>();
        let mut missing = requested
            .difference(&available)
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            missing.sort();
            return Err(ntdb_error(format!(
                "NTDB model package(s) not loaded: {}",
                missing.join(", ")
            )));
        }

        let prepared = self.shared_prepared_documents(text, Some(&requested))?;
        metrics.checkpoint(
            "after_shared_prepare",
            format!("prepared_docs={}", prepared.len()),
        );
        let outputs = self
            .packages
            .par_iter_mut()
            .filter(|entry| requested.contains(&entry.id))
            .map(|entry| {
                let key = entry.package.preparation_key();
                let prepared = prepared.get(&key).ok_or_else(|| {
                    ntdb_error(format!(
                        "missing shared NTDB prepared document for model {}",
                        entry.id
                    ))
                })?;
                Ok(MultiScoreOutput {
                    model_id: entry.id.clone(),
                    outputs: entry.package.score_prepared(
                        &entry.id,
                        text,
                        prepared.as_ref(),
                        operating_point,
                    )?,
                })
            })
            .collect();
        metrics.checkpoint("after_score_prepared", "");
        outputs
    }

    fn shared_prepared_documents(
        &self,
        text: &str,
        requested: Option<&HashSet<String>>,
    ) -> NtdbResult<HashMap<PreparationKey, Arc<PreparedDocument>>> {
        let mut prepared = HashMap::new();
        for entry in self
            .packages
            .iter()
            .filter(|entry| requested.map_or(true, |requested| requested.contains(&entry.id)))
        {
            let key = entry.package.preparation_key();
            if prepared.contains_key(&key) {
                continue;
            }
            let mut metrics = PhaseMetricScope::new(
                "ntdb_shared_prepare",
                format!("model_id={} text_bytes={}", entry.id, text.len()),
            );
            prepared.insert(key, Arc::new(entry.package.prepare_document(text)?));
            metrics.checkpoint("after_prepare_document", format!("model_id={}", entry.id));
        }
        Ok(prepared)
    }
}

fn chunk_promotions(
    aggregator: &mut AggregatorRuntime,
    task: &str,
    labels: &[String],
    text: &str,
    prepared: &PreparedDocument,
    feature_by_name: &HashMap<String, Vec<f32>>,
    embedding_dim: usize,
    embedding_space: &str,
    is_l3_tokenizer_compatible: bool,
    tokenizer_family: Option<&str>,
    operating_point: NtdbOperatingPoint,
) -> NtdbResult<(Vec<Option<f32>>, Vec<L3Candidate>, Vec<L2ChunkOutput>)> {
    let mut scores = Vec::with_capacity(prepared.chunks.len());
    let mut thresholds = Vec::with_capacity(prepared.chunks.len());
    let mut chunk_outputs = Vec::with_capacity(prepared.chunks.len());
    for (index, chunk) in prepared.chunks.iter().enumerate() {
        let chunk_prepared = PreparedDocument {
            chunks: vec![TokenChunk {
                token_ids: chunk.token_ids.clone(),
                byte_span: chunk.byte_span,
            }],
            chunk_width: prepared.chunk_width,
            raw_embeddings: prepared.raw_embeddings
                [index * embedding_dim..(index + 1) * embedding_dim]
                .to_vec(),
            local_features: prepared.local_features
                [index * LOCAL_FEATURE_COUNT..(index + 1) * LOCAL_FEATURE_COUNT]
                .to_vec(),
            global_text_features: prepared.global_text_features,
        };
        let chunk_features = feature_by_name
            .iter()
            .map(|(name, values)| (name.clone(), vec![values[index]]))
            .collect::<HashMap<_, _>>();
        let chunk_text = text
            .get(chunk.byte_span.start..chunk.byte_span.end)
            .unwrap_or(text);
        let output = aggregator.score(
            task,
            labels,
            chunk_text,
            &chunk_prepared,
            &chunk_features,
            operating_point,
        )?;
        scores.push(output.promote_score);
        thresholds.push(output.promote_threshold);
        let mut embedding =
            prepared.raw_embeddings[index * embedding_dim..(index + 1) * embedding_dim].to_vec();
        normalize_embedding(&mut embedding);
        let (token_ids, tok_family) = if is_l3_tokenizer_compatible {
            (
                chunk.token_ids.clone(),
                tokenizer_family.unwrap_or("mmbert").to_string(),
            )
        } else {
            (Vec::new(), String::new())
        };
        chunk_outputs.push(l2_chunk_output(
            chunk.byte_span,
            task,
            labels,
            &output,
            embedding,
            embedding_space,
            token_ids,
            tok_family,
        ));
    }
    let candidates = promoted_chunk_candidates(&prepared.chunks, &scores, &thresholds);
    Ok((scores, candidates, chunk_outputs))
}

fn l2_chunk_output(
    span: ByteSpan,
    task: &str,
    labels: &[String],
    output: &ScoreOutput,
    embedding: Vec<f32>,
    embedding_space: &str,
    token_ids: Vec<u32>,
    tokenizer_family: String,
) -> L2ChunkOutput {
    let (class_name, confidence) = if task == "binary_promote"
        || (label_index(labels, "benign").is_some()
            && label_index(labels, "attack").is_some()
            && label_index(labels, "promote").is_some())
    {
        let attack_index = label_index(labels, "attack").unwrap_or(1);
        let attack_score = output
            .class_scores
            .get(attack_index)
            .copied()
            .unwrap_or_default();
        let threshold = output.attack_threshold.unwrap_or(0.5);
        if attack_score >= threshold {
            ("attack".to_string(), attack_score)
        } else {
            ("benign".to_string(), 1.0 - attack_score)
        }
    } else {
        let predicted_index = if output.predicted_label == "promote" {
            best_non_promote_index(labels, &output.class_scores).unwrap_or(output.predicted_index)
        } else {
            output.predicted_index
        };
        let class_name = labels
            .get(predicted_index)
            .cloned()
            .unwrap_or_else(|| output.predicted_label.clone());
        let confidence = output
            .class_scores
            .get(predicted_index)
            .copied()
            .unwrap_or(output.promote_score.unwrap_or_default());
        (class_name, confidence)
    };

    L2ChunkOutput {
        span,
        class_name,
        confidence: confidence.clamp(0.0, 1.0),
        promoted: output
            .promote_score
            .zip(output.promote_threshold)
            .is_some_and(|(score, threshold)| score >= threshold),
        promote_score: output.promote_score,
        promote_threshold: output.promote_threshold,
        source_pipeline: String::new(),
        source_model: String::new(),
        embedding,
        embedding_space: embedding_space.to_string(),
        token_ids,
        tokenizer_family,
    }
}

fn normalize_embedding(embedding: &mut [f32]) {
    let norm = embedding
        .iter()
        .map(|value| f64::from(*value) * f64::from(*value))
        .sum::<f64>()
        .sqrt();
    if norm <= f64::EPSILON {
        return;
    }
    for value in embedding {
        *value = (f64::from(*value) / norm) as f32;
    }
}

fn label_index(labels: &[String], needle: &str) -> Option<usize> {
    labels.iter().position(|label| label == needle)
}

fn best_non_promote_index(labels: &[String], scores: &[f32]) -> Option<usize> {
    scores
        .iter()
        .copied()
        .enumerate()
        .filter(|(index, _)| labels.get(*index).is_some_and(|label| label != "promote"))
        .max_by(|left, right| left.1.total_cmp(&right.1))
        .map(|(index, _)| index)
}

fn promoted_chunk_candidates(
    chunks: &[TokenChunk],
    scores: &[Option<f32>],
    thresholds: &[Option<f32>],
) -> Vec<L3Candidate> {
    chunks
        .iter()
        .zip(scores)
        .zip(thresholds)
        .filter_map(|((chunk, score), threshold)| {
            let (score, threshold) = score.zip(*threshold)?;
            (score >= threshold).then_some(L3Candidate {
                span: chunk.byte_span,
                promote_score: score,
                promote_threshold: threshold,
                source_pipeline: String::new(),
                source_model: String::new(),
                l2_class: String::new(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_chunk_promote_selects_only_scores_at_or_above_threshold() {
        let chunks = vec![
            TokenChunk {
                token_ids: vec![1],
                byte_span: ByteSpan { start: 0, end: 100 },
            },
            TokenChunk {
                token_ids: vec![2],
                byte_span: ByteSpan {
                    start: 100,
                    end: 200,
                },
            },
            TokenChunk {
                token_ids: vec![3],
                byte_span: ByteSpan {
                    start: 200,
                    end: 300,
                },
            },
        ];

        let candidates = promoted_chunk_candidates(
            &chunks,
            &[Some(0.2), Some(0.95), Some(0.8)],
            &[Some(0.8), Some(0.8), Some(0.8)],
        );

        assert_eq!(candidates.len(), 2);
        assert_eq!(
            (candidates[0].span.start, candidates[0].span.end),
            (100, 200)
        );
        assert_eq!(
            (candidates[1].span.start, candidates[1].span.end),
            (200, 300)
        );
        assert_eq!(candidates[0].promote_score, 0.95);
    }
}
