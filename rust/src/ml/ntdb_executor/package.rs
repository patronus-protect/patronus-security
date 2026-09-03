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
    joint_v3_runtime::JointV3Runtime,
    manifest::{parse_package_manifest, PackageManifest},
    ntdb_error, NtdbResult,
};

use crate::ml::tokenizer::{RuntimeTokenizer, TokenChunk, TOKENIZER_FAMILY};

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
    #[serde(skip)]
    pub chunk_class_probabilities: Vec<Vec<f32>>,
    #[serde(skip)]
    pub joint_v3_decision: Option<Arc<JointV3DecisionContext>>,
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
    #[serde(skip)]
    pub class_probabilities: Vec<f32>,
    #[serde(skip)]
    pub joint_v3_decision: Option<Arc<JointV3DecisionContext>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct JointV3DecisionContext {
    pub labels: Vec<String>,
    pub default_class_index: usize,
    pub l2: JointV3CandidatePolicy,
    pub l3: JointV3CandidatePolicy,
    pub union: JointV3CandidatePolicy,
}

#[derive(Debug, Clone, PartialEq)]
pub struct JointV3CandidatePolicy {
    pub aggregation: String,
    pub risk_margin_threshold: f32,
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
    joint_v3: JointV3Runtime,
}

pub struct NtdbMultiPackage {
    packages: Vec<NamedPackage>,
}

struct NamedPackage {
    id: String,
    package: NtdbPackage,
}

pub(super) struct PreparedDocument {
    pub(super) chunks: Arc<Vec<TokenChunk>>,
    pub(super) raw_embeddings: Vec<f32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PreparationKey {
    encoder_ptr: usize,
}

impl NtdbPackage {
    pub fn load(
        package_dir: impl AsRef<Path>,
        encoders: &mut StaticEncoderStore,
    ) -> NtdbResult<Self> {
        let package_dir = package_dir.as_ref().to_path_buf();
        let mut manifest: PackageManifest = parse_package_manifest(
            &fs::read_to_string(package_dir.join("manifest.json")).map_err(|err| {
                ntdb_error(format!(
                    "failed to read NTDB manifest {}: {err}",
                    package_dir.join("manifest.json").display()
                ))
            })?,
        )
        .map_err(|err| ntdb_error(format!("failed to parse NTDB manifest: {err}")))?;
        manifest.validate()?;
        manifest.normalize_runtime_defaults();

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

        let joint_v3 = JointV3Runtime::load(
            &package_dir,
            manifest
                .joint_v3
                .as_ref()
                .ok_or_else(|| ntdb_error("NTDB v4 joint_v3 is required"))?,
        )?;

        Ok(Self {
            manifest,
            tokenizer,
            encoder,
            joint_v3,
        })
    }

    fn score_prepared(
        &mut self,
        model_id: &str,
        prepared: &PreparedDocument,
        operating_point: NtdbOperatingPoint,
    ) -> NtdbResult<Vec<ScoreOutput>> {
        let mut output = self
            .joint_v3
            .score(&self.manifest.task, prepared, operating_point)?;
        populate_joint_v3_chunks(
            model_id,
            &self.manifest,
            prepared,
            &mut output,
            self.manifest.minilm.embedding_dim,
        );
        Ok(vec![output])
    }

    fn score_prepared_batch(
        &mut self,
        model_id: &str,
        prepared: &[Arc<PreparedDocument>],
        operating_point: NtdbOperatingPoint,
    ) -> NtdbResult<Vec<Vec<ScoreOutput>>> {
        let mut outputs =
            self.joint_v3
                .score_batch(&self.manifest.task, prepared, operating_point)?;
        for (document, output) in prepared.iter().zip(&mut outputs) {
            populate_joint_v3_chunks(
                model_id,
                &self.manifest,
                document,
                output,
                self.manifest.minilm.embedding_dim,
            );
        }
        Ok(outputs.into_iter().map(|output| vec![output]).collect())
    }

    fn preparation_key(&self) -> PreparationKey {
        PreparationKey {
            encoder_ptr: Arc::as_ptr(&self.encoder) as usize,
        }
    }

    fn prepare_document(&self, chunks: Arc<Vec<TokenChunk>>) -> NtdbResult<PreparedDocument> {
        let raw_embeddings = self.embed_chunks(&chunks)?;
        Ok(PreparedDocument {
            chunks,
            raw_embeddings,
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
        let fingerprint = packages[0].package.tokenizer.0.fingerprint;
        if packages
            .iter()
            .any(|entry| entry.package.tokenizer.0.fingerprint != fingerprint)
        {
            return Err(ntdb_error(
                "NTDB v4 packages must share the same compact mmBERT tokenizer",
            ));
        }
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
            .map(|_| vec!["joint_v3".to_string()])
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
                        prepared.as_ref(),
                        operating_point,
                    )?,
                })
            })
            .collect()
    }

    pub fn score_all_models_batch(
        &mut self,
        texts: &[String],
        operating_point: NtdbOperatingPoint,
    ) -> NtdbResult<Vec<Vec<MultiScoreOutput>>> {
        let prepared = texts
            .iter()
            .map(|text| self.shared_prepared_documents(text, None))
            .collect::<NtdbResult<Vec<_>>>()?;
        let mut result = (0..texts.len()).map(|_| Vec::new()).collect::<Vec<_>>();
        for entry in &mut self.packages {
            let key = entry.package.preparation_key();
            let documents = prepared
                .iter()
                .map(|items| Arc::clone(&items[&key]))
                .collect::<Vec<_>>();
            let outputs =
                entry
                    .package
                    .score_prepared_batch(&entry.id, &documents, operating_point)?;
            for (target, outputs) in result.iter_mut().zip(outputs) {
                target.push(MultiScoreOutput {
                    model_id: entry.id.clone(),
                    outputs,
                });
            }
        }
        Ok(result)
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
        let Some(first) = self
            .packages
            .iter()
            .find(|entry| requested.is_none_or(|ids| ids.contains(&entry.id)))
        else {
            return Ok(prepared);
        };
        let chunks = Arc::new(first.package.tokenizer.token_chunks(text));
        for entry in self
            .packages
            .iter()
            .filter(|entry| requested.is_none_or(|requested| requested.contains(&entry.id)))
        {
            let key = entry.package.preparation_key();
            if prepared.contains_key(&key) {
                continue;
            }
            let mut metrics = PhaseMetricScope::new(
                "ntdb_shared_prepare",
                format!("model_id={} text_bytes={}", entry.id, text.len()),
            );
            prepared.insert(
                key,
                Arc::new(entry.package.prepare_document(Arc::clone(&chunks))?),
            );
            metrics.checkpoint("after_prepare_document", format!("model_id={}", entry.id));
        }
        Ok(prepared)
    }
}

fn populate_joint_v3_chunks(
    model_id: &str,
    manifest: &PackageManifest,
    prepared: &PreparedDocument,
    output: &mut ScoreOutput,
    embedding_dim: usize,
) {
    let threshold = output.promote_threshold.unwrap_or(f32::INFINITY);
    let scores = &output.chunk_promote_scores;
    let promoted = scores
        .iter()
        .enumerate()
        .filter_map(|(index, score)| {
            score
                .filter(|score| *score >= threshold)
                .map(|score| (index, score))
        })
        .collect::<Vec<_>>();
    output.l3_candidate_spans = promoted
        .iter()
        .map(|(index, _)| chunk_span(&prepared.chunks[*index]))
        .collect();
    output.l3_candidates = promoted
        .iter()
        .map(|(index, score)| L3Candidate {
            span: chunk_span(&prepared.chunks[*index]),
            promote_score: *score,
            promote_threshold: threshold,
            source_pipeline: String::new(),
            source_model: model_id.to_string(),
            l2_class: output.predicted_label.clone(),
        })
        .collect();
    let chunk_class_probabilities = std::mem::take(&mut output.chunk_class_probabilities);
    let joint_v3_decision = output.joint_v3_decision.clone();
    output.l2_chunk_outputs = prepared
        .chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| {
            let mut embedding = prepared.raw_embeddings
                [index * embedding_dim..(index + 1) * embedding_dim]
                .to_vec();
            normalize_embedding(&mut embedding);
            let score = scores.get(index).copied().flatten();
            let class_probabilities = chunk_class_probabilities
                .get(index)
                .cloned()
                .unwrap_or_default();
            let (class_name, confidence) = class_probabilities
                .iter()
                .enumerate()
                .max_by(|left, right| left.1.total_cmp(right.1))
                .map(|(selected, confidence)| {
                    (
                        output
                            .labels
                            .get(selected)
                            .cloned()
                            .unwrap_or_else(|| selected.to_string()),
                        *confidence,
                    )
                })
                .unwrap_or_else(|| {
                    (
                        output.predicted_label.clone(),
                        output
                            .class_scores
                            .get(output.predicted_index)
                            .copied()
                            .unwrap_or_default(),
                    )
                });
            L2ChunkOutput {
                span: chunk_span(chunk),
                class_name,
                confidence,
                promoted: score.is_some_and(|score| score >= threshold),
                promote_score: score,
                promote_threshold: Some(threshold),
                source_pipeline: String::new(),
                source_model: model_id.to_string(),
                embedding,
                embedding_space: manifest
                    .minilm
                    .shared_embedder_identity()
                    .unwrap_or("unknown-l2-encoder")
                    .to_string(),
                token_ids: chunk.token_ids.clone(),
                tokenizer_family: TOKENIZER_FAMILY.to_string(),
                class_probabilities,
                joint_v3_decision: joint_v3_decision.clone(),
            }
        })
        .collect();
}

fn chunk_span(chunk: &TokenChunk) -> ByteSpan {
    ByteSpan {
        start: chunk.byte_span.0,
        end: chunk.byte_span.1,
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

/// Exercise the production token-to-L2-output materialization with supplied
/// promotion scores, without loading either L2 or L3 inference sessions.
#[cfg(test)]
pub(crate) fn token_outputs_for_test(chunks: Vec<TokenChunk>, promote: &[bool]) -> ScoreOutput {
    let mut manifest =
        parse_package_manifest(include_str!("../../../tests/fixtures/ntdb_v4.json")).unwrap();
    manifest.validate().unwrap();
    manifest.normalize_runtime_defaults();
    let prepared = PreparedDocument {
        raw_embeddings: vec![0.0; chunks.len() * manifest.minilm.embedding_dim],
        chunks: Arc::new(chunks),
    };
    let mut output = ScoreOutput {
        aggregator_id: "joint_v3".to_string(),
        task: "binary".to_string(),
        labels: vec!["benign".to_string(), "attack".to_string()],
        predicted_label: "attack".to_string(),
        predicted_index: 1,
        class_scores: vec![0.1, 0.9],
        class_logits: Vec::new(),
        chunks: prepared.chunks.len(),
        attack_threshold: None,
        promote_score: Some(0.9),
        promote_threshold: Some(0.5),
        chunk_promote_scores: promote
            .iter()
            .map(|promote| Some(if *promote { 0.9 } else { 0.1 }))
            .collect(),
        l3_candidate_spans: Vec::new(),
        l3_candidates: Vec::new(),
        l2_chunk_outputs: Vec::new(),
        chunk_class_probabilities: vec![vec![0.1, 0.9]; prepared.chunks.len()],
        joint_v3_decision: None,
    };
    populate_joint_v3_chunks(
        "injection_current",
        &manifest,
        &prepared,
        &mut output,
        manifest.minilm.embedding_dim,
    );
    output
}
