use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tokenizers::Tokenizer;

use crate::NtdbOperatingPoint;

use super::{
    encoder::{StaticEncoder, StaticEncoderStore},
    heuristics::local_text_heuristics,
    manifest::PackageManifest,
    ntdb_error,
    runtime::{AggregatorRuntime, HeadRuntime},
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
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct ByteSpan {
    pub start: usize,
    pub end: usize,
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
    tokenizer: Tokenizer,
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
    pub(super) doc_token_ids: Vec<u32>,
}

pub(super) struct TokenChunk {
    pub(super) token_ids: Vec<u32>,
    pub(super) byte_span: ByteSpan,
}

impl NtdbPackage {
    pub fn load(
        package_dir: impl AsRef<Path>,
        encoders: &mut StaticEncoderStore,
    ) -> NtdbResult<Self> {
        let package_dir = package_dir.as_ref().to_path_buf();
        let manifest: PackageManifest = serde_json::from_str(
            &fs::read_to_string(package_dir.join("manifest.json")).map_err(|err| {
                ntdb_error(format!(
                    "failed to read NTDB manifest {}: {err}",
                    package_dir.join("manifest.json").display()
                ))
            })?,
        )
        .map_err(|err| ntdb_error(format!("failed to parse NTDB manifest: {err}")))?;
        manifest.validate()?;

        let tokenizer_path = package_dir
            .join(&manifest.tokenizer_dir)
            .join("tokenizer.json");
        let mut tokenizer = Tokenizer::from_file(&tokenizer_path).map_err(|err| {
            ntdb_error(format!(
                "failed to load NTDB tokenizer {}: {err}",
                tokenizer_path.display()
            ))
        })?;
        tokenizer
            .with_truncation(None)
            .map_err(|err| ntdb_error(format!("failed to disable tokenizer truncation: {err}")))?;
        tokenizer.with_padding(None);

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

    pub fn score_all(
        &mut self,
        text: &str,
        operating_point: NtdbOperatingPoint,
    ) -> NtdbResult<Vec<ScoreOutput>> {
        let prepared = self.prepare_document(text)?;
        let chunk_count = prepared.chunks.len();
        let embedding_dim = self.manifest.minilm.embedding_dim;

        let per_head = self
            .heads
            .par_iter_mut()
            .map(|head| head.score(&prepared, chunk_count, embedding_dim))
            .collect::<NtdbResult<Vec<_>>>()?;
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

        self.aggregators
            .par_iter_mut()
            .map(|aggregator| {
                let mut output = aggregator.score(
                    &self.manifest.task.kind,
                    &self.manifest.task.labels,
                    text,
                    &prepared,
                    &feature_by_name,
                    operating_point,
                )?;
                if output
                    .promote_score
                    .zip(output.promote_threshold)
                    .is_some_and(|(score, threshold)| score >= threshold)
                {
                    let (scores, spans) = chunk_promotions(
                        aggregator,
                        &self.manifest.task.kind,
                        &self.manifest.task.labels,
                        text,
                        &prepared,
                        &feature_by_name,
                        embedding_dim,
                        operating_point,
                    )?;
                    output.chunk_promote_scores = scores;
                    output.l3_candidate_spans = candidate_spans_or_full(spans, text.len());
                }
                Ok(output)
            })
            .collect()
    }

    fn prepare_document(&self, text: &str) -> NtdbResult<PreparedDocument> {
        let encoding = self
            .tokenizer
            .encode(text, false)
            .map_err(|err| ntdb_error(format!("failed to encode NTDB text: {err}")))?;
        let chunks = chunk_token_ids(
            encoding.get_ids(),
            encoding.get_offsets(),
            self.manifest.minilm.content_tokens_per_chunk,
        );
        let raw_embeddings = self.embed_chunks(&chunks)?;
        let local_features = self.local_features(&chunks)?;
        Ok(PreparedDocument {
            chunks,
            chunk_width: self.manifest.minilm.content_tokens_per_chunk,
            raw_embeddings,
            local_features,
            doc_token_ids: encoding.get_ids().to_vec(),
        })
    }

    fn embed_chunks(&self, chunks: &[TokenChunk]) -> NtdbResult<Vec<f32>> {
        let embedding_dim = self.manifest.minilm.embedding_dim;
        let mut output = vec![0.0_f32; chunks.len() * embedding_dim];
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
                    let source_offset = token_index * embedding_dim;
                    target.iter_mut().enumerate().for_each(|(dim, value)| {
                        *value += self.encoder.embedding_matrix()[source_offset + dim];
                    });
                }
                let denom = chunk.token_ids.len() as f32;
                for value in target {
                    *value /= denom;
                }
                Ok(())
            })?;
        Ok(output)
    }

    fn local_features(&self, chunks: &[TokenChunk]) -> NtdbResult<Vec<f32>> {
        let mut output = Vec::with_capacity(chunks.len() * LOCAL_FEATURE_COUNT);
        for chunk in chunks {
            let chunk_text = self
                .tokenizer
                .decode(&chunk.token_ids, true)
                .map_err(|err| ntdb_error(format!("failed to decode NTDB chunk: {err}")))?;
            output.extend_from_slice(&local_text_heuristics(&chunk_text, &chunk.token_ids));
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
        self.packages
            .par_iter_mut()
            .map(|entry| {
                Ok(MultiScoreOutput {
                    model_id: entry.id.clone(),
                    outputs: entry.package.score_all(text, operating_point)?,
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

        self.packages
            .par_iter_mut()
            .filter(|entry| requested.contains(&entry.id))
            .map(|entry| {
                Ok(MultiScoreOutput {
                    model_id: entry.id.clone(),
                    outputs: entry.package.score_all(text, operating_point)?,
                })
            })
            .collect()
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
    operating_point: NtdbOperatingPoint,
) -> NtdbResult<(Vec<Option<f32>>, Vec<ByteSpan>)> {
    let mut scores = Vec::with_capacity(prepared.chunks.len());
    let mut thresholds = Vec::with_capacity(prepared.chunks.len());
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
            doc_token_ids: chunk.token_ids.clone(),
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
    }
    let spans = promoted_chunk_spans(&prepared.chunks, &scores, &thresholds);
    Ok((scores, spans))
}

fn promoted_chunk_spans(
    chunks: &[TokenChunk],
    scores: &[Option<f32>],
    thresholds: &[Option<f32>],
) -> Vec<ByteSpan> {
    chunks
        .iter()
        .zip(scores)
        .zip(thresholds)
        .filter_map(|((chunk, score), threshold)| {
            score
                .zip(*threshold)
                .is_some_and(|(score, threshold)| score >= threshold)
                .then_some(chunk.byte_span)
        })
        .collect()
}

fn chunk_token_ids(
    token_ids: &[u32],
    offsets: &[(usize, usize)],
    chunk_size: usize,
) -> Vec<TokenChunk> {
    if token_ids.is_empty() {
        return vec![TokenChunk {
            token_ids: Vec::new(),
            byte_span: ByteSpan { start: 0, end: 0 },
        }];
    }
    token_ids
        .chunks(chunk_size)
        .zip(offsets.chunks(chunk_size))
        .map(|(ids, chunk_offsets)| TokenChunk {
            token_ids: ids.to_vec(),
            byte_span: byte_span(chunk_offsets),
        })
        .collect()
}

fn byte_span(offsets: &[(usize, usize)]) -> ByteSpan {
    let start = offsets
        .iter()
        .find(|(start, end)| end > start)
        .map(|(start, _)| *start)
        .unwrap_or(0);
    let end = offsets
        .iter()
        .rev()
        .find(|(start, end)| end > start)
        .map(|(_, end)| *end)
        .unwrap_or(start);
    ByteSpan { start, end }
}

fn candidate_spans_or_full(spans: Vec<ByteSpan>, text_len: usize) -> Vec<ByteSpan> {
    if spans.is_empty() {
        vec![ByteSpan {
            start: 0,
            end: text_len,
        }]
    } else {
        spans
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_chunks_keep_byte_spans() {
        let chunks = chunk_token_ids(&[1, 2, 3, 4], &[(0, 2), (3, 5), (6, 8), (9, 11)], 2);

        assert_eq!(chunks.len(), 2);
        assert_eq!((chunks[0].byte_span.start, chunks[0].byte_span.end), (0, 5));
        assert_eq!(
            (chunks[1].byte_span.start, chunks[1].byte_span.end),
            (6, 11)
        );
    }

    #[test]
    fn document_promote_without_chunk_candidates_falls_back_to_full_text() {
        let spans = candidate_spans_or_full(Vec::new(), 8192);

        assert_eq!(spans.len(), 1);
        assert_eq!((spans[0].start, spans[0].end), (0, 8192));
    }

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

        let spans = promoted_chunk_spans(
            &chunks,
            &[Some(0.2), Some(0.95), Some(0.8)],
            &[Some(0.8), Some(0.8), Some(0.8)],
        );

        assert_eq!(spans.len(), 2);
        assert_eq!((spans[0].start, spans[0].end), (100, 200));
        assert_eq!((spans[1].start, spans[1].end), (200, 300));
    }
}
