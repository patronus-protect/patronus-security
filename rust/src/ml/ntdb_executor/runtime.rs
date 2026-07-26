// SPDX-License-Identifier: GPL-3.0-only
//! Per-head and per-aggregator ONNX runtimes for an NTDB package.

use std::{collections::HashMap, fs, path::Path};

use ort::{
    inputs,
    session::Session,
    value::{TensorRef, ValueType},
};
use serde::Deserialize;

use crate::NtdbOperatingPoint;

use super::{
    heuristics::global_text_heuristics,
    lightgbm::LightGbmModel,
    manifest::{AggregatorManifest, HeadManifest, MetricSweepManifest, PromoteRouterManifest},
    ntdb_error,
    package::{PreparedDocument, ScoreOutput, TokenChunk},
    NtdbResult,
};

pub(super) struct HeadRuntime {
    pub(super) id: String,
    kind: String,
    task_labels: Vec<String>,
    feature_order: Vec<String>,
    lightgbm: Option<LightGbmModel>,
    logistic: Option<LogisticRegression>,
    centroids: Option<BinaryCentroids>,
    textcnn: Option<Session>,
    projection: Option<Session>,
    ntdb: Session,
}

pub(super) struct AggregatorRuntime {
    pub(super) id: String,
    kind: String,
    input_feature_order: Vec<String>,
    global_feature_order: Vec<String>,
    thresholds: HashMap<String, RoutingThresholds>,
    session: Session,
    promote_router: Option<PromoteRouterRuntime>,
}

struct PromoteRouterRuntime {
    input_feature_order: Vec<String>,
    global_feature_order: Vec<String>,
    session: Session,
}

#[derive(Default, Clone, Copy)]
struct RoutingThresholds {
    attack_threshold: Option<f32>,
    promote_threshold: Option<f32>,
}

#[derive(Debug, Deserialize)]
struct LogisticRegression {
    coef: Vec<Vec<f32>>,
    intercept: Vec<f32>,
    classes: Vec<i64>,
}

#[derive(Debug, Deserialize)]
struct BinaryCentroids {
    attack_centroid: Vec<f32>,
    benign_centroid: Vec<f32>,
}

impl HeadRuntime {
    pub(super) fn load(package_dir: &Path, manifest: &HeadManifest) -> NtdbResult<Self> {
        let mut lightgbm = None;
        let mut logistic = None;
        let mut centroids = None;
        let mut textcnn = None;
        for component in &manifest.static_components {
            match component.kind.as_str() {
                "lightgbm" => {
                    lightgbm = Some(LightGbmModel::load(package_dir.join(&component.path))?)
                }
                "logistic_regression" => {
                    logistic = Some(serde_json::from_str(
                        &fs::read_to_string(package_dir.join(&component.path)).map_err(|err| {
                            ntdb_error(format!(
                                "failed to read NTDB logistic regression {}: {err}",
                                component.path
                            ))
                        })?,
                    )?)
                }
                "textcnn_1d" => {
                    textcnn = Some(load_single_thread_session(
                        package_dir.join(&component.path),
                    )?);
                }
                "centroid_cosine" => {
                    centroids = Some(serde_json::from_str(
                        &fs::read_to_string(package_dir.join(&component.path)).map_err(|err| {
                            ntdb_error(format!(
                                "failed to read NTDB centroid component {}: {err}",
                                component.path
                            ))
                        })?,
                    )?)
                }
                other => {
                    return Err(ntdb_error(format!(
                        "unsupported NTDB static component: {other}"
                    )))
                }
            }
        }
        let projection = manifest
            .projection_onnx
            .as_ref()
            .map(|path| load_single_thread_session(package_dir.join(path)))
            .transpose()?;
        Ok(Self {
            id: manifest.id.clone(),
            kind: manifest.kind.clone(),
            task_labels: manifest.task.labels.clone(),
            feature_order: manifest.feature_order.clone(),
            lightgbm,
            logistic,
            centroids,
            textcnn,
            projection,
            ntdb: load_single_thread_session(package_dir.join(&manifest.ntdb_head_onnx))?,
        })
    }

    pub(super) fn output_feature_names(&self) -> Vec<String> {
        if self.kind == "multiclass_attention" {
            self.task_labels
                .iter()
                .map(|label| format!("{}:{label}", self.id))
                .collect()
        } else {
            vec![self.id.clone()]
        }
    }

    pub(super) fn score(
        &mut self,
        prepared: &PreparedDocument,
        chunk_count: usize,
        embedding_dim: usize,
    ) -> NtdbResult<Vec<Vec<f32>>> {
        let available = self.static_feature_map(prepared, chunk_count, embedding_dim)?;
        let mut composite = Vec::new();
        for chunk_index in 0..chunk_count {
            for name in &self.feature_order {
                if name == "raw_embedding" || name == "raw_embedding_384" {
                    let start = chunk_index * embedding_dim;
                    composite
                        .extend_from_slice(&prepared.raw_embeddings[start..start + embedding_dim]);
                } else if name == "projection_64" {
                    let values = available.get(name).ok_or_else(|| {
                        ntdb_error(format!("missing static feature {name} for {}", self.id))
                    })?;
                    let start = chunk_index * 64;
                    composite.extend_from_slice(&values[start..start + 64]);
                } else {
                    let values = available.get(name).ok_or_else(|| {
                        ntdb_error(format!("missing static feature {name} for {}", self.id))
                    })?;
                    composite.push(values[chunk_index]);
                }
            }
        }
        let feature_dim = composite.len() / chunk_count;
        let outputs = self.ntdb.run(inputs! {
            "features" => TensorRef::from_array_view(([1usize, chunk_count, feature_dim], &composite[..]))?
        })?;
        if self.kind == "multiclass_attention" {
            let scores = tensor_values(&outputs, "step_class_scores")?;
            let class_count = self.task_labels.len();
            if scores.len() < chunk_count * class_count {
                return Err(ntdb_error("NTDB step_class_scores output is too small"));
            }
            Ok((0..chunk_count)
                .map(|chunk_index| {
                    (0..class_count)
                        .map(|class_index| scores[chunk_index * class_count + class_index])
                        .collect()
                })
                .collect())
        } else {
            let scores = tensor_values(&outputs, "step_scores")?;
            if scores.len() < chunk_count {
                return Err(ntdb_error("NTDB step_scores output is too small"));
            }
            Ok((0..chunk_count)
                .map(|chunk_index| vec![scores[chunk_index]])
                .collect())
        }
    }

    fn static_feature_map(
        &mut self,
        prepared: &PreparedDocument,
        chunk_count: usize,
        embedding_dim: usize,
    ) -> NtdbResult<HashMap<String, Vec<f32>>> {
        let mut map = HashMap::new();
        if let Some(model) = &self.lightgbm {
            let mut per_class = vec![
                Vec::with_capacity(chunk_count);
                model.predict_probabilities(&vec![0.0; embedding_dim]).len()
            ];
            for chunk in prepared.raw_embeddings.chunks_exact(embedding_dim) {
                let probs = model.predict_probabilities(chunk);
                for (index, prob) in probs.into_iter().enumerate() {
                    per_class[index].push(prob);
                }
            }
            if self.kind == "multiclass_attention" {
                for (label, values) in self.task_labels.iter().zip(per_class.into_iter()) {
                    map.insert(format!("p_lgb_{label}"), values);
                }
            } else {
                map.insert(
                    "p_lgb".to_string(),
                    per_class.into_iter().nth(1).unwrap_or_default(),
                );
            }
        }
        if let Some(model) = &self.logistic {
            let mut per_class = vec![Vec::with_capacity(chunk_count); model.output_dim()];
            for chunk in prepared.raw_embeddings.chunks_exact(embedding_dim) {
                let probs = model.predict_probabilities(chunk);
                for (index, prob) in probs.into_iter().enumerate() {
                    per_class[index].push(prob);
                }
            }
            if self.kind == "multiclass_attention" {
                for (label, values) in self.task_labels.iter().zip(per_class.into_iter()) {
                    map.insert(format!("p_lr_{label}"), values);
                }
            } else {
                map.insert(
                    "p_lr".to_string(),
                    per_class.into_iter().nth(1).unwrap_or_default(),
                );
            }
        }
        if let Some(centroids) = &self.centroids {
            let mut attack = Vec::with_capacity(chunk_count);
            let mut benign = Vec::with_capacity(chunk_count);
            for chunk in prepared.raw_embeddings.chunks_exact(embedding_dim) {
                attack.push(unit_left_dot(chunk, &centroids.attack_centroid));
                benign.push(unit_left_dot(chunk, &centroids.benign_centroid));
            }
            map.insert("s_attack_centroid".to_string(), attack);
            map.insert("s_benign_centroid".to_string(), benign);
        }
        if let Some(session) = &mut self.textcnn {
            let (token_ids, token_lengths, max_len) =
                token_arrays(&prepared.chunks, prepared.chunk_width);
            let outputs = session.run(inputs! {
                "token_ids" => TensorRef::from_array_view(([chunk_count, max_len], &token_ids[..]))?,
                "token_lengths" => TensorRef::from_array_view(([chunk_count], &token_lengths[..]))?
            })?;
            let scores = tensor_values(&outputs, "class_scores")?;
            let class_count = self.task_labels.len();
            if scores.len() < chunk_count * class_count {
                return Err(ntdb_error("NTDB textcnn class_scores output is too small"));
            }
            for (label_index, label) in self.task_labels.iter().enumerate() {
                map.insert(
                    format!("p_textcnn_{label}"),
                    (0..chunk_count)
                        .map(|chunk_index| scores[chunk_index * class_count + label_index])
                        .collect(),
                );
            }
        }
        if let Some(session) = &mut self.projection {
            let outputs = session.run(inputs! {
                "raw_embeddings" => TensorRef::from_array_view(([chunk_count, embedding_dim], &prepared.raw_embeddings[..]))?
            })?;
            let projection = tensor_values(&outputs, "projection")?;
            if projection.len() < chunk_count * 64 {
                return Err(ntdb_error("NTDB projection output is too small"));
            }
            map.insert(
                "projection_64".to_string(),
                projection[..chunk_count * 64].to_vec(),
            );
        }
        Ok(map)
    }
}

impl AggregatorRuntime {
    pub(super) fn load(package_dir: &Path, manifest: &AggregatorManifest) -> NtdbResult<Self> {
        let session = load_single_thread_session(package_dir.join(&manifest.onnx))?;
        validate_session_feature_dim(
            &session,
            &manifest.id,
            "features",
            manifest.input_feature_order.len(),
        )?;
        validate_session_feature_dim(
            &session,
            &manifest.id,
            "global_features",
            manifest.global_feature_order.len(),
        )?;
        let promote_router = manifest
            .promote_router
            .as_ref()
            .map(|router| PromoteRouterRuntime::load(package_dir, &manifest.id, router))
            .transpose()?;
        Ok(Self {
            id: manifest.id.clone(),
            kind: manifest.kind.clone(),
            input_feature_order: manifest.input_feature_order.clone(),
            global_feature_order: manifest.global_feature_order.clone(),
            thresholds: routing_thresholds(manifest.metric_sweep.as_ref()),
            session,
            promote_router,
        })
    }

    pub(super) fn score(
        &mut self,
        task: &str,
        labels: &[String],
        text: &str,
        prepared: &PreparedDocument,
        feature_by_name: &HashMap<String, Vec<f32>>,
        operating_point: NtdbOperatingPoint,
    ) -> NtdbResult<ScoreOutput> {
        let thresholds = self.thresholds(operating_point)?;
        let chunk_count = prepared.chunks.len();
        let (sequence_features, global) = build_sequence_and_global_features(
            text,
            prepared,
            feature_by_name,
            &self.input_feature_order,
            &self.global_feature_order,
        )?;
        let feature_dim = self.input_feature_order.len();
        let outputs = self.session.run(inputs! {
            "features" => TensorRef::from_array_view(([1usize, chunk_count, feature_dim], &sequence_features[..]))?,
            "global_features" => TensorRef::from_array_view(([1usize, global.len()], &global[..]))?
        })?;
        if self.kind == "binary_promote_router" || outputs.contains_key("attack_score") {
            let attack_score = first_output(&outputs, "attack_score")?;
            let attack_logit = first_output(&outputs, "attack_logit")?;
            let promote = if let Some(router) = &mut self.promote_router {
                Some(router.score(text, prepared, feature_by_name)?)
            } else {
                optional_first_output(&outputs, "promote_score")?
                    .zip(optional_first_output(&outputs, "promote_logit")?)
            };
            let promote_score = promote.map(|(score, _)| score);
            let promote_logit = promote.map(|(_, logit)| logit);
            let benign_score =
                (1.0 - attack_score.max(promote_score.unwrap_or(0.0))).clamp(0.0, 1.0);
            let mut class_scores = Vec::with_capacity(labels.len());
            let mut class_logits = Vec::with_capacity(labels.len());
            for label in labels {
                match label.as_str() {
                    "benign" => {
                        class_scores.push(benign_score);
                        class_logits.push(0.0);
                    }
                    "attack" => {
                        class_scores.push(attack_score);
                        class_logits.push(attack_logit);
                    }
                    "promote" => {
                        class_scores.push(promote_score.ok_or_else(|| {
                            ntdb_error("NTDB binary output missing promote score")
                        })?);
                        class_logits.push(promote_logit.ok_or_else(|| {
                            ntdb_error("NTDB binary output missing promote logit")
                        })?);
                    }
                    other => {
                        return Err(ntdb_error(format!(
                            "unsupported NTDB binary label: {other}"
                        )))
                    }
                }
            }
            let (predicted_index, _) = class_scores
                .iter()
                .copied()
                .enumerate()
                .max_by(|left, right| left.1.total_cmp(&right.1))
                .ok_or_else(|| ntdb_error("binary router produced no scores"))?;
            return Ok(ScoreOutput {
                aggregator_id: self.id.clone(),
                task: task.to_string(),
                labels: labels.to_vec(),
                predicted_label: labels
                    .get(predicted_index)
                    .cloned()
                    .unwrap_or_else(|| predicted_index.to_string()),
                predicted_index,
                class_scores,
                class_logits,
                chunks: chunk_count,
                attack_threshold: thresholds.attack_threshold,
                promote_score,
                promote_threshold: promote_score.and(thresholds.promote_threshold),
                chunk_promote_scores: Vec::new(),
                l3_candidate_spans: Vec::new(),
                l3_candidates: Vec::new(),
                l2_chunk_outputs: Vec::new(),
            });
        }

        let scores = tensor_values(&outputs, "doc_class_scores")?;
        let logits = tensor_values(&outputs, "doc_class_logits")?;
        let promote = if let Some(router) = &mut self.promote_router {
            let (score, logit) = router.score(text, prepared, feature_by_name)?;
            Some((score, logit))
        } else {
            optional_first_output(&outputs, "promote_score")?
                .zip(optional_first_output(&outputs, "promote_logit")?)
        };
        let mut class_scores = scores.to_vec();
        let mut class_logits = logits.to_vec();
        if labels.len() > class_scores.len() {
            if labels
                .get(class_scores.len())
                .is_some_and(|label| label == "promote")
            {
                let Some((promote_score, promote_logit)) = promote else {
                    return Err(ntdb_error(
                        "NTDB document class output missing promote score",
                    ));
                };
                class_scores.push(promote_score);
                class_logits.push(promote_logit);
            }
        }
        if class_scores.len() < labels.len() || class_logits.len() < labels.len() {
            return Err(ntdb_error("NTDB document class output is too small"));
        }
        class_scores.truncate(labels.len());
        class_logits.truncate(labels.len());
        let (predicted_index, _) = class_scores
            .iter()
            .copied()
            .enumerate()
            .max_by(|left, right| left.1.total_cmp(&right.1))
            .ok_or_else(|| ntdb_error("aggregator produced no class scores"))?;
        let promote_score = promote.map(|(score, _)| score);
        Ok(ScoreOutput {
            aggregator_id: self.id.clone(),
            task: task.to_string(),
            labels: labels.to_vec(),
            predicted_label: labels
                .get(predicted_index)
                .cloned()
                .unwrap_or_else(|| predicted_index.to_string()),
            predicted_index,
            class_scores,
            class_logits,
            chunks: chunk_count,
            attack_threshold: thresholds.attack_threshold,
            promote_score,
            promote_threshold: promote_score.and(thresholds.promote_threshold),
            chunk_promote_scores: Vec::new(),
            l3_candidate_spans: Vec::new(),
            l3_candidates: Vec::new(),
            l2_chunk_outputs: Vec::new(),
        })
    }

    fn thresholds(&self, operating_point: NtdbOperatingPoint) -> NtdbResult<RoutingThresholds> {
        if self.thresholds.is_empty() {
            return Ok(RoutingThresholds::default());
        }
        self.thresholds
            .get(operating_point.as_str())
            .copied()
            .ok_or_else(|| {
                ntdb_error(format!(
                    "NTDB aggregator {} has no {} operating point",
                    self.id,
                    operating_point.as_str()
                ))
            })
    }
}

impl PromoteRouterRuntime {
    fn load(
        package_dir: &Path,
        aggregator_id: &str,
        manifest: &PromoteRouterManifest,
    ) -> NtdbResult<Self> {
        if manifest.kind != "layered_promote_router" {
            return Err(ntdb_error(format!(
                "unsupported NTDB promote router type: {}",
                manifest.kind
            )));
        }
        let session = load_single_thread_session(package_dir.join(&manifest.onnx))?;
        let router_id = format!("{aggregator_id}.promote_router");
        validate_session_feature_dim(
            &session,
            &router_id,
            "features",
            manifest.input_feature_order.len(),
        )?;
        validate_session_feature_dim(
            &session,
            &router_id,
            "global_features",
            manifest.global_feature_order.len(),
        )?;
        Ok(Self {
            input_feature_order: manifest.input_feature_order.clone(),
            global_feature_order: manifest.global_feature_order.clone(),
            session,
        })
    }

    fn score(
        &mut self,
        text: &str,
        prepared: &PreparedDocument,
        feature_by_name: &HashMap<String, Vec<f32>>,
    ) -> NtdbResult<(f32, f32)> {
        let chunk_count = prepared.chunks.len();
        let (sequence_features, global) = build_sequence_and_global_features(
            text,
            prepared,
            feature_by_name,
            &self.input_feature_order,
            &self.global_feature_order,
        )?;
        let feature_dim = self.input_feature_order.len();
        let outputs = self.session.run(inputs! {
            "features" => TensorRef::from_array_view(([1usize, chunk_count, feature_dim], &sequence_features[..]))?,
            "global_features" => TensorRef::from_array_view(([1usize, global.len()], &global[..]))?
        })?;
        Ok((
            first_output(&outputs, "promote_score")?,
            first_output(&outputs, "promote_logit")?,
        ))
    }
}

fn build_sequence_and_global_features(
    text: &str,
    prepared: &PreparedDocument,
    feature_by_name: &HashMap<String, Vec<f32>>,
    input_feature_order: &[String],
    global_feature_order: &[String],
) -> NtdbResult<(Vec<f32>, Vec<f32>)> {
    let chunk_count = prepared.chunks.len();
    let mut sequence_features = Vec::with_capacity(chunk_count * input_feature_order.len());
    for chunk_index in 0..chunk_count {
        for name in input_feature_order {
            let values = feature_by_name
                .get(name)
                .ok_or_else(|| ntdb_error(format!("missing aggregator input feature {name}")))?;
            sequence_features.push(values[chunk_index]);
        }
    }

    let head_feature_count = input_feature_order
        .iter()
        .position(|name| name == "local_char_count_log")
        .unwrap_or(input_feature_order.len());
    let mut step_means = Vec::with_capacity(chunk_count);
    let mut disagreements = Vec::with_capacity(chunk_count);
    for chunk_index in 0..chunk_count {
        let start = chunk_index * input_feature_order.len();
        let row = &sequence_features[start..start + head_feature_count];
        step_means.push(mean(row));
        disagreements.push(stddev(row));
    }
    let local_entropy = feature_by_name
        .get("local_shannon_entropy_norm")
        .cloned()
        .unwrap_or_else(|| vec![0.0; chunk_count]);
    let global = global_text_heuristics(
        text,
        &prepared.doc_token_ids,
        chunk_count,
        mean(&local_entropy),
        max(&local_entropy),
        mean(&disagreements),
        max(&disagreements),
        max(&step_means),
    );
    if global_feature_order.len() > global.len() {
        return Err(ntdb_error(
            "NTDB global feature order exceeds runtime feature count",
        ));
    }
    Ok((
        sequence_features,
        global[..global_feature_order.len()].to_vec(),
    ))
}

impl LogisticRegression {
    fn output_dim(&self) -> usize {
        if self.coef.len() == 1 && self.classes.len() == 2 {
            2
        } else {
            self.coef.len()
        }
    }

    fn predict_probabilities(&self, features: &[f32]) -> Vec<f32> {
        if self.coef.len() == 1 && self.classes.len() == 2 {
            let logit = dot(features, &self.coef[0]) + self.intercept[0];
            let positive = sigmoid(logit);
            return vec![1.0 - positive, positive];
        }
        let logits = self
            .coef
            .iter()
            .enumerate()
            .map(|(index, coef)| dot(features, coef) + self.intercept[index])
            .collect::<Vec<_>>();
        softmax(&logits)
    }
}

fn token_arrays(chunks: &[TokenChunk], chunk_width: usize) -> (Vec<i64>, Vec<i64>, usize) {
    let max_len = chunk_width.max(1);
    let mut token_ids = vec![0_i64; chunks.len() * max_len];
    let mut token_lengths = vec![0_i64; chunks.len()];
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        let effective_len = chunk.token_ids.len().min(max_len);
        token_lengths[chunk_index] = effective_len as i64;
        for (token_index, token_id) in chunk.token_ids.iter().take(effective_len).enumerate() {
            token_ids[chunk_index * max_len + token_index] = i64::from(*token_id);
        }
    }
    (token_ids, token_lengths, max_len)
}

pub(super) fn load_single_thread_session(path: impl AsRef<Path>) -> NtdbResult<Session> {
    let path = path.as_ref();
    let builder = Session::builder()
        .map_err(|err| ntdb_error(format!("failed to create ORT session builder: {err}")))?;
    let builder = builder
        .with_intra_threads(1)
        .map_err(|err| ntdb_error(format!("failed to set ORT intra threads: {err}")))?;
    let builder = builder
        .with_inter_threads(1)
        .map_err(|err| ntdb_error(format!("failed to set ORT inter threads: {err}")))?;
    let mut builder = builder
        .with_intra_op_spinning(false)
        .map_err(|err| ntdb_error(format!("failed to disable ORT spinning: {err}")))?;
    builder.commit_from_file(path).map_err(|err| {
        ntdb_error(format!(
            "failed to load ORT model {}: {err}",
            path.display()
        ))
    })
}

fn validate_session_feature_dim(
    session: &Session,
    aggregator_id: &str,
    input_name: &str,
    manifest_feature_count: usize,
) -> NtdbResult<()> {
    let Some(expected_feature_count) = session_input_feature_dim(session, input_name) else {
        return Ok(());
    };
    if manifest_feature_count == expected_feature_count {
        return Ok(());
    }
    Err(ntdb_error(format!(
        "NTDB aggregator {aggregator_id} manifest declares {manifest_feature_count} features for input {input_name}, but ONNX expects {expected_feature_count}; export is inconsistent"
    )))
}

fn session_input_feature_dim(session: &Session, input_name: &str) -> Option<usize> {
    #[cfg(ort_rc_10)]
    let mut inputs = session.inputs.iter();
    #[cfg(not(ort_rc_10))]
    let mut inputs = session.inputs().iter();

    let input = inputs.find(|input| {
        #[cfg(ort_rc_10)]
        {
            input.name == input_name
        }
        #[cfg(not(ort_rc_10))]
        {
            input.name() == input_name
        }
    })?;
    #[cfg(ort_rc_10)]
    let dtype = &input.input_type;
    #[cfg(not(ort_rc_10))]
    let dtype = input.dtype();
    let ValueType::Tensor { shape, .. } = dtype else {
        return None;
    };
    let last_dim = shape.iter().last().copied()?;
    usize::try_from(last_dim).ok().filter(|dim| *dim > 0)
}

pub(super) fn tensor_values<'a, 'r>(
    outputs: &'a ort::session::SessionOutputs<'r>,
    name: &str,
) -> NtdbResult<&'a [f32]> {
    let value = outputs.get(name).ok_or_else(|| {
        let available = outputs
            .iter()
            .map(|(output_name, _)| output_name.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        ntdb_error(format!(
            "NTDB output {name} is missing; available outputs: {available}"
        ))
    })?;
    let (_shape, values) = value.try_extract_tensor::<f32>()?;
    Ok(values)
}

fn first_output(outputs: &ort::session::SessionOutputs<'_>, name: &str) -> NtdbResult<f32> {
    tensor_values(outputs, name)?
        .iter()
        .next()
        .copied()
        .ok_or_else(|| ntdb_error(format!("{name} output is empty")))
}

fn optional_first_output(
    outputs: &ort::session::SessionOutputs<'_>,
    name: &str,
) -> NtdbResult<Option<f32>> {
    if !outputs.contains_key(name) {
        return Ok(None);
    }
    Ok(Some(first_output(outputs, name)?))
}

fn routing_thresholds(
    metric_sweep: Option<&MetricSweepManifest>,
) -> HashMap<String, RoutingThresholds> {
    let Some(metric_sweep) = metric_sweep else {
        return HashMap::new();
    };
    metric_sweep
        .points
        .iter()
        .map(|(name, point)| {
            (
                name.clone(),
                RoutingThresholds {
                    attack_threshold: point
                        .attack_threshold
                        .or_else(|| metric_value(&point.metrics, "attack_threshold")),
                    promote_threshold: point
                        .promote_threshold
                        .or_else(|| metric_value(&point.metrics, "promote_threshold"))
                        .or(point.threshold)
                        .or_else(|| metric_value(&point.metrics, "threshold")),
                },
            )
        })
        .collect()
}

fn metric_value(metrics: &serde_json::Value, key: &str) -> Option<f32> {
    metrics.get(key)?.as_f64().map(|value| value as f32)
}

fn dot(left: &[f32], right: &[f32]) -> f32 {
    left.iter().zip(right).map(|(a, b)| a * b).sum()
}

pub fn unit_left_dot(left: &[f32], right: &[f32]) -> f32 {
    let norm = l2_norm(left);
    if norm <= f32::EPSILON {
        0.0
    } else {
        dot(left, right) / norm
    }
}

fn l2_norm(values: &[f32]) -> f32 {
    values.iter().map(|value| value * value).sum::<f32>().sqrt()
}

fn sigmoid(value: f32) -> f32 {
    1.0 / (1.0 + (-value).exp())
}

fn softmax(values: &[f32]) -> Vec<f32> {
    let max_value = values.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let exp_values = values
        .iter()
        .map(|value| (*value - max_value).exp())
        .collect::<Vec<_>>();
    let denom = exp_values.iter().sum::<f32>();
    if denom == 0.0 {
        return vec![0.0; values.len()];
    }
    exp_values.into_iter().map(|value| value / denom).collect()
}

fn mean(values: &[f32]) -> f32 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f32>() / values.len() as f32
    }
}

fn stddev(values: &[f32]) -> f32 {
    if values.is_empty() {
        return 0.0;
    }
    let avg = mean(values);
    (values
        .iter()
        .map(|value| (value - avg).powi(2))
        .sum::<f32>()
        / values.len() as f32)
        .sqrt()
}

fn max(values: &[f32]) -> f32 {
    values.iter().copied().fold(0.0, f32::max)
}
