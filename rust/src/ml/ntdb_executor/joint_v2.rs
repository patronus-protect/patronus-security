// SPDX-License-Identifier: GPL-3.0-only
use std::{
    collections::HashMap,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use ort::{inputs, session::Session, value::TensorRef};
use rayon::prelude::*;

use crate::NtdbOperatingPoint;

use super::{
    lightgbm::LightGbmModel,
    manifest::{JointV2Manifest, MetricSweepManifest},
    ntdb_error,
    package::{PreparedDocument, ScoreOutput},
    runtime::{load_single_thread_session, tensor_values},
    NtdbResult,
};

const JOINT_V2_AGGREGATOR_ID: &str = "joint_v2";

pub(super) struct JointV2Runtime {
    neural: Session,
    frozen_lightgbm: Vec<LightGbmModel>,
    l3_surrogate: LightGbmModel,
    conditional_branches: Vec<LightGbmModel>,
    pre_lgb_feature_dim: usize,
    promoter_feature_dim: usize,
    l2_threshold: f32,
    l3_call_cost: f32,
    branch_utilities: Vec<Vec<f32>>,
    thresholds: HashMap<String, JointV2Thresholds>,
    default_operating_point: String,
}

#[derive(Clone, Copy)]
struct JointV2Thresholds {
    attack_threshold: f32,
    promote_threshold: f32,
}

struct JointV2RawScore {
    probabilities: Vec<f32>,
    logits: Vec<f32>,
    promote_score: f32,
}

impl JointV2Runtime {
    pub(super) fn load(
        package_dir: &Path,
        manifest: &JointV2Manifest,
        metric_sweep: Option<&MetricSweepManifest>,
    ) -> NtdbResult<Self> {
        let branch_count = manifest.conditional_branches.len();
        if branch_count == 0 {
            return Err(ntdb_error(
                "NTDB Joint-v2 must declare conditional branches",
            ));
        }
        let mut conditional_branches = Vec::with_capacity(branch_count);
        let mut branch_utilities = Vec::with_capacity(branch_count);
        for branch in 0..branch_count {
            let key = branch.to_string();
            let branch_path = manifest
                .conditional_branches
                .get(&key)
                .ok_or_else(|| ntdb_error(format!("missing Joint-v2 conditional branch {key}")))?;
            let utilities = manifest
                .branch_utilities
                .get(&key)
                .cloned()
                .ok_or_else(|| ntdb_error(format!("missing Joint-v2 branch utilities {key}")))?;
            if utilities.is_empty() {
                return Err(ntdb_error(format!(
                    "Joint-v2 branch {key} utilities must not be empty"
                )));
            }
            conditional_branches.push(LightGbmModel::load(package_dir.join(branch_path))?);
            branch_utilities.push(utilities);
        }

        Ok(Self {
            neural: load_single_thread_session(package_dir.join(&manifest.neural_onnx))?,
            frozen_lightgbm: vec![
                LightGbmModel::load(package_dir.join(&manifest.frozen_lightgbm.patronus))?,
                LightGbmModel::load(package_dir.join(&manifest.frozen_lightgbm.jayavibhav))?,
                LightGbmModel::load(package_dir.join(&manifest.frozen_lightgbm.nn_l3_surrogate))?,
            ],
            l3_surrogate: LightGbmModel::load(package_dir.join(&manifest.lightgbm_l3_surrogate))?,
            conditional_branches,
            pre_lgb_feature_dim: manifest.pre_lgb_feature_dim,
            promoter_feature_dim: manifest.promoter_feature_dim,
            l2_threshold: manifest.l2_threshold,
            l3_call_cost: manifest.l3_call_cost,
            branch_utilities,
            thresholds: joint_v2_thresholds(metric_sweep, manifest.l2_threshold),
            default_operating_point: manifest.default_operating_point.clone(),
        })
    }

    pub(super) fn score_chunks(
        &mut self,
        task: &str,
        labels: &[String],
        prepared: &PreparedDocument,
        embedding_dim: usize,
        operating_point: NtdbOperatingPoint,
    ) -> NtdbResult<Vec<ScoreOutput>> {
        let thresholds = self.thresholds(operating_point)?;
        let scores = self.score_batch(
            &prepared.raw_embeddings,
            prepared.chunks.len(),
            1,
            embedding_dim,
        )?;
        Ok(scores
            .into_iter()
            .map(|score| self.to_score_output(task, labels, 1, thresholds, score))
            .collect())
    }

    fn score_batch(
        &mut self,
        raw_embeddings: &[f32],
        batch: usize,
        chunks: usize,
        embedding_dim: usize,
    ) -> NtdbResult<Vec<JointV2RawScore>> {
        if embedding_dim != 384 {
            return Err(ntdb_error("Joint-v2 requires 384d raw embeddings"));
        }
        let expected_raw_len = batch * chunks * embedding_dim;
        if raw_embeddings.len() != expected_raw_len {
            return Err(ntdb_error(format!(
                "Joint-v2 raw embedding shape mismatch: got {}, expected {}",
                raw_embeddings.len(),
                expected_raw_len
            )));
        }
        let profile = profile_enabled();
        let total_started = Instant::now();
        let frozen_started = Instant::now();
        let frozen_probabilities = self
            .frozen_lightgbm
            .par_iter()
            .map(|model| {
                raw_embeddings
                    .par_chunks_exact(embedding_dim)
                    .flat_map_iter(|chunk| model.predict_probabilities(chunk))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let frozen_elapsed = frozen_started.elapsed();
        if frozen_probabilities.len() != 3 {
            return Err(ntdb_error("Joint-v2 requires three frozen LightGBM heads"));
        }
        for values in &frozen_probabilities {
            if values.len() != batch * chunks * 2 {
                return Err(ntdb_error(
                    "Joint-v2 frozen LightGBM head did not emit binary probabilities",
                ));
            }
        }

        let neural_started = Instant::now();
        let (probabilities, logits, pre_lgb) = {
            let outputs = self.neural.run(inputs! {
                "raw_embeddings" => TensorRef::from_array_view(([batch, chunks, embedding_dim], raw_embeddings))?,
                "patronus_lgb_probabilities" => TensorRef::from_array_view(([batch, chunks, 2usize], &frozen_probabilities[0][..]))?,
                "jayavibhav_lgb_probabilities" => TensorRef::from_array_view(([batch, chunks, 2usize], &frozen_probabilities[1][..]))?,
                "nn_l3_surrogate_lgb_probabilities" => TensorRef::from_array_view(([batch, chunks, 2usize], &frozen_probabilities[2][..]))?,
            })?;
            (
                tensor_values(&outputs, "l2_probabilities")?.to_vec(),
                tensor_values(&outputs, "l2_logits")?.to_vec(),
                tensor_values(&outputs, "pre_lgb_promoter_features")?.to_vec(),
            )
        };
        let neural_elapsed = neural_started.elapsed();
        if probabilities.len() != batch * 2 || logits.len() != batch * 2 {
            return Err(ntdb_error("Joint-v2 must emit two L2 classes"));
        }
        if pre_lgb.len() != batch * self.pre_lgb_feature_dim {
            return Err(ntdb_error(format!(
                "Joint-v2 emitted {} pre-LGB feature values, expected {}",
                pre_lgb.len(),
                batch * self.pre_lgb_feature_dim
            )));
        }

        let post_started = Instant::now();
        let surrogate_feature_nanos = AtomicU64::new(0);
        let conditional_nanos = AtomicU64::new(0);
        let scores = (0..batch)
            .into_par_iter()
            .map(|row| {
                let class_probabilities = probabilities[row * 2..row * 2 + 2].to_vec();
                let class_logits = logits[row * 2..row * 2 + 2].to_vec();
                let pre_lgb_row =
                    &pre_lgb[row * self.pre_lgb_feature_dim..(row + 1) * self.pre_lgb_feature_dim];
                let promoter_features = if profile {
                    let started = Instant::now();
                    let result = self.promoter_features(pre_lgb_row, &class_probabilities);
                    surrogate_feature_nanos
                        .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
                    result?
                } else {
                    self.promoter_features(pre_lgb_row, &class_probabilities)?
                };
                let l2_class = self.l2_class(&class_probabilities);
                let state_probabilities = if profile {
                    let started = Instant::now();
                    let result = self.conditional_branches[l2_class]
                        .predict_probabilities(&promoter_features);
                    conditional_nanos
                        .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
                    result
                } else {
                    self.conditional_branches[l2_class].predict_probabilities(&promoter_features)
                };
                let utilities = &self.branch_utilities[l2_class];
                if state_probabilities.len() != utilities.len() {
                    return Err(ntdb_error(format!(
                        "Joint-v2 conditional branch {l2_class} emitted {} states, expected {}",
                        state_probabilities.len(),
                        utilities.len()
                    )));
                }
                let promote_score = state_probabilities
                    .iter()
                    .zip(utilities)
                    .map(|(probability, utility)| probability * utility)
                    .sum::<f32>()
                    - self.l3_call_cost;
                Ok(JointV2RawScore {
                    probabilities: class_probabilities,
                    logits: class_logits,
                    promote_score,
                })
            })
            .collect::<NtdbResult<Vec<_>>>()?;
        let post_elapsed = post_started.elapsed();
        if profile {
            eprintln!(
                "ntdb_joint_v2_profile batch={batch} chunks={chunks} rows={} total_ms={:.3} frozen_lgbm_ms={:.3} neural_onnx_ms={:.3} post_ms={:.3} surrogate_features_cpu_ms={:.3} conditional_lgbm_cpu_ms={:.3}",
                batch * chunks,
                ms(total_started.elapsed()),
                ms(frozen_elapsed),
                ms(neural_elapsed),
                ms(post_elapsed),
                nanos_ms(surrogate_feature_nanos.load(Ordering::Relaxed)),
                nanos_ms(conditional_nanos.load(Ordering::Relaxed)),
            );
        }
        Ok(scores)
    }

    fn promoter_features(&self, pre_lgb: &[f32], probabilities: &[f32]) -> NtdbResult<Vec<f32>> {
        let surrogate = self.l3_surrogate.predict_probabilities(pre_lgb);
        if surrogate.len() < 2 {
            return Err(ntdb_error(
                "Joint-v2 L3 surrogate must emit at least two classes",
            ));
        }
        let surrogate_class = argmax(&surrogate);
        let margin = top_margin(&surrogate);
        let entropy = normalized_entropy(&surrogate);
        let l2_class = self.l2_class(probabilities);
        let mut features = pre_lgb.to_vec();
        features.extend_from_slice(&surrogate);
        for class_index in 0..surrogate.len() {
            features.push(if class_index == surrogate_class {
                1.0
            } else {
                0.0
            });
        }
        features.push(margin);
        features.push(entropy);
        features.push(if surrogate_class != l2_class {
            1.0
        } else {
            0.0
        });
        if features.len() != self.promoter_feature_dim {
            return Err(ntdb_error(format!(
                "Joint-v2 emitted {} promoter features, expected {}",
                features.len(),
                self.promoter_feature_dim
            )));
        }
        Ok(features)
    }

    fn l2_class(&self, probabilities: &[f32]) -> usize {
        if probabilities.len() == 2 {
            usize::from(probabilities[1] >= self.l2_threshold)
        } else {
            argmax(probabilities)
        }
    }

    fn to_score_output(
        &self,
        task: &str,
        labels: &[String],
        chunks: usize,
        thresholds: JointV2Thresholds,
        score: JointV2RawScore,
    ) -> ScoreOutput {
        let predicted_index = argmax(&score.probabilities);
        ScoreOutput {
            aggregator_id: JOINT_V2_AGGREGATOR_ID.to_string(),
            task: task.to_string(),
            labels: labels.to_vec(),
            predicted_label: labels
                .get(predicted_index)
                .cloned()
                .unwrap_or_else(|| predicted_index.to_string()),
            predicted_index,
            class_scores: score.probabilities,
            class_logits: score.logits,
            chunks,
            attack_threshold: Some(thresholds.attack_threshold),
            promote_score: Some(score.promote_score),
            promote_threshold: Some(thresholds.promote_threshold),
            chunk_promote_scores: Vec::new(),
            l3_candidate_spans: Vec::new(),
            l3_candidates: Vec::new(),
            l2_chunk_outputs: Vec::new(),
        }
    }

    fn thresholds(&self, operating_point: NtdbOperatingPoint) -> NtdbResult<JointV2Thresholds> {
        self.thresholds
            .get(operating_point.as_str())
            .or_else(|| self.thresholds.get(&self.default_operating_point))
            .copied()
            .ok_or_else(|| {
                ntdb_error(format!(
                    "Joint-v2 has no {} operating point",
                    operating_point.as_str()
                ))
            })
    }
}

fn joint_v2_thresholds(
    metric_sweep: Option<&MetricSweepManifest>,
    default_attack_threshold: f32,
) -> HashMap<String, JointV2Thresholds> {
    let Some(metric_sweep) = metric_sweep else {
        return HashMap::new();
    };
    metric_sweep
        .points
        .iter()
        .filter_map(|(name, point)| {
            let attack_threshold = point
                .attack_threshold
                .or_else(|| metric_value(&point.metrics, "attack_threshold"))
                .unwrap_or(default_attack_threshold);
            let promote_threshold = point
                .promote_threshold
                .or_else(|| metric_value(&point.metrics, "promote_threshold"))
                .or(point.threshold)
                .or_else(|| metric_value(&point.metrics, "threshold"))?;
            Some((
                name.clone(),
                JointV2Thresholds {
                    attack_threshold,
                    promote_threshold,
                },
            ))
        })
        .collect()
}

fn metric_value(metrics: &serde_json::Value, key: &str) -> Option<f32> {
    metrics.get(key)?.as_f64().map(|value| value as f32)
}

fn argmax(values: &[f32]) -> usize {
    values
        .iter()
        .copied()
        .enumerate()
        .max_by(|left, right| left.1.total_cmp(&right.1))
        .map(|(index, _)| index)
        .unwrap_or(0)
}

fn top_margin(values: &[f32]) -> f32 {
    let mut top = f32::NEG_INFINITY;
    let mut second = f32::NEG_INFINITY;
    for value in values {
        if *value > top {
            second = top;
            top = *value;
        } else if *value > second {
            second = *value;
        }
    }
    (top - second).abs()
}

fn normalized_entropy(values: &[f32]) -> f32 {
    if values.len() <= 1 {
        return 0.0;
    }
    -values
        .iter()
        .map(|value| value.max(1e-12) * value.max(1e-12).ln())
        .sum::<f32>()
        / (values.len() as f32).ln()
}

fn profile_enabled() -> bool {
    std::env::var_os("PATRONUS_NTDB_PROFILE").is_some()
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn nanos_ms(nanos: u64) -> f64 {
    nanos as f64 / 1_000_000.0
}
