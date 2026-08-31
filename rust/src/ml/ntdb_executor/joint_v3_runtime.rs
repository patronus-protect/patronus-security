// SPDX-License-Identifier: GPL-3.0-only
//! Package-v4 joint mmBERT L2 runtime and promoter.

use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
};

use ort::{
    session::{Session, SessionInputValue},
    value::Tensor,
};
use rayon::prelude::*;

use crate::NtdbOperatingPoint;

use super::{
    lightgbm::LightGbmModel,
    manifest::{JointV3Manifest, TaskManifest},
    ntdb_error,
    package::{JointV3CandidatePolicy, JointV3DecisionContext, PreparedDocument, ScoreOutput},
    runtime::load_single_thread_session,
    NtdbResult,
};

pub(super) struct JointV3Runtime {
    neural: Session,
    neural_inputs: Vec<String>,
    heads: Vec<JointV3HeadRuntime>,
    promoter_feature_dim: usize,
    promoter: JointV3PromoterRuntime,
    document_decision: super::manifest::JointV3DocumentDecisionManifest,
    attack_threshold: Option<f32>,
}

struct JointV3HeadRuntime {
    id: String,
    class_count: usize,
    lightgbm: LightGbmModel,
}

struct JointV3PromoterRuntime {
    models: HashMap<String, LightGbmModel>,
    utility: ActionablePolicy,
    best_promote: ActionablePolicy,
}

#[derive(Clone)]
struct ActionablePolicy {
    gate: String,
    threshold: f32,
    aggregation: String,
    document_risk_margin_threshold: f32,
}

struct JointPrediction {
    probabilities: Vec<f32>,
    promoter_features: Vec<f32>,
}

impl JointV3Runtime {
    pub(super) fn load(package_dir: &Path, manifest: &JointV3Manifest) -> NtdbResult<Self> {
        let mut head_by_id = manifest
            .heads
            .iter()
            .map(|head| (head.id.as_str(), head))
            .collect::<HashMap<_, _>>();
        let heads = manifest
            .neural_stack
            .head_order
            .iter()
            .zip(&manifest.neural_stack.head_class_counts)
            .map(|(id, class_count)| {
                let head = head_by_id
                    .remove(id.as_str())
                    .ok_or_else(|| ntdb_error(format!("NTDB package v4 is missing head {id}")))?;
                let lightgbm = LightGbmModel::load(package_dir.join(&head.frozen_lightgbm))?;
                if lightgbm.feature_count() != 384 {
                    return Err(ntdb_error(format!(
                        "NTDB package v4 head {id} LightGBM expects {} features, expected 384",
                        lightgbm.feature_count()
                    )));
                }
                Ok(JointV3HeadRuntime {
                    id: id.clone(),
                    class_count: *class_count,
                    lightgbm,
                })
            })
            .collect::<NtdbResult<Vec<_>>>()?;
        let promoter = JointV3PromoterRuntime::load(package_dir, manifest)?;
        Ok(Self {
            neural: load_single_thread_session(package_dir.join(&manifest.neural_stack.onnx))?,
            neural_inputs: manifest.neural_stack.input_names.clone(),
            heads,
            promoter_feature_dim: manifest.neural_stack.promoter_feature_dim,
            promoter,
            document_decision: manifest.document_decision.clone(),
            attack_threshold: None,
        })
    }

    pub(super) fn score(
        &mut self,
        task: &TaskManifest,
        prepared: &PreparedDocument,
        operating_point: NtdbOperatingPoint,
    ) -> NtdbResult<ScoreOutput> {
        let chunks = self.predict(prepared, prepared.chunks.len(), 1)?;
        self.output_from_chunks(task, chunks, operating_point)
    }

    fn output_from_chunks(
        &self,
        task: &TaskManifest,
        chunks: Vec<JointPrediction>,
        operating_point: NtdbOperatingPoint,
    ) -> NtdbResult<ScoreOutput> {
        let operating_point =
            short_injection_operating_point(&task.kind, operating_point, chunks.len());
        let chunk_routing = chunks
            .iter()
            .map(|chunk| {
                let (score, threshold) = self.promoter.score(
                    &chunk.probabilities,
                    &chunk.promoter_features,
                    operating_point,
                )?;
                Ok((score, threshold))
            })
            .collect::<NtdbResult<Vec<_>>>()?;
        let promote_threshold = chunk_routing
            .first()
            .map(|(_, threshold)| *threshold)
            .unwrap_or(f32::INFINITY);
        let promote_score = chunk_routing
            .iter()
            .map(|(score, _)| *score)
            .fold(f32::NEG_INFINITY, f32::max);
        let context = Arc::new(self.decision_context(task, operating_point)?);
        let chunk_class_probabilities = chunks
            .iter()
            .map(|chunk| chunk.probabilities.clone())
            .collect::<Vec<_>>();
        let class_scores =
            aggregate_probabilities(&chunk_class_probabilities, &context.l2.aggregation)?;
        let predicted_index = argmax(&class_scores)?;
        let output = ScoreOutput {
            aggregator_id: "joint_v3".to_string(),
            task: task.kind.clone(),
            labels: task.labels.clone(),
            predicted_label: task.labels[predicted_index].clone(),
            predicted_index,
            class_scores,
            class_logits: Vec::new(),
            chunks: chunks.len(),
            attack_threshold: self.attack_threshold,
            promote_score: Some(promote_score),
            promote_threshold: Some(promote_threshold),
            chunk_promote_scores: chunk_routing
                .iter()
                .map(|(score, _)| Some(*score))
                .collect(),
            l3_candidate_spans: Vec::new(),
            l3_candidates: Vec::new(),
            l2_chunk_outputs: Vec::new(),
            chunk_class_probabilities,
            joint_v3_decision: Some(context),
        };
        Ok(output)
    }

    pub(super) fn score_batch(
        &mut self,
        task: &TaskManifest,
        prepared: &[PreparedDocument],
        operating_point: NtdbOperatingPoint,
    ) -> NtdbResult<Vec<ScoreOutput>> {
        if prepared.is_empty() {
            return Ok(Vec::new());
        }
        let counts = prepared
            .iter()
            .map(|document| document.chunks.len())
            .collect::<Vec<_>>();
        let embeddings = prepared
            .iter()
            .flat_map(|document| document.raw_embeddings.iter().copied())
            .collect::<Vec<_>>();
        let total_chunks = counts.iter().sum::<usize>();
        let predictions =
            self.predict_tensors(embeddings, vec![true; total_chunks], total_chunks, 1)?;
        let mut predictions = predictions.into_iter();
        counts
            .into_iter()
            .map(|count| {
                self.output_from_chunks(
                    task,
                    predictions.by_ref().take(count).collect(),
                    operating_point,
                )
            })
            .collect()
    }

    fn predict(
        &mut self,
        prepared: &PreparedDocument,
        batch: usize,
        chunks_per_batch: usize,
    ) -> NtdbResult<Vec<JointPrediction>> {
        let chunk_count = prepared.chunks.len();
        if batch.saturating_mul(chunks_per_batch) != chunk_count {
            return Err(ntdb_error("invalid NTDB package v4 neural batch shape"));
        }
        self.predict_tensors(
            prepared.raw_embeddings.clone(),
            vec![true; chunk_count],
            batch,
            chunks_per_batch,
        )
    }

    fn predict_tensors(
        &mut self,
        raw_embeddings: Vec<f32>,
        mask: Vec<bool>,
        batch: usize,
        chunks_per_batch: usize,
    ) -> NtdbResult<Vec<JointPrediction>> {
        let chunk_count = batch.saturating_mul(chunks_per_batch);
        let head_probabilities = self
            .heads
            .par_iter()
            .map(|head| {
                let mut values = Vec::with_capacity(chunk_count * head.class_count);
                for (chunk_index, embedding) in raw_embeddings.chunks_exact(384).enumerate() {
                    if !mask[chunk_index] {
                        values.extend(std::iter::repeat_n(0.0, head.class_count));
                        continue;
                    }
                    let row = head.lightgbm.predict_probabilities(embedding);
                    if row.len() != head.class_count {
                        return Err(ntdb_error(format!(
                            "NTDB package v4 head {} returned {} classes, expected {}",
                            head.id,
                            row.len(),
                            head.class_count
                        )));
                    }
                    values.extend(row);
                }
                Ok(values)
            })
            .collect::<NtdbResult<Vec<_>>>()?;

        let mut inputs =
            Vec::<(String, SessionInputValue<'_>)>::with_capacity(self.heads.len() + 2);
        inputs.push((
            "raw_embeddings".to_string(),
            Tensor::from_array(([batch, chunks_per_batch, 384], raw_embeddings))?.into(),
        ));
        inputs.push((
            "attention_mask".to_string(),
            Tensor::from_array(([batch, chunks_per_batch], mask))?.into(),
        ));
        for (index, (head, values)) in self.heads.iter().zip(head_probabilities).enumerate() {
            let input_name = self
                .neural_inputs
                .get(index + 2)
                .cloned()
                .unwrap_or_else(|| format!("{}_lgb_probabilities", head.id));
            inputs.push((
                input_name,
                Tensor::from_array(([batch, chunks_per_batch, head.class_count], values))?.into(),
            ));
        }
        let outputs = self.neural.run(inputs)?;
        let probabilities = tensor_values(&outputs, "l2_probabilities")?;
        let logits = tensor_values(&outputs, "l2_logits")?;
        let promoter_features = tensor_values(&outputs, "promoter_features")?;
        let class_count = probabilities.len() / batch;
        if class_count == 0
            || probabilities.len() != batch * class_count
            || logits.len() != batch * class_count
            || promoter_features.len() != batch * self.promoter_feature_dim
        {
            return Err(ntdb_error(format!(
                "NTDB package v4 neural outputs do not match batch={batch}, classes={class_count}, promoter_dim={}",
                self.promoter_feature_dim
            )));
        }
        Ok((0..batch)
            .map(|index| JointPrediction {
                probabilities: probabilities[index * class_count..(index + 1) * class_count]
                    .to_vec(),
                promoter_features: promoter_features
                    [index * self.promoter_feature_dim..(index + 1) * self.promoter_feature_dim]
                    .to_vec(),
            })
            .collect())
    }

    fn decision_context(
        &self,
        task: &TaskManifest,
        operating_point: NtdbOperatingPoint,
    ) -> NtdbResult<JointV3DecisionContext> {
        let profile = match operating_point {
            NtdbOperatingPoint::BestFprInF1 => "best_fpr_in_f1",
            NtdbOperatingPoint::BestFnrInF1 => "best_fnr_in_f1",
            _ => self.document_decision.default_operating_point.as_str(),
        };
        let l2 = document_policy(&self.document_decision, "l2_only", profile)?;
        let l3 = document_policy(&self.document_decision, "l3_only", profile)?;
        let union = if matches!(
            operating_point,
            NtdbOperatingPoint::BestPromote
                | NtdbOperatingPoint::BestF1
                | NtdbOperatingPoint::BestLatencyInF1
        ) {
            let point = self.promoter.policy(operating_point);
            JointV3CandidatePolicy {
                aggregation: point.aggregation.clone(),
                risk_margin_threshold: point.document_risk_margin_threshold,
            }
        } else {
            document_policy(&self.document_decision, "union_l2_l3", profile)?
        };
        let default_class_index = task
            .no_risk_class
            .as_ref()
            .and_then(|class| task.labels.iter().position(|label| label == class))
            .unwrap_or(0);
        Ok(JointV3DecisionContext {
            labels: task.labels.clone(),
            default_class_index,
            l2,
            l3,
            union,
        })
    }
}

fn short_injection_operating_point(
    task_kind: &str,
    operating_point: NtdbOperatingPoint,
    chunk_count: usize,
) -> NtdbOperatingPoint {
    if operating_point == NtdbOperatingPoint::ArkApiShortInjectionUtility {
        if task_kind == "injection" && chunk_count <= 2 {
            // JointV3PromoterRuntime maps BestF1 to the manifest's utility promoter.
            return NtdbOperatingPoint::BestF1;
        }
        return NtdbOperatingPoint::BestPromote;
    }
    operating_point
}

fn document_policy(
    decision: &super::manifest::JointV3DocumentDecisionManifest,
    mode: &str,
    profile: &str,
) -> NtdbResult<JointV3CandidatePolicy> {
    let mode = decision
        .modes
        .get(mode)
        .ok_or_else(|| ntdb_error(format!("missing Package-v4 document mode {mode}")))?;
    let point = mode.operating_points.get(profile).ok_or_else(|| {
        ntdb_error(format!(
            "missing Package-v4 document operating point {profile}"
        ))
    })?;
    Ok(JointV3CandidatePolicy {
        aggregation: mode.aggregation.clone(),
        risk_margin_threshold: point.threshold,
    })
}

pub(crate) fn aggregate_probabilities(values: &[Vec<f32>], method: &str) -> NtdbResult<Vec<f32>> {
    let classes = values
        .first()
        .map(Vec::len)
        .ok_or_else(|| ntdb_error("cannot aggregate zero chunks"))?;
    if classes == 0 || values.iter().any(|row| row.len() != classes) {
        return Err(ntdb_error("chunk probability shape mismatch"));
    }
    let mut result = vec![0.0_f32; classes];
    match method {
        "max" => {
            result.fill(f32::NEG_INFINITY);
            for row in values {
                for (target, value) in result.iter_mut().zip(row) {
                    *target = target.max(*value);
                }
            }
        }
        "mean" => {
            for row in values {
                for (target, value) in result.iter_mut().zip(row) {
                    *target += *value;
                }
            }
            for value in &mut result {
                *value /= values.len() as f32;
            }
        }
        "smoothmax" => {
            for class in 0..classes {
                let maximum = values
                    .iter()
                    .map(|row| row[class])
                    .fold(f32::NEG_INFINITY, f32::max);
                let mut weighted = 0.0_f32;
                let mut weight_sum = 0.0_f32;
                for row in values {
                    let weight = (10.0 * (row[class] - maximum)).exp();
                    weighted += row[class] * weight;
                    weight_sum += weight;
                }
                result[class] = weighted / weight_sum.max(1e-12);
            }
        }
        other => {
            return Err(ntdb_error(format!(
                "unsupported Package-v4 aggregation: {other}"
            )))
        }
    }
    Ok(result)
}

impl JointV3PromoterRuntime {
    fn load(package_dir: &Path, manifest: &JointV3Manifest) -> NtdbResult<Self> {
        if manifest.promoter.scope != "per_chunk" {
            return Err(ntdb_error(
                "NTDB package v4 promoter must have per_chunk scope",
            ));
        }
        if manifest.promoter.implementation != "LightGBM" {
            return Err(ntdb_error("NTDB package v4 promoter must use LightGBM"));
        }
        let utility = manifest
            .promoter
            .operating_points
            .get("utility_promote")
            .map(ActionablePolicy::from)
            .ok_or_else(|| ntdb_error("NTDB package v4 has no utility_promote operating point"))?;
        let best_promote = manifest
            .promoter
            .operating_points
            .get("best_promote")
            .map(ActionablePolicy::from)
            .ok_or_else(|| ntdb_error("NTDB package v4 has no best_promote operating point"))?;
        let required = [&utility, &best_promote]
            .into_iter()
            .flat_map(required_models)
            .collect::<HashSet<_>>();
        if required.is_empty() {
            return Err(ntdb_error(
                "NTDB package v4 references no supported promoter model",
            ));
        }
        let models = required
            .into_iter()
            .map(|name| Ok((name.to_string(), load_gate(package_dir, manifest, name)?)))
            .collect::<NtdbResult<HashMap<_, _>>>()?;
        Ok(Self {
            models,
            utility,
            best_promote,
        })
    }

    fn policy(&self, operating_point: NtdbOperatingPoint) -> &ActionablePolicy {
        if matches!(
            operating_point,
            NtdbOperatingPoint::BestPromote | NtdbOperatingPoint::ArkApiShortInjectionUtility
        ) {
            &self.best_promote
        } else {
            &self.utility
        }
    }

    fn score(
        &self,
        _l2_probabilities: &[f32],
        features: &[f32],
        operating_point: NtdbOperatingPoint,
    ) -> NtdbResult<(f32, f32)> {
        let policy = self.policy(operating_point);
        let model = |name: &str| {
            self.models.get(name).ok_or_else(|| {
                ntdb_error(format!(
                    "NTDB package v4 did not load promoter model {name}"
                ))
            })
        };
        let score = match policy.gate.as_str() {
            "direct_actionable" => model("direct_actionable_gate")?.predict_probability(features),
            "factorized_actionable" => {
                model("disagreement_gate")?.predict_probability(features)
                    * model("pre_l3_benefit_gate")?.predict_probability(features)
            }
            other => {
                return Err(ntdb_error(format!(
                    "unsupported actionable promoter gate: {other}"
                )))
            }
        };
        Ok((score, policy.threshold))
    }
}

fn required_models(policy: &ActionablePolicy) -> &'static [&'static str] {
    match policy.gate.as_str() {
        "direct_actionable" => &["direct_actionable_gate"],
        "factorized_actionable" => &["disagreement_gate", "pre_l3_benefit_gate"],
        _ => &[],
    }
}

impl From<&super::manifest::JointV3PromoterOperatingPoint> for ActionablePolicy {
    fn from(point: &super::manifest::JointV3PromoterOperatingPoint) -> Self {
        Self {
            gate: point.gate.clone(),
            threshold: point.promote_threshold,
            aggregation: point.aggregation.clone(),
            document_risk_margin_threshold: point.document_risk_margin_threshold,
        }
    }
}

fn load_gate(
    package_dir: &Path,
    manifest: &JointV3Manifest,
    name: &str,
) -> NtdbResult<LightGbmModel> {
    let gate = gate_manifest(manifest, name)?;
    validate_promoter_dim(gate.n_features, manifest)?;
    let path = gate
        .lightgbm_model
        .as_ref()
        .ok_or_else(|| ntdb_error(format!("NTDB package v4 gate {name} has no LightGBM model")))?;
    let model = LightGbmModel::load(package_dir.join(path))?;
    validate_model_dim(&model, gate.n_features, path)?;
    Ok(model)
}

fn gate_manifest(
    manifest: &JointV3Manifest,
    name: &str,
) -> NtdbResult<super::manifest::JointV3GateManifest> {
    let value = manifest
        .promoter
        .models
        .get(name)
        .ok_or_else(|| ntdb_error(format!("missing NTDB package v4 gate {name}")))?;
    serde_json::from_value(value.clone())
        .map_err(|error| ntdb_error(format!("invalid NTDB package v4 gate {name}: {error}")))
}

fn validate_promoter_dim(feature_count: usize, manifest: &JointV3Manifest) -> NtdbResult<()> {
    if feature_count == manifest.neural_stack.promoter_feature_dim
        && manifest.promoter.feature_dim == feature_count
    {
        Ok(())
    } else {
        Err(ntdb_error(format!(
            "NTDB package v4 promoter declares {feature_count} features, neural stack produces {}",
            manifest.neural_stack.promoter_feature_dim
        )))
    }
}

fn validate_model_dim(model: &LightGbmModel, expected: usize, path: &str) -> NtdbResult<()> {
    if model.feature_count() == expected {
        Ok(())
    } else {
        Err(ntdb_error(format!(
            "NTDB package v4 LightGBM {path} expects {} features, manifest declares {expected}",
            model.feature_count()
        )))
    }
}

fn tensor_values<'a, 'r>(
    outputs: &'a ort::session::SessionOutputs<'r>,
    name: &str,
) -> NtdbResult<&'a [f32]> {
    let value = outputs
        .get(name)
        .ok_or_else(|| ntdb_error(format!("NTDB package v4 output {name} is missing")))?;
    let (_shape, values) = value.try_extract_tensor::<f32>()?;
    Ok(values)
}

fn argmax(values: &[f32]) -> NtdbResult<usize> {
    values
        .iter()
        .copied()
        .enumerate()
        .max_by(|left, right| left.1.total_cmp(&right.1))
        .map(|(index, _)| index)
        .ok_or_else(|| ntdb_error("NTDB package v4 produced no class scores"))
}

#[cfg(test)]
mod tests {
    use super::short_injection_operating_point;
    use crate::NtdbOperatingPoint;

    #[test]
    fn ark_api_utility_profile_is_limited_to_short_injection_documents() {
        let profile = NtdbOperatingPoint::ArkApiShortInjectionUtility;
        assert_eq!(
            short_injection_operating_point("injection", profile, 2),
            NtdbOperatingPoint::BestF1
        );
        assert_eq!(
            short_injection_operating_point("injection", profile, 3),
            NtdbOperatingPoint::BestPromote
        );
        assert_eq!(
            short_injection_operating_point("threat", profile, 1),
            NtdbOperatingPoint::BestPromote
        );
        assert_eq!(
            short_injection_operating_point("injection", NtdbOperatingPoint::BestPromote, 1),
            NtdbOperatingPoint::BestPromote
        );
    }
}
