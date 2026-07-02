use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

use super::long_text::{
    aggregate_chunk_outputs, candidate_selection, chunk_text_bytes, infer_l3_candidate_texts,
    l3_metadata,
};
use super::{degraded_fallback_confidence, l3_pending_layer};
use crate::ml::l1_heuristics::NativeHeuristicsEngine;
use crate::ml::l2::{
    PromptInjectionClassifier, PromptInjectionL2Buffers, PromptInjectionL2Timings,
};
use crate::ml::onnx::LazyOnnxTextClassifier;
use crate::{EvaluationResult, LayerResult, OnnxBatchMode, ScanExecution, SecurityLevel};

#[derive(Debug, Deserialize)]
struct InjectionThresholdsConfig {
    thresholds: HashMap<String, f64>,
}

#[allow(dead_code)]
pub struct PromptInjectionPipeline {
    l1: NativeHeuristicsEngine,
    l2: PromptInjectionClassifier,
    l3: Option<Mutex<LazyOnnxTextClassifier>>,
    t_low_lgbm: f64,
    t_high_lgbm: f64,
    t_low_lr: f64,
    t_high_lr: f64,
    t_low_ft: f64,
    t_high_ft: f64,
    t_consensus_attack: f64,
    t_consensus_benign: f64,
    t_bert: f64,
}

enum BatchEval {
    Ready(EvaluationResult, Vec<LayerResult>),
    NeedsL3 {
        text: String,
        layers: Vec<LayerResult>,
        fallback: Option<EvaluationResult>,
    },
}

fn batch_eval_to_ready(item: Option<BatchEval>) -> Option<(EvaluationResult, Vec<LayerResult>)> {
    match item {
        Some(BatchEval::Ready(result, layers)) => Some((result, layers)),
        Some(BatchEval::NeedsL3 {
            mut layers,
            fallback: Some(result),
            ..
        }) => {
            mark_last_level_layer_matched(&mut layers, &result);
            Some((result, layers))
        }
        _ => None,
    }
}

impl PromptInjectionPipeline {
    pub(crate) fn l3_worker_model(&self) -> Option<LazyOnnxTextClassifier> {
        self.l3
            .as_ref()
            .map(|model| model.lock().expect("l3 mutex poisoned").metadata_clone())
    }

    pub fn new<P: AsRef<Path>>(dir: P) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = dir.as_ref();
        let l1 = NativeHeuristicsEngine::new();
        let l2 = PromptInjectionClassifier::new(dir)?;

        let t_file = File::open(dir.join("cascade_config.json"))?;
        let t_reader = BufReader::new(t_file);
        let t_config: InjectionThresholdsConfig = serde_json::from_reader(t_reader)?;

        let t_low_lgbm = *t_config.thresholds.get("t_low_lgbm").unwrap_or(&0.01);
        let t_high_lgbm = *t_config.thresholds.get("t_high_lgbm").unwrap_or(&0.99);
        let t_low_lr = *t_config.thresholds.get("t_low_lr").unwrap_or(&0.01);
        let t_high_lr = *t_config.thresholds.get("t_high_lr").unwrap_or(&0.99);
        let t_low_ft = *t_config.thresholds.get("t_low_ft").unwrap_or(&0.01);
        let t_high_ft = *t_config.thresholds.get("t_high_ft").unwrap_or(&0.99);
        let t_consensus_attack = *t_config
            .thresholds
            .get("t_consensus_attack")
            .unwrap_or(&0.8);
        let t_consensus_benign = *t_config
            .thresholds
            .get("t_consensus_benign")
            .unwrap_or(&0.8);
        let t_bert = *t_config.thresholds.get("t_bert").unwrap_or(&0.9);

        Ok(PromptInjectionPipeline {
            l1,
            l2,
            l3: LazyOnnxTextClassifier::from_dir_with_paths(
                dir,
                vec!["benign".to_string(), "attack".to_string()],
                "wolf-defender-small",
                &[
                    "l3/onnx/onnx_fp16/model_fp16.onnx",
                    "l3/onnx/onnx_fp16/model.onnx",
                    "l3/onnx/model_fp16.onnx",
                    "l3/onnx/model.onnx",
                ],
                "l3/tokenizer.json",
                512,
            )?
            .map(Mutex::new),
            t_low_lgbm,
            t_high_lgbm,
            t_low_lr,
            t_high_lr,
            t_low_ft,
            t_high_ft,
            t_consensus_attack,
            t_consensus_benign,
            t_bert,
        })
    }

    fn thresholds(&self) -> HashMap<String, f64> {
        HashMap::from([
            ("t_low_lgbm".to_string(), self.t_low_lgbm),
            ("t_high_lgbm".to_string(), self.t_high_lgbm),
            ("t_low_lr".to_string(), self.t_low_lr),
            ("t_high_lr".to_string(), self.t_high_lr),
            ("t_low_ft".to_string(), self.t_low_ft),
            ("t_high_ft".to_string(), self.t_high_ft),
            ("t_consensus_attack".to_string(), self.t_consensus_attack),
            ("t_consensus_benign".to_string(), self.t_consensus_benign),
            ("t_bert".to_string(), self.t_bert),
        ])
    }

    fn l2_layer(
        &self,
        p_lgbm: f64,
        p_lr: f64,
        p_ft: f64,
        class_name: &str,
        confidence: f64,
        matched: bool,
        duration_ms: f64,
        decision: &str,
        votes: Option<(i32, i32, i32)>,
        timings: Option<&PromptInjectionL2Timings>,
    ) -> LayerResult {
        let mut details = HashMap::from([
            ("decision".to_string(), serde_json::json!(decision)),
            ("p_lgbm".to_string(), serde_json::json!(p_lgbm)),
            ("p_lr".to_string(), serde_json::json!(p_lr)),
            ("p_fasttext".to_string(), serde_json::json!(p_ft)),
        ]);
        if let Some(timings) = timings {
            details.insert(
                "feature_ms".to_string(),
                serde_json::json!(timings.feature_ms),
            );
            details.insert(
                "model_lgbm_ms".to_string(),
                serde_json::json!(timings.lgbm_ms),
            );
            details.insert(
                "model_logreg_ms".to_string(),
                serde_json::json!(timings.logistic_regression_ms),
            );
            details.insert(
                "model_fasttext_ms".to_string(),
                serde_json::json!(timings.fasttext_ms),
            );
            details.insert(
                "models_total_ms".to_string(),
                serde_json::json!(
                    timings.lgbm_ms + timings.logistic_regression_ms + timings.fasttext_ms
                ),
            );
        }
        if let Some((vote_lgbm, vote_lr, vote_ft)) = votes {
            details.insert(
                "vote_lgbm".to_string(),
                serde_json::json!(vote_label(vote_lgbm)),
            );
            details.insert(
                "vote_lr".to_string(),
                serde_json::json!(vote_label(vote_lr)),
            );
            details.insert(
                "vote_fasttext".to_string(),
                serde_json::json!(vote_label(vote_ft)),
            );
        }

        layer_result(
            "L2",
            "veto_consensus",
            class_name,
            confidence,
            matched,
            duration_ms,
            self.thresholds(),
            details,
        )
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        self.evaluate_with_max_level(text, SecurityLevel::L3)
    }

    pub fn has_l3_model(&self) -> bool {
        self.l3.is_some()
    }

    pub fn is_l3_loaded(&self) -> bool {
        self.l3
            .as_ref()
            .and_then(|l3| l3.lock().ok().map(|model| model.is_loaded()))
            .unwrap_or(false)
    }

    pub fn evaluate_with_max_level(
        &self,
        text: &str,
        max_level: SecurityLevel,
    ) -> EvaluationResult {
        self.evaluate_with_layers(text, max_level).0
    }

    pub fn evaluate_with_layers(
        &self,
        text: &str,
        max_level: SecurityLevel,
    ) -> (EvaluationResult, Vec<LayerResult>) {
        self.evaluate_with_execution(text, &ScanExecution::new(max_level))
            .expect("default scan execution enables at least L1")
    }

    pub fn evaluate_with_execution(
        &self,
        text: &str,
        execution: &ScanExecution,
    ) -> Option<(EvaluationResult, Vec<LayerResult>)> {
        let l1_enabled = execution.allows_level(SecurityLevel::L1);
        let l2_enabled = execution.allows_level(SecurityLevel::L2);
        let l3_enabled = execution.allows_level(SecurityLevel::L3);
        if !l1_enabled && !l2_enabled && !l3_enabled {
            return None;
        }

        let mut layers = Vec::new();

        let mut l1_benign = false;
        if l1_enabled {
            let l1_started = Instant::now();
            if self.l1.evaluate(text) {
                layers.push(layer_result(
                    "L1",
                    "heuristic",
                    "attack",
                    1.0,
                    true,
                    elapsed_ms(l1_started),
                    HashMap::new(),
                    HashMap::new(),
                ));
                return Some((
                    EvaluationResult {
                        class_name: "attack".to_string(),
                        confidence: 1.0,
                        level: "L1".to_string(),
                    },
                    layers,
                ));
            }
            layers.push(layer_result(
                "L1",
                "heuristic",
                "benign",
                0.0,
                false,
                elapsed_ms(l1_started),
                HashMap::new(),
                HashMap::new(),
            ));
            l1_benign = true;
        }

        if !l2_enabled && !l3_enabled && l1_benign {
            let result = EvaluationResult {
                class_name: "benign".to_string(),
                confidence: 1.0,
                level: SecurityLevel::L1.as_str().to_string(),
            };
            mark_last_level_layer_matched(&mut layers, &result);
            return Some((result, layers));
        }

        if l1_benign && l2_enabled && execution.long_text_policy().should_skip_full_l2(text) {
            return self.evaluate_long_text_after_l1(text, execution, layers, "benign");
        }

        let mut l2_fallback_confidence = None;
        if l2_enabled {
            let l2_started = Instant::now();
            let mut l2_buffers = PromptInjectionL2Buffers::new();
            let scores = self.l2.predict_c_with_buffers(text, &mut l2_buffers);
            let p_lgbm = scores.p_lgbm;
            let p_lr = scores.p_lr;
            let p_ft = scores.p_fasttext;

            let mut veto_attack = false;
            let mut veto_benign = false;
            let mut max_attack_conf: f64 = 0.0;
            let mut max_benign_conf: f64 = 0.0;
            let mut decision = if l3_enabled {
                "fallback_to_l3"
            } else {
                "fallback_to_l2"
            };

            if p_lgbm >= self.t_high_lgbm {
                veto_attack = true;
                max_attack_conf = max_attack_conf.max(p_lgbm);
            }
            if p_lgbm < self.t_low_lgbm {
                veto_benign = true;
                max_benign_conf = max_benign_conf.max(1.0 - p_lgbm);
            }

            if p_lr >= self.t_high_lr {
                veto_attack = true;
                max_attack_conf = max_attack_conf.max(p_lr);
            }
            if p_lr < self.t_low_lr {
                veto_benign = true;
                max_benign_conf = max_benign_conf.max(1.0 - p_lr);
            }

            // Match the calibrated legacy cascade: FastText participates in
            // consensus, but does not trigger high/low vetoes.

            if veto_attack && veto_benign {
                // Conflict -> Fallback to L3 when enabled, otherwise L2 fallback.
            } else if veto_attack {
                decision = "veto_attack";
                let result = EvaluationResult {
                    class_name: "attack".to_string(),
                    confidence: max_attack_conf,
                    level: "L2".to_string(),
                };
                layers.push(self.l2_layer(
                    p_lgbm,
                    p_lr,
                    p_ft,
                    "attack",
                    max_attack_conf,
                    true,
                    elapsed_ms(l2_started),
                    decision,
                    None,
                    Some(&scores.timings),
                ));
                return Some((result, layers));
            } else if veto_benign {
                decision = "veto_benign";
                let result = EvaluationResult {
                    class_name: "benign".to_string(),
                    confidence: max_benign_conf,
                    level: "L2".to_string(),
                };
                layers.push(self.l2_layer(
                    p_lgbm,
                    p_lr,
                    p_ft,
                    "benign",
                    max_benign_conf,
                    true,
                    elapsed_ms(l2_started),
                    decision,
                    None,
                    Some(&scores.timings),
                ));
                return Some((result, layers));
            }

            let vote_lgbm = if p_lgbm >= 0.5 { 1 } else { 0 };
            let vote_lr = if p_lr >= 0.5 { 1 } else { 0 };
            let vote_ft = if p_ft >= 0.5 { 1 } else { 0 };

            let sum_votes = vote_lgbm + vote_lr + vote_ft;
            let majority_class = if sum_votes >= 2 { 1 } else { 0 };

            let mut majority_confs = Vec::with_capacity(3);
            if majority_class == 1 {
                if vote_lgbm == 1 {
                    majority_confs.push(p_lgbm);
                }
                if vote_lr == 1 {
                    majority_confs.push(p_lr);
                }
                if vote_ft == 1 {
                    majority_confs.push(p_ft);
                }

                let avg_conf = majority_confs.iter().sum::<f64>() / majority_confs.len() as f64;
                if avg_conf >= self.t_consensus_attack {
                    decision = "consensus_attack";
                    let result = EvaluationResult {
                        class_name: "attack".to_string(),
                        confidence: avg_conf,
                        level: "L2".to_string(),
                    };
                    layers.push(self.l2_layer(
                        p_lgbm,
                        p_lr,
                        p_ft,
                        "attack",
                        avg_conf,
                        true,
                        elapsed_ms(l2_started),
                        decision,
                        Some((vote_lgbm, vote_lr, vote_ft)),
                        Some(&scores.timings),
                    ));
                    return Some((result, layers));
                }
            } else {
                if vote_lgbm == 0 {
                    majority_confs.push(1.0 - p_lgbm);
                }
                if vote_lr == 0 {
                    majority_confs.push(1.0 - p_lr);
                }
                if vote_ft == 0 {
                    majority_confs.push(1.0 - p_ft);
                }

                let avg_conf = majority_confs.iter().sum::<f64>() / majority_confs.len() as f64;
                if avg_conf >= self.t_consensus_benign {
                    decision = "consensus_benign";
                    let result = EvaluationResult {
                        class_name: "benign".to_string(),
                        confidence: avg_conf,
                        level: "L2".to_string(),
                    };
                    layers.push(self.l2_layer(
                        p_lgbm,
                        p_lr,
                        p_ft,
                        "benign",
                        avg_conf,
                        true,
                        elapsed_ms(l2_started),
                        decision,
                        Some((vote_lgbm, vote_lr, vote_ft)),
                        Some(&scores.timings),
                    ));
                    return Some((result, layers));
                }
            }

            let l2_matched = !l3_enabled;
            layers.push(self.l2_layer(
                p_lgbm,
                p_lr,
                p_ft,
                "benign",
                p_lgbm,
                l2_matched,
                elapsed_ms(l2_started),
                decision,
                Some((vote_lgbm, vote_lr, vote_ft)),
                Some(&scores.timings),
            ));
            if l2_matched {
                return Some((
                    EvaluationResult {
                        class_name: "benign".to_string(),
                        confidence: p_lgbm,
                        level: "L2".to_string(),
                    },
                    layers,
                ));
            }
            l2_fallback_confidence = Some(p_lgbm);
        }

        let mut fallback_due_to_error = false;
        if l3_enabled && execution.defer_l3() && self.l3.is_some() {
            if let Some(confidence) = l2_fallback_confidence {
                let result = EvaluationResult {
                    class_name: "benign".to_string(),
                    confidence,
                    level: "L2".to_string(),
                };
                layers.push(l3_pending_layer(&result, execution));
                return Some((result, layers));
            }
        }
        if l3_enabled {
            if let Some(l3) = &self.l3 {
                if let Ok(mut model) = l3.lock() {
                    let l3_started = Instant::now();
                    let l3_result = model.infer(text, execution.backend()).map(|result| {
                        let details = l3_metadata(
                            model.precision(),
                            model.model_path(),
                            model.model_name(),
                            model.execution_provider(),
                            "single",
                            1,
                        );
                        (result, details)
                    });
                    match l3_result {
                        Ok((result, details)) => {
                            layers.push(layer_result(
                                "L3",
                                "onnx",
                                &result.class_name,
                                result.confidence,
                                true,
                                elapsed_ms(l3_started),
                                HashMap::from([("t_bert".to_string(), self.t_bert)]),
                                details,
                            ));
                            return Some((result, layers));
                        }
                        Err(err) => {
                            let mut details = l3_metadata(
                                model.precision(),
                                model.model_path(),
                                model.model_name(),
                                model.execution_provider(),
                                "single",
                                1,
                            );
                            details.insert("error".to_string(), serde_json::json!(err.to_string()));
                            details.insert(
                                "fallback_due_to_error".to_string(),
                                serde_json::json!(true),
                            );
                            fallback_due_to_error = true;
                            layers.push(layer_result(
                                "L3",
                                "onnx_error",
                                "error",
                                0.0,
                                false,
                                elapsed_ms(l3_started),
                                HashMap::from([("t_bert".to_string(), self.t_bert)]),
                                details,
                            ));
                        }
                    }
                }
            }
        }

        if let Some(p_lgbm) = l2_fallback_confidence {
            let result = EvaluationResult {
                class_name: "benign".to_string(),
                confidence: if fallback_due_to_error {
                    degraded_fallback_confidence(p_lgbm)
                } else {
                    p_lgbm
                },
                level: "L2".to_string(),
            };
            mark_last_l2_layer_matched(&mut layers, &result);
            return Some((result, layers));
        }

        if l1_benign {
            let result = EvaluationResult {
                class_name: "benign".to_string(),
                confidence: 1.0,
                level: SecurityLevel::L1.as_str().to_string(),
            };
            mark_last_layer_matched(&mut layers, &result);
            return Some((result, layers));
        }

        None
    }

    fn evaluate_long_text_after_l1(
        &self,
        text: &str,
        execution: &ScanExecution,
        full_text_layers: Vec<LayerResult>,
        safe_class: &str,
    ) -> Option<(EvaluationResult, Vec<LayerResult>)> {
        let policy = execution.long_text_policy();
        let chunking = policy.chunking().ok()?;
        let chunks = chunk_text_bytes(text, chunking);
        let mut chunk_execution = execution.clone();
        let mut disabled_policy = policy;
        disabled_policy.enabled = false;
        chunk_execution.set_long_text_policy(disabled_policy);
        chunk_execution = chunk_execution.with_max_level(SecurityLevel::L2);

        let mut chunk_outputs = self.evaluate_batch_with_execution(&chunks, &chunk_execution);
        if execution.allows_level(SecurityLevel::L3) && !execution.defer_l3() {
            self.apply_l3_to_long_text_candidates(
                &chunks,
                &mut chunk_outputs,
                execution,
                safe_class,
            );
        }
        let mut aggregate = aggregate_chunk_outputs(
            full_text_layers,
            chunk_outputs,
            chunks.len(),
            safe_class,
            policy.verify_non_benign_l2,
        )?;
        if execution.allows_level(SecurityLevel::L3)
            && execution.defer_l3()
            && self.l3.is_some()
            && aggregate.result.level == "L2"
            && aggregate.result.class_name != safe_class
        {
            aggregate
                .layers
                .push(l3_pending_layer(&aggregate.result, execution));
        }
        Some((aggregate.result, aggregate.layers))
    }

    fn apply_l3_to_long_text_candidates(
        &self,
        chunks: &[String],
        chunk_outputs: &mut [(EvaluationResult, Vec<LayerResult>)],
        execution: &ScanExecution,
        safe_class: &str,
    ) {
        let policy = execution.long_text_policy();
        let selection = candidate_selection(chunk_outputs, |result, layers| {
            chunk_output_needs_l3(result, layers, safe_class, policy.verify_non_benign_l2)
        });
        if selection.indexes.is_empty() {
            return;
        }

        let raw_candidate_count = selection.raw_count;
        let deduped_candidate_count = selection.deduped_count;
        let dedup_strategy = selection.strategy;
        let candidate_indexes = selection.indexes;
        let l3_texts: Vec<String> = candidate_indexes
            .iter()
            .map(|index| chunks[*index].clone())
            .collect();
        let Some(l3_result) = infer_l3_candidate_texts(&self.l3, &l3_texts, execution) else {
            return;
        };
        let l3_results = match l3_result {
            Ok(results) => results,
            Err(err) => {
                for candidate_index in candidate_indexes {
                    let mut details = err.details.clone();
                    details.insert(
                        "candidate_reason".to_string(),
                        serde_json::json!("long_text_chunk"),
                    );
                    details.insert(
                        "candidate_raw_count".to_string(),
                        serde_json::json!(raw_candidate_count),
                    );
                    details.insert(
                        "candidate_deduped_count".to_string(),
                        serde_json::json!(deduped_candidate_count),
                    );
                    details.insert(
                        "candidate_dedup_strategy".to_string(),
                        serde_json::json!(dedup_strategy),
                    );
                    chunk_outputs[candidate_index].1.push(layer_result(
                        "L3",
                        "onnx_error",
                        "error",
                        0.0,
                        false,
                        err.duration_ms,
                        HashMap::from([("t_bert".to_string(), self.t_bert)]),
                        details,
                    ));
                    chunk_outputs[candidate_index].0.confidence =
                        degraded_fallback_confidence(chunk_outputs[candidate_index].0.confidence);
                }
                return;
            }
        };
        for (candidate_index, (result, mut details, duration_ms)) in
            candidate_indexes.into_iter().zip(l3_results)
        {
            details.insert(
                "candidate_reason".to_string(),
                serde_json::json!("long_text_chunk"),
            );
            details.insert(
                "candidate_raw_count".to_string(),
                serde_json::json!(raw_candidate_count),
            );
            details.insert(
                "candidate_deduped_count".to_string(),
                serde_json::json!(deduped_candidate_count),
            );
            details.insert(
                "candidate_dedup_strategy".to_string(),
                serde_json::json!(dedup_strategy),
            );
            chunk_outputs[candidate_index].1.push(layer_result(
                "L3",
                "onnx",
                &result.class_name,
                result.confidence,
                true,
                duration_ms,
                HashMap::from([("t_bert".to_string(), self.t_bert)]),
                details,
            ));
            chunk_outputs[candidate_index].0 = result;
        }
    }

    pub fn evaluate_batch(&self, texts: &[String]) -> Vec<EvaluationResult> {
        self.evaluate_batch_with_max_level(texts, SecurityLevel::L3)
    }

    pub fn evaluate_batch_with_max_level(
        &self,
        texts: &[String],
        max_level: SecurityLevel,
    ) -> Vec<EvaluationResult> {
        use rayon::prelude::*;
        texts
            .par_iter()
            .map(|text| self.evaluate_with_max_level(text, max_level))
            .collect()
    }

    pub fn evaluate_batch_with_layers(
        &self,
        texts: &[String],
        max_level: SecurityLevel,
    ) -> Vec<(EvaluationResult, Vec<LayerResult>)> {
        self.evaluate_batch_with_execution(texts, &ScanExecution::new(max_level))
    }

    pub fn evaluate_batch_with_execution(
        &self,
        texts: &[String],
        execution: &ScanExecution,
    ) -> Vec<(EvaluationResult, Vec<LayerResult>)> {
        if execution.onnx_batch_mode() == OnnxBatchMode::TensorBatch
            && execution.allows_level(SecurityLevel::L3)
        {
            return self.evaluate_batch_with_tensor_l3(texts, execution);
        }

        use rayon::prelude::*;
        if !execution.allows_level(SecurityLevel::L3) {
            return texts
                .par_iter()
                .map_init(PromptInjectionL2Buffers::new, |buffers, text| {
                    self.prepare_batch_eval_with_buffers(text, execution, buffers)
                })
                .filter_map(batch_eval_to_ready)
                .collect();
        }

        texts
            .par_iter()
            .filter_map(|text| self.evaluate_with_execution(text, execution))
            .collect()
    }

    fn evaluate_batch_with_tensor_l3(
        &self,
        texts: &[String],
        execution: &ScanExecution,
    ) -> Vec<(EvaluationResult, Vec<LayerResult>)> {
        use rayon::prelude::*;

        let prepared: Vec<Option<BatchEval>> = texts
            .par_iter()
            .map_init(PromptInjectionL2Buffers::new, |buffers, text| {
                self.prepare_batch_eval_with_buffers(text, execution, buffers)
            })
            .collect();
        let mut output = vec![None; texts.len()];
        let mut l3_indexes = Vec::new();
        let mut l3_texts = Vec::new();
        let mut l3_layers = Vec::new();
        let mut l3_fallbacks = Vec::new();

        for (index, item) in prepared.into_iter().enumerate() {
            match item {
                Some(BatchEval::Ready(result, layers)) => output[index] = Some((result, layers)),
                Some(BatchEval::NeedsL3 {
                    text,
                    layers,
                    fallback,
                }) => {
                    l3_indexes.push(index);
                    l3_texts.push(text);
                    l3_layers.push(layers);
                    l3_fallbacks.push(fallback);
                }
                None => {}
            }
        }

        if !l3_texts.is_empty() {
            let batch_result: Option<
                Result<
                    Vec<(EvaluationResult, HashMap<String, serde_json::Value>, f64)>,
                    Box<dyn std::error::Error>,
                >,
            > = self
                .l3
                .as_ref()
                .and_then(|l3| l3.lock().ok())
                .map(|mut model| {
                    let batch_started = Instant::now();
                    model
                        .infer_batch(&l3_texts, execution.backend())
                        .map(|results| {
                            let duration_ms = elapsed_ms(batch_started) / l3_texts.len() as f64;
                            let metadata = l3_metadata(
                                model.precision(),
                                model.model_path(),
                                model.model_name(),
                                model.execution_provider(),
                                "tensor_batch",
                                l3_texts.len(),
                            );
                            results
                                .into_iter()
                                .map(|result| (result, metadata.clone(), duration_ms))
                                .collect()
                        })
                });

            match batch_result {
                Some(Ok(results)) => {
                    for (((index, mut layers), fallback), result) in l3_indexes
                        .into_iter()
                        .zip(l3_layers)
                        .zip(l3_fallbacks)
                        .zip(results)
                    {
                        let (result, mut details, duration_ms) = result;
                        details.insert(
                            "fallback_had_l2".to_string(),
                            serde_json::json!(fallback.is_some()),
                        );
                        layers.push(layer_result(
                            "L3",
                            "onnx",
                            &result.class_name,
                            result.confidence,
                            true,
                            duration_ms,
                            HashMap::from([("t_bert".to_string(), self.t_bert)]),
                            details,
                        ));
                        output[index] = Some((result, layers));
                    }
                }
                Some(Err(err)) => {
                    for ((index, mut layers), fallback) in
                        l3_indexes.into_iter().zip(l3_layers).zip(l3_fallbacks)
                    {
                        let mut details = HashMap::from([
                            ("runtime".to_string(), serde_json::json!("onnxruntime")),
                            (
                                "batch_mode".to_string(),
                                serde_json::json!(execution.onnx_batch_mode().as_str()),
                            ),
                        ]);
                        details.insert("error".to_string(), serde_json::json!(err.to_string()));
                        details
                            .insert("fallback_due_to_error".to_string(), serde_json::json!(true));
                        layers.push(layer_result(
                            "L3",
                            "onnx_error",
                            "error",
                            0.0,
                            false,
                            0.0,
                            HashMap::from([("t_bert".to_string(), self.t_bert)]),
                            details,
                        ));
                        if let Some(mut fallback_result) = fallback {
                            if fallback_result.level == "L2" {
                                fallback_result.confidence =
                                    degraded_fallback_confidence(fallback_result.confidence);
                            }
                            mark_last_level_layer_matched(&mut layers, &fallback_result);
                            output[index] = Some((fallback_result, layers));
                        }
                    }
                }
                None => {
                    for ((index, mut layers), fallback) in
                        l3_indexes.into_iter().zip(l3_layers).zip(l3_fallbacks)
                    {
                        if let Some(fallback_result) = fallback {
                            mark_last_level_layer_matched(&mut layers, &fallback_result);
                            output[index] = Some((fallback_result, layers));
                        }
                    }
                }
            }
        }

        output.into_iter().flatten().collect()
    }

    fn prepare_batch_eval_with_buffers(
        &self,
        text: &str,
        execution: &ScanExecution,
        l2_buffers: &mut PromptInjectionL2Buffers,
    ) -> Option<BatchEval> {
        let l1_enabled = execution.allows_level(SecurityLevel::L1);
        let l2_enabled = execution.allows_level(SecurityLevel::L2);
        let l3_enabled = execution.allows_level(SecurityLevel::L3);
        if !l1_enabled && !l2_enabled && !l3_enabled {
            return None;
        }

        let mut layers = Vec::new();
        let mut l1_benign = false;
        if l1_enabled {
            let l1_started = Instant::now();
            if self.l1.evaluate(text) {
                layers.push(layer_result(
                    "L1",
                    "heuristic",
                    "attack",
                    1.0,
                    true,
                    elapsed_ms(l1_started),
                    HashMap::new(),
                    HashMap::new(),
                ));
                return Some(BatchEval::Ready(
                    EvaluationResult {
                        class_name: "attack".to_string(),
                        confidence: 1.0,
                        level: "L1".to_string(),
                    },
                    layers,
                ));
            }
            layers.push(layer_result(
                "L1",
                "heuristic",
                "benign",
                0.0,
                false,
                elapsed_ms(l1_started),
                HashMap::new(),
                HashMap::new(),
            ));
            l1_benign = true;
        }

        if !l2_enabled && !l3_enabled && l1_benign {
            let result = EvaluationResult {
                class_name: "benign".to_string(),
                confidence: 1.0,
                level: SecurityLevel::L1.as_str().to_string(),
            };
            mark_last_layer_matched(&mut layers, &result);
            return Some(BatchEval::Ready(result, layers));
        }

        if l1_benign && l2_enabled && execution.long_text_policy().should_skip_full_l2(text) {
            return self
                .evaluate_long_text_after_l1(text, execution, layers, "benign")
                .map(|(result, layers)| BatchEval::Ready(result, layers));
        }

        let mut fallback = None;
        if l2_enabled {
            let l2_started = Instant::now();
            let scores = self.l2.predict_c_with_buffers(text, l2_buffers);
            let p_lgbm = scores.p_lgbm;
            let p_lr = scores.p_lr;
            let p_ft = scores.p_fasttext;

            let mut veto_attack = false;
            let mut veto_benign = false;
            let mut max_attack_conf: f64 = 0.0;
            let mut max_benign_conf: f64 = 0.0;
            let mut decision = if l3_enabled {
                "fallback_to_l3"
            } else {
                "fallback_to_l2"
            };

            if p_lgbm >= self.t_high_lgbm {
                veto_attack = true;
                max_attack_conf = max_attack_conf.max(p_lgbm);
            }
            if p_lgbm < self.t_low_lgbm {
                veto_benign = true;
                max_benign_conf = max_benign_conf.max(1.0 - p_lgbm);
            }
            if p_lr >= self.t_high_lr {
                veto_attack = true;
                max_attack_conf = max_attack_conf.max(p_lr);
            }
            if p_lr < self.t_low_lr {
                veto_benign = true;
                max_benign_conf = max_benign_conf.max(1.0 - p_lr);
            }

            if veto_attack && !veto_benign {
                decision = "veto_attack";
                let result = EvaluationResult {
                    class_name: "attack".to_string(),
                    confidence: max_attack_conf,
                    level: "L2".to_string(),
                };
                layers.push(self.l2_layer(
                    p_lgbm,
                    p_lr,
                    p_ft,
                    "attack",
                    max_attack_conf,
                    true,
                    elapsed_ms(l2_started),
                    decision,
                    None,
                    Some(&scores.timings),
                ));
                return Some(BatchEval::Ready(result, layers));
            }
            if veto_benign && !veto_attack {
                decision = "veto_benign";
                let result = EvaluationResult {
                    class_name: "benign".to_string(),
                    confidence: max_benign_conf,
                    level: "L2".to_string(),
                };
                layers.push(self.l2_layer(
                    p_lgbm,
                    p_lr,
                    p_ft,
                    "benign",
                    max_benign_conf,
                    true,
                    elapsed_ms(l2_started),
                    decision,
                    None,
                    Some(&scores.timings),
                ));
                return Some(BatchEval::Ready(result, layers));
            }

            let vote_lgbm = if p_lgbm >= 0.5 { 1 } else { 0 };
            let vote_lr = if p_lr >= 0.5 { 1 } else { 0 };
            let vote_ft = if p_ft >= 0.5 { 1 } else { 0 };
            let sum_votes = vote_lgbm + vote_lr + vote_ft;
            let majority_class = if sum_votes >= 2 { 1 } else { 0 };
            let mut majority_confs = Vec::with_capacity(3);

            if majority_class == 1 {
                if vote_lgbm == 1 {
                    majority_confs.push(p_lgbm);
                }
                if vote_lr == 1 {
                    majority_confs.push(p_lr);
                }
                if vote_ft == 1 {
                    majority_confs.push(p_ft);
                }
                let avg_conf = majority_confs.iter().sum::<f64>() / majority_confs.len() as f64;
                if avg_conf >= self.t_consensus_attack {
                    decision = "consensus_attack";
                    let result = EvaluationResult {
                        class_name: "attack".to_string(),
                        confidence: avg_conf,
                        level: "L2".to_string(),
                    };
                    layers.push(self.l2_layer(
                        p_lgbm,
                        p_lr,
                        p_ft,
                        "attack",
                        avg_conf,
                        true,
                        elapsed_ms(l2_started),
                        decision,
                        Some((vote_lgbm, vote_lr, vote_ft)),
                        Some(&scores.timings),
                    ));
                    return Some(BatchEval::Ready(result, layers));
                }
            } else {
                if vote_lgbm == 0 {
                    majority_confs.push(1.0 - p_lgbm);
                }
                if vote_lr == 0 {
                    majority_confs.push(1.0 - p_lr);
                }
                if vote_ft == 0 {
                    majority_confs.push(1.0 - p_ft);
                }
                let avg_conf = majority_confs.iter().sum::<f64>() / majority_confs.len() as f64;
                if avg_conf >= self.t_consensus_benign {
                    decision = "consensus_benign";
                    let result = EvaluationResult {
                        class_name: "benign".to_string(),
                        confidence: avg_conf,
                        level: "L2".to_string(),
                    };
                    layers.push(self.l2_layer(
                        p_lgbm,
                        p_lr,
                        p_ft,
                        "benign",
                        avg_conf,
                        true,
                        elapsed_ms(l2_started),
                        decision,
                        Some((vote_lgbm, vote_lr, vote_ft)),
                        Some(&scores.timings),
                    ));
                    return Some(BatchEval::Ready(result, layers));
                }
            }

            let l2_matched = !l3_enabled;
            layers.push(self.l2_layer(
                p_lgbm,
                p_lr,
                p_ft,
                "benign",
                p_lgbm,
                l2_matched,
                elapsed_ms(l2_started),
                decision,
                Some((vote_lgbm, vote_lr, vote_ft)),
                Some(&scores.timings),
            ));
            let result = EvaluationResult {
                class_name: "benign".to_string(),
                confidence: p_lgbm,
                level: "L2".to_string(),
            };
            if l2_matched {
                return Some(BatchEval::Ready(result, layers));
            }
            fallback = Some(result);
        } else if l1_benign {
            fallback = Some(EvaluationResult {
                class_name: "benign".to_string(),
                confidence: 1.0,
                level: SecurityLevel::L1.as_str().to_string(),
            });
        }

        if l3_enabled {
            return Some(BatchEval::NeedsL3 {
                text: text.to_string(),
                layers,
                fallback,
            });
        }

        fallback.map(|result| {
            let mut layers = layers;
            mark_last_level_layer_matched(&mut layers, &result);
            BatchEval::Ready(result, layers)
        })
    }
}

fn chunk_output_needs_l3(
    result: &EvaluationResult,
    layers: &[LayerResult],
    safe_class: &str,
    verify_non_benign_l2: bool,
) -> bool {
    if verify_non_benign_l2 && result.class_name != safe_class {
        return true;
    }
    layers.iter().any(|layer| {
        if layer.level != "L2" {
            return false;
        }
        layer
            .details
            .get("decision")
            .and_then(|value| value.as_str())
            .is_some_and(|decision| decision == "fallback_to_l2" || decision == "fallback_to_l3")
    })
}

fn layer_result(
    level: &str,
    layer_type: &str,
    class_name: &str,
    confidence: f64,
    matched: bool,
    duration_ms: f64,
    thresholds: HashMap<String, f64>,
    details: HashMap<String, serde_json::Value>,
) -> LayerResult {
    LayerResult {
        level: level.to_string(),
        layer_type: layer_type.to_string(),
        class_name: class_name.to_string(),
        confidence,
        matched,
        duration_ms,
        thresholds,
        details,
    }
}

fn mark_last_layer_matched(layers: &mut [LayerResult], result: &EvaluationResult) {
    if let Some(last) = layers.last_mut() {
        last.class_name = result.class_name.clone();
        last.confidence = result.confidence;
        last.level = result.level.clone();
        last.matched = true;
    }
}

fn mark_last_l2_layer_matched(layers: &mut [LayerResult], result: &EvaluationResult) {
    if let Some(layer) = layers.iter_mut().rev().find(|layer| layer.level == "L2") {
        layer.class_name = result.class_name.clone();
        layer.confidence = result.confidence;
        layer.matched = true;
    } else {
        mark_last_layer_matched(layers, result);
    }
}

fn mark_last_level_layer_matched(layers: &mut [LayerResult], result: &EvaluationResult) {
    if let Some(layer) = layers
        .iter_mut()
        .rev()
        .find(|layer| layer.level == result.level && layer.layer_type != "onnx_error")
    {
        layer.class_name = result.class_name.clone();
        layer.confidence = result.confidence;
        layer.matched = true;
    } else {
        mark_last_layer_matched(layers, result);
    }
}

fn vote_label(vote: i32) -> &'static str {
    if vote == 1 {
        "attack"
    } else {
        "benign"
    }
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onnx_error_fallback_marks_l2_without_overwriting_error_layer() {
        let mut layers = vec![
            layer_result(
                "L2",
                "veto_consensus",
                "benign",
                0.72,
                false,
                1.0,
                HashMap::new(),
                HashMap::from([("decision".to_string(), serde_json::json!("fallback_to_l3"))]),
            ),
            layer_result(
                "L3",
                "onnx_error",
                "error",
                0.0,
                false,
                2.0,
                HashMap::new(),
                HashMap::from([("fallback_due_to_error".to_string(), serde_json::json!(true))]),
            ),
        ];
        let result = EvaluationResult {
            class_name: "benign".to_string(),
            confidence: degraded_fallback_confidence(0.72),
            level: "L2".to_string(),
        };

        mark_last_l2_layer_matched(&mut layers, &result);

        assert!(layers[0].matched);
        assert_eq!(layers[0].class_name, "benign");
        assert!((layers[0].confidence - 0.36).abs() < f64::EPSILON);
        assert!(!layers[1].matched);
        assert_eq!(layers[1].level, "L3");
        assert_eq!(layers[1].layer_type, "onnx_error");
        assert_eq!(
            layers[1].details.get("fallback_due_to_error"),
            Some(&serde_json::json!(true))
        );
    }
}
