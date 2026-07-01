use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

use crate::ml::l1_heuristics::NativeHeuristicsEngine;
use crate::ml::l2::PromptInjectionClassifier;
use crate::ml::onnx::LazyOnnxTextClassifier;
use crate::{EvaluationResult, LayerResult, SecurityLevel};

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

impl PromptInjectionPipeline {
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
    ) -> LayerResult {
        let mut details = HashMap::from([
            ("decision".to_string(), serde_json::json!(decision)),
            ("p_lgbm".to_string(), serde_json::json!(p_lgbm)),
            ("p_lr".to_string(), serde_json::json!(p_lr)),
            ("p_fasttext".to_string(), serde_json::json!(p_ft)),
        ]);
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
        let mut layers = Vec::new();

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
            return (
                EvaluationResult {
                    class_name: "attack".to_string(),
                    confidence: 1.0,
                    level: "L1".to_string(),
                },
                layers,
            );
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

        if max_level < SecurityLevel::L2 {
            let result = EvaluationResult {
                class_name: "benign".to_string(),
                confidence: 1.0,
                level: SecurityLevel::L1.as_str().to_string(),
            };
            mark_last_layer_matched(&mut layers, &result);
            return (result, layers);
        }

        let l2_started = Instant::now();
        let features = self.l2.extract_features_c(text);
        let p_lgbm = self.l2.predict_c_from_features(&features);
        let p_lr = self.l2.predict_lr_from_features(&features);
        let p_ft = self.l2.predict_ft(text);

        let mut veto_attack = false;
        let mut veto_benign = false;
        let mut max_attack_conf: f64 = 0.0;
        let mut max_benign_conf: f64 = 0.0;
        let mut decision = "fallback_to_l3";

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
            // Conflict -> Fallback to L3
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
            ));
            return (result, layers);
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
            ));
            return (result, layers);
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
                ));
                return (result, layers);
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
                ));
                return (result, layers);
            }
        }

        layers.push(self.l2_layer(
            p_lgbm,
            p_lr,
            p_ft,
            "benign",
            p_lgbm,
            false,
            elapsed_ms(l2_started),
            decision,
            Some((vote_lgbm, vote_lr, vote_ft)),
        ));

        let mut fallback_due_to_error = false;
        if max_level >= SecurityLevel::L3 {
            if let Some(l3) = &self.l3 {
                if let Ok(mut model) = l3.lock() {
                    let l3_started = Instant::now();
                    match model.infer(text) {
                        Ok(result) => {
                            let mut details = HashMap::new();
                            details.insert("runtime".to_string(), serde_json::json!("onnxruntime"));
                            if let Some(precision) = model.precision() {
                                details
                                    .insert("precision".to_string(), serde_json::json!(precision));
                            }
                            if let Some(model_path) = model.model_path() {
                                details.insert(
                                    "model_file".to_string(),
                                    serde_json::json!(model_path.to_string_lossy().to_string()),
                                );
                            }
                            details.insert(
                                "model_name".to_string(),
                                serde_json::json!(model.model_name()),
                            );
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
                            return (result, layers);
                        }
                        Err(err) => {
                            let mut details = HashMap::new();
                            details.insert("runtime".to_string(), serde_json::json!("onnxruntime"));
                            details.insert("error".to_string(), serde_json::json!(err.to_string()));
                            details.insert(
                                "fallback_due_to_error".to_string(),
                                serde_json::json!(true),
                            );
                            fallback_due_to_error = true;
                            if let Some(precision) = model.precision() {
                                details
                                    .insert("precision".to_string(), serde_json::json!(precision));
                            }
                            if let Some(model_path) = model.model_path() {
                                details.insert(
                                    "model_file".to_string(),
                                    serde_json::json!(model_path.to_string_lossy().to_string()),
                                );
                            }
                            details.insert(
                                "model_name".to_string(),
                                serde_json::json!(model.model_name()),
                            );
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
        (result, layers)
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
        use rayon::prelude::*;
        texts
            .par_iter()
            .map(|text| self.evaluate_with_layers(text, max_level))
            .collect()
    }
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

fn degraded_fallback_confidence(confidence: f64) -> f64 {
    (confidence * 0.5).min(0.5)
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
