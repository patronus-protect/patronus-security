use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

use crate::ml::l1_heuristics::{HeuristicsEngine, RawRule};
use crate::ml::l2::{L2Classifier, L2ModelConfig};
use crate::ml::onnx::LazyOnnxTextClassifier;
use crate::{EvaluationResult, LayerResult, SecurityLevel};

#[derive(Debug, Deserialize)]
struct ThresholdsConfig {
    thresholds: HashMap<String, f64>,
    global_k: f64,
}

fn class_names_from_l2_config(config: &L2ModelConfig) -> Vec<String> {
    if let Some(names) = &config.class_names {
        return names.clone();
    }
    if let Some(lr_word) = &config.lr_word {
        if let Some(names) = &lr_word.class_names {
            return names.clone();
        }
    }
    if let Some(lr_char) = &config.lr_char {
        if let Some(names) = &lr_char.class_names {
            return names.clone();
        }
    }
    if let Some(fasttext) = &config.fasttext {
        if let Some(names) = &fasttext.class_names {
            return names.clone();
        }
    }
    if let Some(classes) = &config.classes {
        if classes.len() <= TOOL_CLASS_NAMES.len()
            && classes
                .iter()
                .all(|class_id| *class_id < TOOL_CLASS_NAMES.len())
        {
            return classes
                .iter()
                .map(|class_id| TOOL_CLASS_NAMES[*class_id].to_string())
                .collect();
        }
        return classes
            .iter()
            .map(|class_id| class_id.to_string())
            .collect();
    }
    vec!["safe".to_string(), "unsafe".to_string()]
}

const TOOL_CLASS_NAMES: &[&str] = &[
    "tool_class.file.read",
    "tool_class.file.search",
    "tool_class.file.list",
    "tool_class.file.write",
    "tool_class.file.delete",
    "tool_class.shell.execute",
    "tool_class.web.search",
    "tool_class.web.fetch",
    "tool_class.browser.action",
    "tool_class.api.read",
    "tool_class.api.write",
    "tool_class.database.read",
    "tool_class.database.write",
    "tool_class.vcs.read",
    "tool_class.vcs.write",
    "tool_class.memory.read",
    "tool_class.memory.write",
    "tool_class.messaging.send",
    "tool_class.unknown",
];

pub struct Pipeline {
    l1: HeuristicsEngine,
    l2: L2Classifier,
    l3: Option<Mutex<LazyOnnxTextClassifier>>,
    thresholds: HashMap<String, f64>,
    global_k: f64,
}

impl Pipeline {
    pub fn new<P: AsRef<Path>>(dir: P) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = dir.as_ref();

        // 1. Load L1 rules
        let r_file = File::open(dir.join("l1_rules.json"))?;
        let r_reader = BufReader::new(r_file);
        let raw_rules: Vec<RawRule> = serde_json::from_reader(r_reader)?;
        let l1 = HeuristicsEngine::new(raw_rules);

        // 2. Load L2 model config
        let m_file = File::open(dir.join("l2_config.json"))?;
        let m_reader = BufReader::new(m_file);
        let l2_config: L2ModelConfig = serde_json::from_reader(m_reader)?;
        let l3_class_names = class_names_from_l2_config(&l2_config);
        let l2 = L2Classifier::new(l2_config);

        // 3. Load thresholds config
        let t_file = File::open(dir.join("cascade_config.json"))?;
        let t_reader = BufReader::new(t_file);
        let t_config: ThresholdsConfig = serde_json::from_reader(t_reader)?;

        Ok(Pipeline {
            l1,
            l2,
            l3: LazyOnnxTextClassifier::from_dir(
                dir,
                l3_class_names,
                dir.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("onnx-classifier"),
            )?
            .map(Mutex::new),
            thresholds: t_config.thresholds,
            global_k: t_config.global_k,
        })
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

        // Step 1: L1 Heuristics
        let l1_started = Instant::now();
        if let Some((class_name, conf)) = self.l1.evaluate(text) {
            layers.push(layer_result(
                "L1",
                "rules",
                &class_name,
                conf,
                true,
                elapsed_ms(l1_started),
                HashMap::new(),
                HashMap::new(),
            ));
            return (
                EvaluationResult {
                    class_name,
                    confidence: conf,
                    level: "L1".to_string(),
                },
                layers,
            );
        }
        layers.push(layer_result(
            "L1",
            "rules",
            "safe",
            0.0,
            false,
            elapsed_ms(l1_started),
            HashMap::new(),
            HashMap::new(),
        ));

        if max_level < SecurityLevel::L2 {
            let result = EvaluationResult {
                class_name: "safe".to_string(),
                confidence: 1.0,
                level: SecurityLevel::L1.as_str().to_string(),
            };
            mark_last_layer_matched(&mut layers, &result);
            return (result, layers);
        }

        // Step 2: L2 Fast ML
        let l2_started = Instant::now();
        let (class_name, confidence) = self.l2.predict(text);
        let threshold = self
            .thresholds
            .get(&class_name)
            .copied()
            .unwrap_or(self.global_k);
        let l2_matched = confidence >= threshold || max_level < SecurityLevel::L3;
        let mut thresholds = HashMap::new();
        thresholds.insert("class_threshold".to_string(), threshold);
        thresholds.insert("global_k".to_string(), self.global_k);
        let mut details = HashMap::new();
        details.insert(
            "threshold_source".to_string(),
            serde_json::json!(if self.thresholds.contains_key(&class_name) {
                "class"
            } else {
                "global"
            }),
        );
        details.insert(
            "fallback_to_l3".to_string(),
            serde_json::json!(confidence < threshold && max_level >= SecurityLevel::L3),
        );
        layers.push(layer_result(
            "L2",
            "fast_ml",
            &class_name,
            confidence,
            l2_matched,
            elapsed_ms(l2_started),
            thresholds,
            details,
        ));

        if l2_matched {
            return (
                EvaluationResult {
                    class_name,
                    confidence,
                    level: "L2".to_string(),
                },
                layers,
            );
        }

        let mut fallback_due_to_error = false;
        if let Some(l3) = &self.l3 {
            if let Ok(mut model) = l3.lock() {
                let l3_started = Instant::now();
                match model.infer(text) {
                    Ok(result) => {
                        let mut details = HashMap::new();
                        details.insert("runtime".to_string(), serde_json::json!("onnxruntime"));
                        if let Some(precision) = model.precision() {
                            details.insert("precision".to_string(), serde_json::json!(precision));
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
                            HashMap::new(),
                            details,
                        ));
                        return (result, layers);
                    }
                    Err(err) => {
                        let mut details = HashMap::new();
                        details.insert("runtime".to_string(), serde_json::json!("onnxruntime"));
                        details.insert("error".to_string(), serde_json::json!(err.to_string()));
                        details
                            .insert("fallback_due_to_error".to_string(), serde_json::json!(true));
                        fallback_due_to_error = true;
                        if let Some(precision) = model.precision() {
                            details.insert("precision".to_string(), serde_json::json!(precision));
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
                            HashMap::new(),
                            details,
                        ));
                    }
                }
            }
        }

        let confidence = if fallback_due_to_error {
            degraded_fallback_confidence(confidence)
        } else {
            confidence
        };
        let result = EvaluationResult {
            class_name,
            confidence,
            level: "L2".to_string(),
        };
        mark_last_layer_matched(&mut layers, &result);
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
    if let Some(layer) = layers.last_mut() {
        layer.class_name.clone_from(&result.class_name);
        layer.confidence = result.confidence;
        layer.matched = true;
    }
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

fn degraded_fallback_confidence(confidence: f64) -> f64 {
    (confidence * 0.5).min(0.5)
}
