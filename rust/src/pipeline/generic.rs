use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

use super::decision_cache::DecisionCache;
use super::long_text::{
    aggregate_chunk_outputs, candidate_selection, chunk_text_bytes, infer_l3_candidate_texts,
    l3_metadata,
};
use super::PipelineStrategy;
use super::{degraded_fallback_confidence, l3_pending_layer};
use crate::ml::l1_heuristics::{HeuristicsEngine, RawRule};
use crate::ml::l2::{L2Classifier, L2ModelConfig};
use crate::ml::onnx::LazyOnnxTextClassifier;
use crate::{EvaluationResult, LayerResult, OnnxBatchMode, ScanExecution, SecurityLevel};

#[derive(Debug, Deserialize)]
struct ThresholdsConfig {
    thresholds: HashMap<String, f64>,
    global_k: f64,
}

pub(crate) fn class_names_from_l2_config(config: &L2ModelConfig) -> Vec<String> {
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
    l2: Option<L2Classifier>,
    l3: Option<Mutex<LazyOnnxTextClassifier>>,
    thresholds: HashMap<String, f64>,
    global_k: f64,
    cache_namespace: String,
    decision_cache: DecisionCache,
    strategy: PipelineStrategy,
}

enum BatchEval {
    Ready(EvaluationResult, Vec<LayerResult>),
    NeedsL3 {
        text: String,
        layers: Vec<LayerResult>,
        fallback: Option<EvaluationResult>,
    },
}

impl Pipeline {
    pub(crate) fn l3_worker_model(&self) -> Option<LazyOnnxTextClassifier> {
        self.l3
            .as_ref()
            .map(|model| model.lock().expect("l3 mutex poisoned").metadata_clone())
    }

    pub fn new<P: AsRef<Path>>(dir: P) -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_with_max_level(dir, SecurityLevel::L3)
    }

    pub fn new_with_max_level<P: AsRef<Path>>(
        dir: P,
        max_level: SecurityLevel,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_with_strategy(dir, max_level, PipelineStrategy::generic_text_local_multi())
    }

    pub(crate) fn new_with_strategy<P: AsRef<Path>>(
        dir: P,
        max_level: SecurityLevel,
        strategy: PipelineStrategy,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = dir.as_ref();

        // 1. Load L1 rules
        let r_file = File::open(dir.join("l1_rules.json"))?;
        let r_reader = BufReader::new(r_file);
        let raw_rules: Vec<RawRule> = serde_json::from_reader(r_reader)?;
        let l1 = HeuristicsEngine::new(raw_rules);

        if max_level == SecurityLevel::L1 {
            return Ok(Pipeline {
                l1,
                l2: None,
                l3: None,
                thresholds: HashMap::new(),
                global_k: 0.0,
                cache_namespace: cache_namespace(dir),
                decision_cache: DecisionCache::default(),
                strategy,
            });
        }

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
            l2: Some(l2),
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
            cache_namespace: cache_namespace(dir),
            decision_cache: DecisionCache::default(),
            strategy,
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

        if let Some(cached) = self
            .decision_cache
            .get(&self.cache_namespace, text, execution)
        {
            return Some(cached);
        }

        let mut layers = Vec::new();

        let mut l1_safe = false;
        if l1_enabled {
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
                return self.cache_and_return(
                    text,
                    execution,
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
            l1_safe = true;
        }

        if !l2_enabled && !l3_enabled && l1_safe {
            let result = EvaluationResult {
                class_name: "safe".to_string(),
                confidence: 1.0,
                level: SecurityLevel::L1.as_str().to_string(),
            };
            mark_last_layer_matched(&mut layers, &result);
            return self.cache_and_return(text, execution, result, layers);
        }

        if l1_safe
            && l2_enabled
            && self
                .strategy
                .should_skip_full_l2(text, execution.long_text_policy())
        {
            return self
                .evaluate_long_text_after_l1(text, execution, layers, "safe")
                .and_then(|(result, layers)| {
                    self.cache_and_return(text, execution, result, layers)
                });
        }

        let mut l2_candidate = None;
        if l2_enabled {
            let l2_started = Instant::now();
            let Some(l2) = &self.l2 else {
                return if l1_safe {
                    let result = EvaluationResult {
                        class_name: "safe".to_string(),
                        confidence: 1.0,
                        level: SecurityLevel::L1.as_str().to_string(),
                    };
                    mark_last_layer_matched(&mut layers, &result);
                    self.cache_and_return(text, execution, result, layers)
                } else {
                    None
                };
            };
            let (class_name, confidence) = l2.predict(text);
            let threshold = self
                .thresholds
                .get(&class_name)
                .copied()
                .unwrap_or(self.global_k);
            let l2_matched = confidence >= threshold || !l3_enabled;
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
                serde_json::json!(confidence < threshold && l3_enabled),
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
                return self.cache_and_return(
                    text,
                    execution,
                    EvaluationResult {
                        class_name,
                        confidence,
                        level: "L2".to_string(),
                    },
                    layers,
                );
            }
            l2_candidate = Some((class_name, confidence));
        }

        let mut fallback_due_to_error = false;
        if l3_enabled && !self.strategy.l3_allowed_for_text(text) {
            if let Some((class_name, confidence)) = l2_candidate {
                let result = EvaluationResult {
                    class_name,
                    confidence,
                    level: "L2".to_string(),
                };
                layers.push(l3_skipped_size_layer(
                    &result,
                    self.strategy.l3_max_bytes,
                    text.len(),
                ));
                mark_last_level_layer_matched(&mut layers, &result);
                return self.cache_and_return(text, execution, result, layers);
            }
        }

        if l3_enabled && execution.defer_l3() && self.l3.is_some() {
            if let Some((class_name, confidence)) = l2_candidate {
                let result = EvaluationResult {
                    class_name,
                    confidence,
                    level: "L2".to_string(),
                };
                layers.push(l3_pending_layer(&result, execution));
                return self.cache_and_return(text, execution, result, layers);
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
                                HashMap::new(),
                                details,
                            ));
                            return self.cache_and_return(text, execution, result, layers);
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
                                HashMap::new(),
                                details,
                            ));
                        }
                    }
                }
            }
        }

        if let Some((class_name, confidence)) = l2_candidate {
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
            mark_last_level_layer_matched(&mut layers, &result);
            return self.cache_and_return(text, execution, result, layers);
        }

        if l1_safe {
            let result = EvaluationResult {
                class_name: "safe".to_string(),
                confidence: 1.0,
                level: SecurityLevel::L1.as_str().to_string(),
            };
            mark_last_layer_matched(&mut layers, &result);
            return self.cache_and_return(text, execution, result, layers);
        }

        None
    }

    fn cache_and_return(
        &self,
        text: &str,
        execution: &ScanExecution,
        result: EvaluationResult,
        layers: Vec<LayerResult>,
    ) -> Option<(EvaluationResult, Vec<LayerResult>)> {
        self.decision_cache
            .insert(&self.cache_namespace, text, execution, &result, &layers);
        Some((result, layers))
    }

    fn evaluate_long_text_after_l1(
        &self,
        text: &str,
        execution: &ScanExecution,
        full_text_layers: Vec<LayerResult>,
        safe_class: &str,
    ) -> Option<(EvaluationResult, Vec<LayerResult>)> {
        let policy = self.strategy.long_text_policy(execution.long_text_policy());
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
            self.strategy.aggregation,
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
        let policy = self.strategy.long_text_policy(execution.long_text_policy());
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
                        HashMap::new(),
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
                HashMap::new(),
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
            .map(|text| self.prepare_batch_eval(text, execution))
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
                            HashMap::new(),
                            details,
                        ));
                        output[index] = Some((result, layers));
                    }
                }
                Some(Err(err)) => {
                    for ((index, mut layers), fallback) in
                        l3_indexes.into_iter().zip(l3_layers).zip(l3_fallbacks)
                    {
                        let details = HashMap::from([
                            ("runtime".to_string(), serde_json::json!("onnxruntime")),
                            (
                                "batch_mode".to_string(),
                                serde_json::json!(execution.onnx_batch_mode().as_str()),
                            ),
                        ]);
                        let mut details = details;
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
                            HashMap::new(),
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

    fn prepare_batch_eval(&self, text: &str, execution: &ScanExecution) -> Option<BatchEval> {
        let l1_enabled = execution.allows_level(SecurityLevel::L1);
        let l2_enabled = execution.allows_level(SecurityLevel::L2);
        let l3_enabled = execution.allows_level(SecurityLevel::L3);
        if !l1_enabled && !l2_enabled && !l3_enabled {
            return None;
        }

        let mut layers = Vec::new();
        let mut l1_safe = false;
        if l1_enabled {
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
                return Some(BatchEval::Ready(
                    EvaluationResult {
                        class_name,
                        confidence: conf,
                        level: "L1".to_string(),
                    },
                    layers,
                ));
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
            l1_safe = true;
        }

        if !l2_enabled && !l3_enabled && l1_safe {
            let result = EvaluationResult {
                class_name: "safe".to_string(),
                confidence: 1.0,
                level: SecurityLevel::L1.as_str().to_string(),
            };
            mark_last_layer_matched(&mut layers, &result);
            return Some(BatchEval::Ready(result, layers));
        }

        if l1_safe
            && l2_enabled
            && self
                .strategy
                .should_skip_full_l2(text, execution.long_text_policy())
        {
            return self
                .evaluate_long_text_after_l1(text, execution, layers, "safe")
                .map(|(result, layers)| BatchEval::Ready(result, layers));
        }

        let mut fallback = None;
        if l2_enabled {
            let l2_started = Instant::now();
            let Some(l2) = &self.l2 else {
                return if l1_safe {
                    let result = EvaluationResult {
                        class_name: "safe".to_string(),
                        confidence: 1.0,
                        level: SecurityLevel::L1.as_str().to_string(),
                    };
                    mark_last_layer_matched(&mut layers, &result);
                    Some(BatchEval::Ready(result, layers))
                } else {
                    None
                };
            };
            let (class_name, confidence) = l2.predict(text);
            let threshold = self
                .thresholds
                .get(&class_name)
                .copied()
                .unwrap_or(self.global_k);
            let l2_matched = confidence >= threshold || !l3_enabled;
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
                serde_json::json!(confidence < threshold && l3_enabled),
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
            let result = EvaluationResult {
                class_name,
                confidence,
                level: "L2".to_string(),
            };
            if l2_matched {
                return Some(BatchEval::Ready(result, layers));
            }
            fallback = Some(result);
        } else if l1_safe {
            fallback = Some(EvaluationResult {
                class_name: "safe".to_string(),
                confidence: 1.0,
                level: SecurityLevel::L1.as_str().to_string(),
            });
        }

        if l3_enabled && !self.strategy.l3_allowed_for_text(text) {
            return fallback.map(|result| {
                let mut layers = layers;
                layers.push(l3_skipped_size_layer(
                    &result,
                    self.strategy.l3_max_bytes,
                    text.len(),
                ));
                mark_last_level_layer_matched(&mut layers, &result);
                BatchEval::Ready(result, layers)
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

fn cache_namespace(dir: &Path) -> String {
    format!("generic:{}", dir.to_string_lossy())
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
        if let Some(threshold) = layer
            .thresholds
            .get("class_threshold")
            .or_else(|| layer.thresholds.get("global_k"))
        {
            return layer.confidence < *threshold;
        }
        false
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

fn l3_skipped_size_layer(
    result: &EvaluationResult,
    max_bytes: Option<usize>,
    text_bytes: usize,
) -> LayerResult {
    layer_result(
        "L3",
        "onnx_skipped",
        &result.class_name,
        result.confidence,
        false,
        0.0,
        HashMap::new(),
        HashMap::from([
            (
                "reason".to_string(),
                serde_json::json!("text_too_large_for_l3"),
            ),
            ("text_bytes".to_string(), serde_json::json!(text_bytes)),
            ("max_bytes".to_string(), serde_json::json!(max_bytes)),
        ]),
    )
}

fn mark_last_layer_matched(layers: &mut [LayerResult], result: &EvaluationResult) {
    if let Some(layer) = layers.last_mut() {
        layer.class_name.clone_from(&result.class_name);
        layer.confidence = result.confidence;
        layer.matched = true;
    }
}

fn mark_last_level_layer_matched(layers: &mut [LayerResult], result: &EvaluationResult) {
    if let Some(layer) = layers
        .iter_mut()
        .rev()
        .find(|layer| layer.level == result.level && layer.layer_type != "onnx_error")
    {
        layer.class_name.clone_from(&result.class_name);
        layer.confidence = result.confidence;
        layer.matched = true;
    } else {
        mark_last_layer_matched(layers, result);
    }
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}
