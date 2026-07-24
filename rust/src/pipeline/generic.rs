// SPDX-License-Identifier: GPL-3.0-only
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::time::Instant;

use super::decision_cache::DecisionCache;
use crate::ml::l1_heuristics::{HeuristicsEngine, RawRule};
use crate::{EvaluationResult, LayerResult, ScanExecution, SecurityLevel};

pub struct Pipeline {
    l1: HeuristicsEngine,
    cache_namespace: String,
    decision_cache: DecisionCache,
}

impl Pipeline {
    pub fn new<P: AsRef<Path>>(dir: P) -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_with_max_level(dir, SecurityLevel::L1)
    }

    pub fn new_with_max_level<P: AsRef<Path>>(
        dir: P,
        _max_level: SecurityLevel,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = dir.as_ref();
        let rules_file = File::open(dir.join("l1_rules.json"))?;
        let rules_reader = BufReader::new(rules_file);
        let raw_rules: Vec<RawRule> = serde_json::from_reader(rules_reader)?;
        Ok(Pipeline {
            l1: HeuristicsEngine::new(raw_rules),
            cache_namespace: cache_namespace(dir),
            decision_cache: DecisionCache::default(),
        })
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        self.evaluate_with_max_level(text, SecurityLevel::L1)
    }

    pub fn has_l3_model(&self) -> bool {
        false
    }

    pub fn is_l3_loaded(&self) -> bool {
        false
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
            .unwrap_or_else(|| {
                (
                    EvaluationResult {
                        class_name: "disabled".to_string(),
                        confidence: 0.0,
                        level: SecurityLevel::L1.as_str().to_string(),
                    },
                    Vec::new(),
                )
            })
    }

    pub fn evaluate_with_execution(
        &self,
        text: &str,
        execution: &ScanExecution,
    ) -> Option<(EvaluationResult, Vec<LayerResult>)> {
        if !execution.allows_level(SecurityLevel::L1) {
            return None;
        }

        if let Some(cached) = self
            .decision_cache
            .get(&self.cache_namespace, text, execution)
        {
            return Some(cached);
        }

        let started = Instant::now();
        let (class_name, confidence) = self
            .l1
            .evaluate(text)
            .unwrap_or_else(|| ("safe".to_string(), 1.0));
        let result = EvaluationResult {
            class_name,
            confidence,
            level: SecurityLevel::L1.as_str().to_string(),
        };
        let layers = vec![LayerResult {
            level: result.level.clone(),
            layer_type: "rules".to_string(),
            class_name: result.class_name.clone(),
            confidence: result.confidence,
            matched: true,
            duration_ms: elapsed_ms(started),
            thresholds: HashMap::new(),
            details: HashMap::new(),
        }];
        self.decision_cache
            .insert(&self.cache_namespace, text, execution, &result, &layers);
        Some((result, layers))
    }

    pub fn evaluate_batch(&self, texts: &[String]) -> Vec<EvaluationResult> {
        self.evaluate_batch_with_max_level(texts, SecurityLevel::L1)
    }

    pub fn evaluate_batch_with_max_level(
        &self,
        texts: &[String],
        max_level: SecurityLevel,
    ) -> Vec<EvaluationResult> {
        texts
            .iter()
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
        texts
            .iter()
            .filter_map(|text| self.evaluate_with_execution(text, execution))
            .collect()
    }
}

fn cache_namespace(dir: &Path) -> String {
    format!("rules:{}", dir.display())
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}
