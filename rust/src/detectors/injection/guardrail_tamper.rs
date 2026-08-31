// SPDX-License-Identifier: GPL-3.0-only
use crate::threat::looks_like_guardrail_tamper_lower;
use crate::EvaluationResult;

pub struct GuardrailTamperPipeline;

impl Default for GuardrailTamperPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl GuardrailTamperPipeline {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        let is_violation = looks_like_guardrail_tamper_lower(&text.to_lowercase());
        let class_name = if is_violation {
            "guardrail_tamper"
        } else {
            "safe"
        };
        EvaluationResult {
            class_name: class_name.to_string(),
            confidence: 1.0,
            level: "L1".to_string(),
        }
    }

    pub fn evaluate_batch(&self, texts: &[String]) -> Vec<EvaluationResult> {
        use rayon::prelude::*;
        texts.par_iter().map(|t| self.evaluate(t)).collect()
    }
}
