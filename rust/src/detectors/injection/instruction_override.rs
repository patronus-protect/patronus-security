// SPDX-License-Identifier: AGPL-3.0-only
use crate::threat::looks_like_instruction_override_lower;
use crate::EvaluationResult;

pub struct InstructionOverridePipeline;

impl InstructionOverridePipeline {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        let matched = looks_like_instruction_override_lower(&text.to_lowercase());
        EvaluationResult {
            class_name: if matched {
                "instruction_override"
            } else {
                "safe"
            }
            .to_string(),
            confidence: 1.0,
            level: "L1".to_string(),
        }
    }

    pub fn evaluate_batch(&self, texts: &[String]) -> Vec<EvaluationResult> {
        use rayon::prelude::*;
        texts.par_iter().map(|text| self.evaluate(text)).collect()
    }
}
