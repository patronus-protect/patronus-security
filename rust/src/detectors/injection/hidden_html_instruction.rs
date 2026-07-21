// SPDX-License-Identifier: GPL-3.0-only
use crate::threat::looks_like_hidden_html_instruction;
use crate::EvaluationResult;

pub struct HiddenHtmlInstructionPipeline;

impl HiddenHtmlInstructionPipeline {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        let is_violation = looks_like_hidden_html_instruction(text);
        let class_name = if is_violation {
            "hidden_html_instruction"
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
