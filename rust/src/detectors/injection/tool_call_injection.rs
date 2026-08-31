// SPDX-License-Identifier: GPL-3.0-only
use crate::threat::looks_like_tool_call_injection_lower;
use crate::EvaluationResult;

pub struct ToolCallInjectionPipeline;

impl Default for ToolCallInjectionPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolCallInjectionPipeline {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        let matched = looks_like_tool_call_injection_lower(&text.to_lowercase());
        EvaluationResult {
            class_name: if matched {
                "tool_call_injection"
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
