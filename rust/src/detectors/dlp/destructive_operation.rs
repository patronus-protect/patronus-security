// SPDX-License-Identifier: GPL-3.0-only
use crate::threat::looks_like_destructive_operation_lower;
use crate::EvaluationResult;

pub struct DestructiveOperationPipeline;

impl Default for DestructiveOperationPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl DestructiveOperationPipeline {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        let is_violation = looks_like_destructive_operation_lower(&text.to_lowercase());
        let class_name = if is_violation {
            "destructive_operation"
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
