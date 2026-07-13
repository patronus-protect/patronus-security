use crate::threat::{
    looks_like_encoded_instruction_request_lower, looks_like_obfuscated_instruction,
};
use crate::EvaluationResult;

pub struct EncodedInstructionPipeline;

impl EncodedInstructionPipeline {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        let is_violation = looks_like_encoded_instruction_request_lower(&text.to_lowercase())
            || looks_like_obfuscated_instruction(text);
        let class_name = if is_violation {
            "encoded_instruction"
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
