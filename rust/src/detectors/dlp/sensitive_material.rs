use crate::threat::looks_like_sensitive_material_request_lower;
use crate::EvaluationResult;

pub struct SensitiveMaterialPipeline;

impl SensitiveMaterialPipeline {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        let is_violation = looks_like_sensitive_material_request_lower(&text.to_lowercase());
        let class_name = if is_violation {
            "sensitive_material"
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
