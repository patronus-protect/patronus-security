// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::EvaluationResult;

pub struct CovertInstructionPipeline;

impl Default for CovertInstructionPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl CovertInstructionPipeline {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, text: &str) -> crate::detectors::NativeDetection {
        self.detect_prepared(&crate::threat::NativeText::new(text))
    }

    pub fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        super::signal::native_detection_prepared("covert_instruction", prepared)
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        self.detect(text).result
    }

    pub fn evaluate_batch(&self, texts: &[String]) -> Vec<EvaluationResult> {
        use rayon::prelude::*;
        texts.par_iter().map(|text| self.evaluate(text)).collect()
    }
}
