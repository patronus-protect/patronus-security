// SPDX-License-Identifier: GPL-3.0-only
use crate::EvaluationResult;

pub struct EncodedInstructionPipeline;

impl Default for EncodedInstructionPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl EncodedInstructionPipeline {
    pub fn new() -> Self {
        Self
    }

    pub(crate) fn detect(&self, text: &str) -> crate::detectors::NativeDetection {
        super::signal::native_detection("encoded_instruction", text)
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        self.detect(text).result
    }

    pub fn evaluate_batch(&self, texts: &[String]) -> Vec<EvaluationResult> {
        use rayon::prelude::*;
        texts.par_iter().map(|t| self.evaluate(t)).collect()
    }
}
