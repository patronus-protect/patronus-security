// SPDX-License-Identifier: GPL-3.0-only
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

    pub(crate) fn detect(&self, text: &str) -> crate::detectors::NativeDetection {
        self.detect_prepared(&crate::threat::NativeText::new(text))
    }

    pub(crate) fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        super::signal::native_detection_prepared("guardrail_tamper", prepared)
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        self.detect(text).result
    }

    pub fn evaluate_batch(&self, texts: &[String]) -> Vec<EvaluationResult> {
        use rayon::prelude::*;
        texts.par_iter().map(|t| self.evaluate(t)).collect()
    }
}
