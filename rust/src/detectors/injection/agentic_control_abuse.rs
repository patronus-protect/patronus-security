// SPDX-License-Identifier: GPL-3.0-only
use crate::EvaluationResult;

pub struct AgenticControlAbusePipeline;

impl Default for AgenticControlAbusePipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl AgenticControlAbusePipeline {
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
        super::signal::native_detection_prepared("agentic_control_abuse", prepared)
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        self.detect(text).result
    }

    pub fn evaluate_batch(&self, texts: &[String]) -> Vec<EvaluationResult> {
        use rayon::prelude::*;
        texts.par_iter().map(|t| self.evaluate(t)).collect()
    }
}
