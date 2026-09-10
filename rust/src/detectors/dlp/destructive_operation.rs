// SPDX-License-Identifier: GPL-3.0-only
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

    pub(crate) fn detect(&self, text: &str) -> crate::detectors::NativeDetection {
        self.detect_prepared(&crate::threat::NativeText::new(text))
    }

    pub(crate) fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        let text = prepared.text();
        crate::detectors::evidence::detection_from_matches(
            text,
            "dlp_destructive_operation",
            "destructive_operation",
            crate::threat::native_matches_prepared("destructive_operation", prepared),
        )
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        self.detect(text).result
    }

    pub fn evaluate_batch(&self, texts: &[String]) -> Vec<EvaluationResult> {
        use rayon::prelude::*;
        texts.par_iter().map(|t| self.evaluate(t)).collect()
    }
}
