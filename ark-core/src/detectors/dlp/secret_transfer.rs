// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::EvaluationResult;

pub struct SecretTransferPipeline;

impl Default for SecretTransferPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretTransferPipeline {
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
        let text = prepared.text();
        crate::detectors::evidence::detection_from_matches(
            text,
            "dlp_secret_transfer",
            "secret_transfer",
            crate::threat::native_matches_prepared("secret_transfer", prepared),
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
