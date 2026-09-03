// SPDX-License-Identifier: GPL-3.0-only
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

    pub(crate) fn detect(&self, text: &str) -> crate::detectors::NativeDetection {
        crate::detectors::evidence::detection_from_matches(
            text,
            "dlp_secret_transfer",
            "secret_transfer",
            crate::threat::native_matches("secret_transfer", text),
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
