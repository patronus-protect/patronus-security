// SPDX-License-Identifier: GPL-3.0-only
use crate::EvaluationResult;

pub struct JailbreakFramingPipeline;

impl Default for JailbreakFramingPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl JailbreakFramingPipeline {
    pub fn new() -> Self {
        Self
    }

    pub(crate) fn detect(&self, text: &str) -> crate::detectors::NativeDetection {
        super::signal::native_detection("jailbreak_framing", text)
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        self.detect(text).result
    }

    pub fn evaluate_batch(&self, texts: &[String]) -> Vec<EvaluationResult> {
        use rayon::prelude::*;
        texts.par_iter().map(|text| self.evaluate(text)).collect()
    }
}
