// SPDX-License-Identifier: GPL-3.0-only
use crate::EvaluationResult;

pub struct ToolCallInjectionPipeline;

impl Default for ToolCallInjectionPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolCallInjectionPipeline {
    pub fn new() -> Self {
        Self
    }

    pub(crate) fn detect(&self, text: &str) -> crate::detectors::NativeDetection {
        super::signal::native_detection("tool_call_injection", text)
    }

    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        self.detect(text).result
    }

    pub fn evaluate_batch(&self, texts: &[String]) -> Vec<EvaluationResult> {
        use rayon::prelude::*;
        texts.par_iter().map(|text| self.evaluate(text)).collect()
    }
}
