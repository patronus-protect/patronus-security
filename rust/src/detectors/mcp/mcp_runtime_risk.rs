// SPDX-License-Identifier: GPL-3.0-only
use crate::EvaluationResult;

pub struct McpRuntimeRiskPipeline;

impl Default for McpRuntimeRiskPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl McpRuntimeRiskPipeline {
    pub fn new() -> Self {
        Self
    }

    pub(crate) fn detect(&self, text: &str) -> crate::detectors::NativeDetection {
        crate::detectors::evidence::detection_from_matches(
            text,
            "dlp_mcp_runtime_risk",
            "mcp_runtime_risk",
            crate::threat::native_matches("mcp_runtime_risk", text),
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
