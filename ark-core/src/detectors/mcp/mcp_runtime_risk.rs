// SPDX-License-Identifier: MIT OR Apache-2.0

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
}

impl crate::detectors::NativeDetector for McpRuntimeRiskPipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        let text = prepared.text();
        crate::detectors::evidence::detection_from_matches(
            text,
            "dlp_mcp_runtime_risk",
            "mcp_runtime_risk",
            crate::threat::native_matches_prepared("mcp_runtime_risk", prepared),
        )
    }
}
