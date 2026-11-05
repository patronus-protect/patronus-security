// SPDX-License-Identifier: MIT OR Apache-2.0

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
}

impl crate::detectors::NativeDetector for ToolCallInjectionPipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        super::signal::native_detection_prepared("tool_call_injection", prepared)
    }
}
