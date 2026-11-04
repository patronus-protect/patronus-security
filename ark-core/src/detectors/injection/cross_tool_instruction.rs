// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct CrossToolInstructionPipeline;

impl Default for CrossToolInstructionPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossToolInstructionPipeline {
    pub fn new() -> Self {
        Self
    }
}

impl crate::detectors::NativeDetector for CrossToolInstructionPipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        super::signal::native_detection_prepared("cross_tool_instruction", prepared)
    }
}
