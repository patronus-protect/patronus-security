// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct ToolOutputInstructionPipeline;

impl Default for ToolOutputInstructionPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolOutputInstructionPipeline {
    pub fn new() -> Self {
        Self
    }
}

impl crate::detectors::NativeDetector for ToolOutputInstructionPipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        super::signal::native_detection_prepared("tool_output_instruction", prepared)
    }
}
