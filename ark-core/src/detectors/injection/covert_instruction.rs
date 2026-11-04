// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct CovertInstructionPipeline;

impl Default for CovertInstructionPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl CovertInstructionPipeline {
    pub fn new() -> Self {
        Self
    }
}

impl crate::detectors::NativeDetector for CovertInstructionPipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        super::signal::native_detection_prepared("covert_instruction", prepared)
    }
}
