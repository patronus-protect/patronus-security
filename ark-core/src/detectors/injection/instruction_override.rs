// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct InstructionOverridePipeline;

impl Default for InstructionOverridePipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl InstructionOverridePipeline {
    pub fn new() -> Self {
        Self
    }
}

impl crate::detectors::NativeDetector for InstructionOverridePipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        super::signal::native_detection_prepared("instruction_override", prepared)
    }
}
