// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct InstructionBoundaryPipeline;

impl Default for InstructionBoundaryPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl InstructionBoundaryPipeline {
    pub fn new() -> Self {
        Self
    }
}

impl crate::detectors::NativeDetector for InstructionBoundaryPipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        super::signal::native_detection_prepared("instruction_boundary", prepared)
    }
}
