// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct InstructionLeakPipeline;

impl Default for InstructionLeakPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl InstructionLeakPipeline {
    pub fn new() -> Self {
        Self
    }
}

impl crate::detectors::NativeDetector for InstructionLeakPipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        super::signal::native_detection_prepared("instruction_leak", prepared)
    }
}
