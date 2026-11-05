// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct EncodedInstructionPipeline;

impl Default for EncodedInstructionPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl EncodedInstructionPipeline {
    pub fn new() -> Self {
        Self
    }
}

impl crate::detectors::NativeDetector for EncodedInstructionPipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        super::signal::native_detection_prepared("encoded_instruction", prepared)
    }
}
