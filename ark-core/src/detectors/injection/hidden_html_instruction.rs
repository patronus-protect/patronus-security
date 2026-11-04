// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct HiddenHtmlInstructionPipeline;

impl Default for HiddenHtmlInstructionPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl HiddenHtmlInstructionPipeline {
    pub fn new() -> Self {
        Self
    }
}

impl crate::detectors::NativeDetector for HiddenHtmlInstructionPipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        super::signal::native_detection_prepared("hidden_html_instruction", prepared)
    }
}
