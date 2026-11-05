// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct AgenticControlAbusePipeline;

impl Default for AgenticControlAbusePipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl AgenticControlAbusePipeline {
    pub fn new() -> Self {
        Self
    }
}

impl crate::detectors::NativeDetector for AgenticControlAbusePipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        super::signal::native_detection_prepared("agentic_control_abuse", prepared)
    }
}
