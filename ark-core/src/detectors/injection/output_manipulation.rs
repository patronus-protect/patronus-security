// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct OutputManipulationPipeline;

impl Default for OutputManipulationPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputManipulationPipeline {
    pub fn new() -> Self {
        Self
    }
}

impl crate::detectors::NativeDetector for OutputManipulationPipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        super::signal::native_detection_prepared("output_manipulation", prepared)
    }
}
