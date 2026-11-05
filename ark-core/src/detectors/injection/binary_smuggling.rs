// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct BinarySmugglingPipeline;

impl Default for BinarySmugglingPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl BinarySmugglingPipeline {
    pub fn new() -> Self {
        Self
    }
}

impl crate::detectors::NativeDetector for BinarySmugglingPipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        super::signal::native_detection_prepared("binary_smuggling", prepared)
    }
}
