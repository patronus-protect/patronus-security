// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct ZeroWidthObfuscationPipeline;

impl Default for ZeroWidthObfuscationPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl ZeroWidthObfuscationPipeline {
    pub fn new() -> Self {
        Self
    }
}

impl crate::detectors::NativeDetector for ZeroWidthObfuscationPipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        super::signal::native_detection_prepared("zero_width_obfuscation", prepared)
    }
}
