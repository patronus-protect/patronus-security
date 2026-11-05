// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct UnicodeConfusablePipeline;

impl Default for UnicodeConfusablePipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl UnicodeConfusablePipeline {
    pub fn new() -> Self {
        Self
    }
}

impl crate::detectors::NativeDetector for UnicodeConfusablePipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        super::signal::native_detection_prepared("unicode_confusable", prepared)
    }
}
