// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct JailbreakFramingPipeline;

impl Default for JailbreakFramingPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl JailbreakFramingPipeline {
    pub fn new() -> Self {
        Self
    }
}

impl crate::detectors::NativeDetector for JailbreakFramingPipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        super::signal::native_detection_prepared("jailbreak_framing", prepared)
    }
}
