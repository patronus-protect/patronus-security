// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct GuardrailTamperPipeline;

impl Default for GuardrailTamperPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl GuardrailTamperPipeline {
    pub fn new() -> Self {
        Self
    }
}

impl crate::detectors::NativeDetector for GuardrailTamperPipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        super::signal::native_detection_prepared("guardrail_tamper", prepared)
    }
}
