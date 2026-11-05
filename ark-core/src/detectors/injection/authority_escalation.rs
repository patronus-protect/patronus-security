// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct AuthorityEscalationPipeline;

impl Default for AuthorityEscalationPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthorityEscalationPipeline {
    pub fn new() -> Self {
        Self
    }
}

impl crate::detectors::NativeDetector for AuthorityEscalationPipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        super::signal::native_detection_prepared("authority_escalation", prepared)
    }
}
