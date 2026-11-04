// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct MultiTurnEscalationPipeline;

impl Default for MultiTurnEscalationPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiTurnEscalationPipeline {
    pub fn new() -> Self {
        Self
    }
}

impl crate::detectors::NativeDetector for MultiTurnEscalationPipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        super::signal::native_detection_prepared("multi_turn_escalation", prepared)
    }
}
