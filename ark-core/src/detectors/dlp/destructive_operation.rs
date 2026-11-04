// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct DestructiveOperationPipeline;

impl Default for DestructiveOperationPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl DestructiveOperationPipeline {
    pub fn new() -> Self {
        Self
    }
}

impl crate::detectors::NativeDetector for DestructiveOperationPipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        let text = prepared.text();
        crate::detectors::evidence::detection_from_matches(
            text,
            "dlp_destructive_operation",
            "destructive_operation",
            crate::threat::native_matches_prepared("destructive_operation", prepared),
        )
    }
}
