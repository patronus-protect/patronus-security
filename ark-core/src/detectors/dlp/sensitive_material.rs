// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct SensitiveMaterialPipeline;

impl Default for SensitiveMaterialPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl SensitiveMaterialPipeline {
    pub fn new() -> Self {
        Self
    }
}

impl crate::detectors::NativeDetector for SensitiveMaterialPipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        let text = prepared.text();
        crate::detectors::evidence::detection_from_matches(
            text,
            "dlp_sensitive_material",
            "sensitive_material",
            crate::threat::native_matches_prepared("sensitive_material", prepared),
        )
    }
}
