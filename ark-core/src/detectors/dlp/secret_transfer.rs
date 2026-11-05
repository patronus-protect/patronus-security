// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct SecretTransferPipeline;

impl Default for SecretTransferPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretTransferPipeline {
    pub fn new() -> Self {
        Self
    }
}

impl crate::detectors::NativeDetector for SecretTransferPipeline {
    fn detect_prepared(
        &self,
        prepared: &crate::threat::NativeText<'_>,
    ) -> crate::detectors::NativeDetection {
        let text = prepared.text();
        crate::detectors::evidence::detection_from_matches(
            text,
            "dlp_secret_transfer",
            "secret_transfer",
            crate::threat::native_matches_prepared("secret_transfer", prepared),
        )
    }
}
