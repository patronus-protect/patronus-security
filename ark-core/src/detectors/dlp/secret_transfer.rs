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
        crate::detectors::evidence::detection_from_matches(
            prepared.text(),
            "dlp_secret_transfer",
            "secret_transfer",
            crate::detectors::threat::native_requests(
                prepared,
                "secret_transfer",
                crate::SecurityCategory::Exfiltration,
            ),
        )
    }
}
