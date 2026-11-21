// SPDX-License-Identifier: GPL-3.0-only
//! The request `config` of `POST /v1/scan`, shared by the Ark API worker and
//! the distributed coordinator: the coordinator validates a request with the
//! same type before it forwards it to a worker.
use patronus_ark_core::cascade::{ScanGateMatrix, SecurityLevel};
use patronus_ark_core::{
    ChunkOverlapTokens, DynamicPiiRequestConfig, NtdbOperatingPoint, SecurityCategory,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
/// The `config` object of `POST /v1/scan`.
///
/// [`Self::validate`] runs every check that needs no worker configuration; the
/// worker then resolves the request against its categories, API key and
/// `dynamic-pii` defaults.
pub struct RequestScanConfig {
    #[serde(default)]
    pub categories: Option<Vec<SecurityCategory>>,
    #[serde(default)]
    pub max_level: Option<SecurityLevel>,
    #[serde(default)]
    pub gates: Option<ScanGateMatrix>,
    /// A JSON object; `{}` when absent.
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
    /// Parsed by [`Self::ntdb_operating_point`].
    #[serde(default)]
    pub ntdb_operating_point: Option<String>,
    /// Parsed by [`Self::chunk_overlap_tokens`].
    #[serde(default)]
    pub chunk_overlap_tokens: Option<i64>,
    /// Request-local `dynamic-pii` labels, thresholds and gates; the worker's
    /// `pipeline.dynamic_pii` input limits, chunking and timeouts still apply.
    #[serde(default)]
    pub dynamic_pii: Option<DynamicPiiRequestConfig>,
}

fn empty_metadata() -> Value {
    Value::Object(Default::default())
}

impl RequestScanConfig {
    /// A request without a `config` object.
    pub fn empty() -> Self {
        Self {
            metadata: empty_metadata(),
            ..Default::default()
        }
    }

    /// Check everything that needs no worker configuration. `max_level` and
    /// `gates` were already validated while parsing.
    pub fn validate(&self) -> Result<(), String> {
        if !self.metadata.is_object() {
            return Err("config.metadata must be a JSON object".to_string());
        }
        if self
            .categories
            .as_ref()
            .is_some_and(|categories| categories.is_empty())
        {
            return Err("config.categories must not be empty".to_string());
        }
        self.ntdb_operating_point()?;
        self.chunk_overlap_tokens()?;
        if let Some(dynamic_pii) = &self.dynamic_pii {
            if let Some(categories) = &self.categories {
                require_dynamic_pii_category(categories)?;
            }
            dynamic_pii
                .clone()
                .validated_request()
                .map_err(|error| format!("config.dynamic_pii: {error}"))?;
        }
        Ok(())
    }

    /// The requested NTDB operating point, if any.
    pub fn ntdb_operating_point(&self) -> Result<Option<NtdbOperatingPoint>, String> {
        self.ntdb_operating_point
            .as_deref()
            .map(str::parse)
            .transpose()
    }

    /// The requested chunk overlap; zero when absent.
    pub fn chunk_overlap_tokens(&self) -> Result<ChunkOverlapTokens, String> {
        ChunkOverlapTokens::try_from(self.chunk_overlap_tokens.unwrap_or(0))
            .map_err(|error| format!("config.{error}"))
    }
}

/// A request-local `dynamic_pii` block needs the `dynamic-pii` category among
/// the request's categories.
pub fn require_dynamic_pii_category(categories: &[SecurityCategory]) -> Result<(), String> {
    if categories.contains(&SecurityCategory::DynamicPii) {
        Ok(())
    } else {
        Err("config.dynamic_pii requires the 'dynamic-pii' category in this request".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(value: Value) -> Result<(), String> {
        serde_json::from_value::<RequestScanConfig>(value)
            .map_err(|error| error.to_string())
            .and_then(|config| config.validate())
    }

    #[test]
    fn request_config_rejects_unknown_fields_and_bad_values() {
        assert_eq!(check(serde_json::json!({})), Ok(()));
        assert!(check(serde_json::json!({"extra": true})).is_err());
        assert!(check(serde_json::json!({"categories": ["unknown"]})).is_err());
        assert_eq!(
            check(serde_json::json!({"categories": []})),
            Err("config.categories must not be empty".to_string())
        );
        assert_eq!(
            check(serde_json::json!({"metadata": []})),
            Err("config.metadata must be a JSON object".to_string())
        );
        assert_eq!(
            check(serde_json::json!({"chunk_overlap_tokens": 65})),
            Err("config.chunk_overlap_tokens must be between 0 and 64".to_string())
        );
        assert_eq!(
            check(serde_json::json!({"ntdb_operating_point": "nope"})),
            Err("Unknown NTDB operating point: nope".to_string())
        );
        let config: RequestScanConfig = serde_json::from_value(serde_json::json!({
            "ntdb_operating_point": "best-fpr-in-f1", "chunk_overlap_tokens": 16
        }))
        .unwrap();
        assert_eq!(
            config.ntdb_operating_point(),
            Ok(Some(NtdbOperatingPoint::BestFprInF1))
        );
        assert_eq!(
            config.chunk_overlap_tokens().map(ChunkOverlapTokens::get),
            Ok(16)
        );
        assert_eq!(RequestScanConfig::empty().metadata, serde_json::json!({}));
    }

    #[test]
    fn dynamic_pii_block_is_validated_like_the_worker() {
        assert_eq!(
            check(serde_json::json!({
                "categories": ["dynamic-pii"],
                "dynamic_pii": {
                    "labels": ["street_address", "person"],
                    "label_thresholds": {"street_address": 0.4},
                    "execution_gate": {"type": "if_result_in", "pipeline": "dlp", "results": ["safe"]}
                }
            })),
            Ok(())
        );
        assert_eq!(
            check(serde_json::json!({"dynamic_pii": {"labels": ["person"]}})),
            Ok(())
        );
        let too_many = (0..31)
            .map(|index| format!("label_{index}"))
            .collect::<Vec<_>>();
        for invalid in [
            serde_json::json!({"categories": ["pii"], "dynamic_pii": {"labels": ["person"]}}),
            serde_json::json!({"dynamic_pii": {"labels": []}}),
            serde_json::json!({"dynamic_pii": {"labels": ["person"], "timeout_ms": 1}}),
            serde_json::json!({"dynamic_pii": {"labels": ["person"], "threshold": 1.5}}),
            serde_json::json!({"dynamic_pii": {"labels": ["person"], "label_thresholds": {"city": 0.4}}}),
            serde_json::json!({"dynamic_pii": {"labels": too_many}}),
            serde_json::json!({"dynamic_pii": {"labels": ["x".repeat(65)]}}),
            serde_json::json!({"dynamic_pii": {"labels": ["first_name", "first name"]}}),
            serde_json::json!({"dynamic_pii": {
                "labels": ["person"],
                "execution_gate": {"type": "if_no_result", "pipeline": "dynamic-pii"}
            }}),
            serde_json::json!({"dynamic_pii": ["street_address"]}),
        ] {
            assert!(
                check(invalid.clone()).is_err(),
                "{invalid} must be rejected"
            );
        }
    }
}
