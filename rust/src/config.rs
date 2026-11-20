// SPDX-License-Identifier: GPL-3.0-only
//! Ark's one gateway config: Ark Core's [`ScannerConfig`] plus Ark's own keys.

use std::path::PathBuf;
use std::time::Duration;

use patronus_ark_core::warmup::DownloadPolicy;
use patronus_ark_core::ScannerConfig;
use serde::{Deserialize, Deserializer};

use crate::{
    CacheEncryptionConfig, CacheWriteMode, DynamicPiiConfig, ExactCacheConfig, ExecutionBackend,
    L3Strategy, MemoryCacheConfig, NtdbOperatingPoint, OnnxBatchMode, OnnxRuntimeOptions,
    PersistentCacheConfig, SecurityCategory, SecurityLevel,
};

/// The config of a [`crate::SecurityGateway`]: every key of Ark Core's
/// [`ScannerConfig`] (`categories`, `max_level`, the gate keys, `cascade`,
/// `cache_root`, `wolf`, `shell`) with the same meaning, plus Ark's own keys.
/// Ark accepts every category, not only Core's text-scan ones, and reads
/// Core's `wolf` and `shell` for its injection L3 and its `shell_command`
/// category. Core's `max_input_bytes` and `max_findings` limit Core's
/// scanner only. Unknown keys are refused.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GatewayConfig {
    /// Core's keys, at the top level of the config.
    #[serde(flatten)]
    pub core: ScannerConfig,
    /// Whether `warmup`/`prepare_assets` may download missing model files:
    /// `never` (default) or `missing`.
    pub download: DownloadPolicy,
    /// The categories that may download; unset: every configured category.
    pub download_categories: Option<Vec<SecurityCategory>>,
    /// Physical L3 classifier topology: `dedicated` (default) or `multi`.
    pub l3_strategy: L3Strategy,
    /// Calibrated NTDB operating point. Default: `best_promote`.
    pub ntdb_operating_point: NtdbOperatingPoint,
    /// Calibrated NTDB final-decision threshold set. Default: `best_f1`.
    pub ntdb_decision_threshold_point: NtdbOperatingPoint,
    /// ONNX execution backend of Ark's models: `auto` (default), `cpu`,
    /// `gpu`, `coreml`, ...
    pub execution_backend: ExecutionBackend,
    /// L3 batch execution; unset follows `execution_backend`.
    pub onnx_batch_mode: Option<OnnxBatchMode>,
    /// ONNX Runtime session options of Ark's models.
    pub onnx_runtime: OnnxRuntimeOptions,
    /// The `dynamic_pii` (GLiNER) pipeline's config.
    pub dynamic_pii: DynamicPiiConfig,
    /// The exact decision cache (key `cache`): `storage_location`,
    /// `encryption_key_hex`, `entry_ttl_seconds`, `memory_max_entries`,
    /// `memory_max_bytes`. Without a storage location it stays in memory.
    #[serde(deserialize_with = "deserialize_cache")]
    pub cache: ExactCacheConfig,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            core: ScannerConfig::default(),
            download: DownloadPolicy::Never,
            download_categories: None,
            l3_strategy: L3Strategy::default(),
            ntdb_operating_point: NtdbOperatingPoint::default(),
            ntdb_decision_threshold_point: NtdbOperatingPoint::BestF1,
            execution_backend: ExecutionBackend::default(),
            onnx_batch_mode: None,
            onnx_runtime: OnnxRuntimeOptions::default(),
            dynamic_pii: DynamicPiiConfig::default(),
            cache: ExactCacheConfig::default(),
        }
    }
}

impl GatewayConfig {
    /// The default config for `categories` up to `max_level`.
    pub fn new(categories: Vec<SecurityCategory>, max_level: SecurityLevel) -> Self {
        Self {
            core: ScannerConfig {
                categories,
                max_level,
                ..ScannerConfig::default()
            },
            ..Self::default()
        }
    }

    /// Refuse what no gateway can run: no categories, a duplicate category,
    /// zero ONNX threads, invalid Wolf windows (with Ark's serving profile
    /// filling unset sizes) or Dynamic-PII settings, and Wolf settings Ark
    /// takes from its own keys.
    pub fn validate(&self) -> Result<(), String> {
        let categories = &self.core.categories;
        if categories.is_empty() {
            return Err("categories must not be empty".into());
        }
        if let Some(category) = categories
            .iter()
            .enumerate()
            .find_map(|(i, c)| categories[..i].contains(c).then_some(c))
        {
            return Err(format!("duplicate category {}", category.as_str()));
        }
        if self.onnx_runtime.intra_threads == Some(0) || self.onnx_runtime.inter_threads == Some(0)
        {
            return Err("onnx_runtime thread counts must be positive".into());
        }
        if let Some(wolf) = &self.core.wolf {
            crate::ScanExecution::default()
                .set_wolf(wolf.clone())
                .map_err(|error| format!("wolf: {error}"))?;
            if wolf.threshold.is_some()
                || wolf.backend != ExecutionBackend::default()
                || wolf.runtime_options != OnnxRuntimeOptions::default()
            {
                return Err(
                    "wolf.threshold, wolf.backend and wolf.runtime_options: Ark calibrates \
                    Wolf with ntdb_decision_threshold_point and runs it on \
                    execution_backend and onnx_runtime"
                        .into(),
                );
            }
        }
        self.dynamic_pii
            .clone()
            .validated()
            .map(drop)
            .map_err(|error| format!("dynamic_pii: {error}"))
    }
}

/// The serialized [`ExactCacheConfig`]; missing keys keep the defaults.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CacheKeys {
    storage_location: Option<PathBuf>,
    encryption_key_hex: Option<String>,
    entry_ttl_seconds: u64,
    memory_max_entries: usize,
    memory_max_bytes: usize,
}

impl Default for CacheKeys {
    fn default() -> Self {
        let cache = ExactCacheConfig::default();
        Self {
            storage_location: None,
            encryption_key_hex: None,
            entry_ttl_seconds: cache.entry_ttl.as_secs(),
            memory_max_entries: cache.memory.max_entries,
            memory_max_bytes: cache.memory.max_bytes,
        }
    }
}

impl TryFrom<CacheKeys> for ExactCacheConfig {
    type Error = String;

    fn try_from(keys: CacheKeys) -> Result<Self, String> {
        if keys.entry_ttl_seconds == 0 {
            return Err("cache.entry_ttl_seconds must be positive".into());
        }
        let encryption = keys
            .encryption_key_hex
            .as_deref()
            .map(parse_key_hex)
            .transpose()?;
        Ok(Self {
            memory: MemoryCacheConfig {
                max_entries: keys.memory_max_entries,
                max_bytes: keys.memory_max_bytes,
            },
            persistent: keys
                .storage_location
                .map(|storage_location| PersistentCacheConfig {
                    storage_location,
                    write_mode: CacheWriteMode::Async,
                    write_behind: Default::default(),
                    encryption,
                }),
            entry_ttl: Duration::from_secs(keys.entry_ttl_seconds),
        })
    }
}

fn deserialize_cache<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<ExactCacheConfig, D::Error> {
    CacheKeys::deserialize(deserializer)?
        .try_into()
        .map_err(serde::de::Error::custom)
}

/// A 32-byte cache key from 64 hex characters.
fn parse_key_hex(value: &str) -> Result<CacheEncryptionConfig, String> {
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return Err("cache.encryption_key_hex must contain exactly 64 hex characters".into());
    }
    let mut key = [0u8; 32];
    for (byte, pair) in key.iter_mut().zip(bytes.as_chunks::<2>().0) {
        let pair = std::str::from_utf8(pair).map_err(|error| error.to_string())?;
        *byte = u8::from_str_radix(pair, 16)
            .map_err(|_| "cache.encryption_key_hex must contain only hex characters".to_string())?;
    }
    Ok(CacheEncryptionConfig::from_key(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: serde_json::Value) -> Result<GatewayConfig, String> {
        serde_json::from_value(json).map_err(|error| error.to_string())
    }

    #[test]
    fn core_keys_and_ark_keys_share_one_config() {
        let config = parse(serde_json::json!({
            "categories": ["pii", "dynamic_pii"],
            "max_level": "L3",
            "rules": {"pii_email": false},
            "l2": false,
            "cascade": {},
            "cache_root": "/models",
            "wolf": {"model": "edge", "execution": {"batch_size": 2}},
            "shell": {"policy_dirs": ["/p"]},
            "download": "missing",
            "l3_strategy": "multi",
            "onnx_batch_mode": "tensor_batch",
            "execution_backend": "cpu",
            "cache": {"entry_ttl_seconds": 60, "encryption_key_hex": "ab".repeat(32)},
        }))
        .unwrap();
        assert_eq!(
            config.core.categories,
            [SecurityCategory::Pii, SecurityCategory::DynamicPii]
        );
        assert!(!config.core.gates.native.allows_rule("pii_email"));
        assert_eq!(config.core.gates.l2, Some(false));
        assert!(config.core.gates.cascade.is_some());
        assert_eq!(config.core.cache_root, Some(PathBuf::from("/models")));
        assert_eq!(config.core.wolf.as_ref().unwrap().execution.batch_size, 2);
        assert_eq!(config.download, DownloadPolicy::Missing);
        assert_eq!(config.l3_strategy, L3Strategy::Multi);
        assert_eq!(config.onnx_batch_mode, Some(OnnxBatchMode::TensorBatch));
        assert_eq!(config.execution_backend, ExecutionBackend::Cpu);
        assert_eq!(config.cache.entry_ttl, Duration::from_secs(60));
        assert!(config.cache.persistent.is_none());
        config.validate().unwrap();
        let defaults = parse(serde_json::json!({})).unwrap();
        assert_eq!(
            defaults.ntdb_decision_threshold_point,
            NtdbOperatingPoint::BestF1
        );
        assert_eq!(
            defaults.ntdb_operating_point,
            NtdbOperatingPoint::BestPromote
        );
    }

    #[test]
    fn unknown_and_invalid_keys_are_refused() {
        for json in [
            serde_json::json!({"model_dir": "/m"}),
            serde_json::json!({"download_files": true}),
            serde_json::json!({"gates": {}}),
            serde_json::json!({"wolf_options": {}}),
            serde_json::json!({"l3_strategy": "nope"}),
            serde_json::json!({"cache": {"dir": "/c"}}),
            serde_json::json!({"cache": {"entry_ttl_seconds": 0}}),
            serde_json::json!({"cache": {"encryption_key_hex": "zz".repeat(32)}}),
        ] {
            assert!(parse(json.clone()).is_err(), "{json}");
        }
        for (json, message) in [
            (serde_json::json!({"categories": []}), "must not be empty"),
            (
                serde_json::json!({"categories": ["pii", "pii"]}),
                "duplicate",
            ),
            (
                serde_json::json!({"wolf": {"execution": {"overlap_tokens": 254}}}),
                "wolf",
            ),
            (
                serde_json::json!({"wolf": {"backend": "cpu"}}),
                "execution_backend",
            ),
            (
                serde_json::json!({"onnx_runtime": {"intra_threads": 0}}),
                "positive",
            ),
        ] {
            let error = parse(json.clone()).unwrap().validate().unwrap_err();
            assert!(error.contains(message), "{json}: {error}");
        }
    }
}
