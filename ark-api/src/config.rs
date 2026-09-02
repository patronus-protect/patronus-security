use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use patronus_ark::{
    ConditionalPipelineGate, DynamicPiiConfig, L3ClusteringStrategy, L3EarlyExitMode,
    L3PipelinePolicy, L3ProgressMode, L3SchedulerPolicy, OnnxRuntimeOptions, ScanGateMatrix,
    SecurityCategory, SecurityLevel,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RawConfig {
    server: RawServer,
    auth: RawAuth,
    pipeline: RawPipeline,
    #[serde(default)]
    cache: RawCache,
}

#[derive(Debug, Deserialize)]
struct RawServer {
    bind: String,
    #[serde(default = "default_max_upload_mb")]
    max_upload_mb: usize,
}

fn default_max_upload_mb() -> usize {
    25
}

#[derive(Debug, Deserialize)]
struct RawAuth {
    keys: Vec<RawApiKey>,
}

#[derive(Debug, Deserialize)]
struct RawApiKey {
    name: String,
    key_hash: String,
    #[serde(default)]
    categories: Option<Vec<String>>,
    #[serde(default)]
    default_categories: Option<Vec<String>>,
    /// Per-key gate override. Falls back to `pipeline.gates` when absent.
    #[serde(default)]
    gates: Option<RawGates>,
}

#[derive(Debug, Deserialize)]
struct RawPipeline {
    categories: Vec<String>,
    max_level: String,
    #[serde(default)]
    model_dir: Option<String>,
    #[serde(default)]
    download_files: bool,
    /// Default execution gates applied to every scan unless a key overrides them.
    #[serde(default)]
    gates: Option<RawGates>,
    /// Overrides the `dynamic-pii` (GLiNER) pipeline's config — library
    /// default uses its small core label bundle. Deserializes
    /// straight into `patronus_ark::DynamicPiiConfig`, which already derives
    /// Deserialize with `#[serde(default, deny_unknown_fields)]`, so any
    /// field omitted here (chunk sizing, timeouts, ...) keeps the library
    /// default while `labels`/`label_thresholds`/`conditional_labels` are
    /// fully expressible in YAML exactly as the Rust API defines them.
    #[serde(default)]
    dynamic_pii: Option<DynamicPiiConfig>,
    /// Process-wide CPU session tuning. Applied before warmup so every ONNX
    /// session is created with the same bounded thread policy.
    #[serde(default)]
    onnx_runtime: RawOnnxRuntime,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawOnnxRuntime {
    intra_threads: Option<usize>,
    inter_threads: Option<usize>,
    spinning: Option<bool>,
}

impl Default for RawOnnxRuntime {
    fn default() -> Self {
        let defaults = OnnxRuntimeOptions::default();
        Self {
            intra_threads: defaults.intra_threads,
            inter_threads: defaults.inter_threads,
            spinning: defaults.spinning,
        }
    }
}

impl RawOnnxRuntime {
    fn into_options(self) -> Result<OnnxRuntimeOptions, ConfigError> {
        if self.intra_threads == Some(0) || self.inter_threads == Some(0) {
            return Err(ConfigError::Invalid(
                "pipeline.onnx_runtime thread counts must be positive".to_string(),
            ));
        }
        Ok(OnnxRuntimeOptions {
            intra_threads: self.intra_threads,
            inter_threads: self.inter_threads,
            spinning: self.spinning,
        })
    }
}

/// Mirrors `patronus_ark::ScanGateMatrix`, including the request-local L3
/// scheduler policy under `policy`.
///
/// `conditional` gates are deserialized straight into the library's own
/// `ConditionalPipelineGate` / `GateExpression` types, so the full
/// metadata/prior-result condition tree (`all` / `any` / `not` /
/// `metadata` / `result`, plus per-pipeline L3 policy overrides) is
/// expressible in YAML exactly as the Rust API defines it.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawGates {
    #[serde(default)]
    l1: Option<bool>,
    #[serde(default)]
    l2: Option<bool>,
    #[serde(default)]
    l3: Option<bool>,
    #[serde(default)]
    models: HashMap<String, bool>,
    #[serde(default)]
    rules: HashMap<String, bool>,
    #[serde(default)]
    conditional: Vec<ConditionalPipelineGate>,
    #[serde(default)]
    policy: Option<RawL3Policy>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawL3Policy {
    enabled: Option<bool>,
    priority: Option<Vec<String>>,
    ttl_ms: Option<HashMap<String, u64>>,
    estimated_cost_ms: Option<HashMap<String, u64>>,
    fairness_quantum_ms: Option<u64>,
    max_wait_ms: Option<u64>,
    degraded_factor: Option<f64>,
    early_exit: Option<L3EarlyExitMode>,
    progress: Option<L3ProgressMode>,
    #[serde(alias = "execution")]
    clustering: Option<L3ClusteringStrategy>,
    representatives_per_cluster: Option<usize>,
    verify_representatives_per_cluster: Option<usize>,
    min_cluster_similarity: Option<f64>,
    max_cluster_size: Option<usize>,
    pipelines: Option<HashMap<String, L3PipelinePolicy>>,
}

impl RawGates {
    pub(crate) fn into_gate_matrix(self) -> Result<ScanGateMatrix, ConfigError> {
        for gate in &self.conditional {
            gate.validate().map_err(ConfigError::Invalid)?;
        }
        let RawGates {
            l1,
            l2,
            l3,
            models,
            rules,
            conditional,
            policy: raw_policy,
        } = self;
        let mut policy = L3SchedulerPolicy::default();
        if let Some(raw) = raw_policy {
            if let Some(value) = raw.enabled {
                policy.enabled = value;
            }
            if let Some(value) = raw.priority {
                policy.priority = value;
            }
            if let Some(value) = raw.ttl_ms {
                policy.ttl_ms = value;
            }
            if let Some(value) = raw.estimated_cost_ms {
                policy.estimated_cost_ms = value;
            }
            if let Some(value) = raw.fairness_quantum_ms {
                policy.fairness_quantum_ms = value;
            }
            if let Some(value) = raw.max_wait_ms {
                policy.max_wait_ms = value;
            }
            if let Some(value) = raw.degraded_factor {
                policy.degraded_factor = value;
            }
            if let Some(value) = raw.early_exit {
                policy.early_exit = value;
            }
            if let Some(value) = raw.progress {
                policy.progress = value;
            }
            if let Some(value) = raw.clustering {
                policy.clustering = value;
            }
            if let Some(value) = raw.representatives_per_cluster {
                policy.representatives_per_cluster = value;
            }
            if let Some(value) = raw.verify_representatives_per_cluster {
                policy.verify_representatives_per_cluster = value;
            }
            if let Some(value) = raw.min_cluster_similarity {
                policy.min_cluster_similarity = value;
            }
            if let Some(value) = raw.max_cluster_size {
                policy.max_cluster_size = value;
            }
            if let Some(value) = raw.pipelines {
                policy.pipelines = value;
            }
        }
        validate_l3_policy(&policy)?;
        Ok(ScanGateMatrix {
            l1,
            l2,
            l3,
            models,
            rules,
            conditional,
            l3_policy: policy,
        })
    }
}

fn validate_l3_policy(policy: &L3SchedulerPolicy) -> Result<(), ConfigError> {
    if policy.fairness_quantum_ms == 0 || policy.max_cluster_size == 0 {
        return Err(ConfigError::Invalid(
            "gates.policy fairness_quantum_ms and max_cluster_size must be positive".to_string(),
        ));
    }
    if !(0.0..=1.0).contains(&policy.degraded_factor)
        || !(0.0..=1.0).contains(&policy.min_cluster_similarity)
    {
        return Err(ConfigError::Invalid(
            "gates.policy degraded_factor and min_cluster_similarity must be between 0 and 1"
                .to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize, Default)]
struct RawCache {
    dir: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ApiKeyConfig {
    pub name: String,
    /// Lowercase hex-encoded SHA-256 digest of the raw bearer token, without a `sha256:` prefix.
    pub key_hash: String,
    /// `None` means all pipeline categories are permitted for this key.
    pub allowed_categories: Option<Vec<SecurityCategory>>,
    /// Categories used when the caller omits request-local configuration.
    pub default_categories: Option<Vec<SecurityCategory>>,
    /// `None` means fall back to `Config::default_gates`.
    pub gates: Option<ScanGateMatrix>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub max_upload_bytes: usize,
    pub keys: Vec<ApiKeyConfig>,
    pub categories: Vec<SecurityCategory>,
    pub max_level: SecurityLevel,
    pub model_dir: Option<PathBuf>,
    pub download_files: bool,
    pub cache_dir: Option<PathBuf>,
    /// Gates applied when the authenticated key has no override.
    pub default_gates: ScanGateMatrix,
    /// `None` keeps the library's core Dynamic-PII bundle.
    pub dynamic_pii: Option<DynamicPiiConfig>,
    pub onnx_runtime: OnnxRuntimeOptions,
}

impl Config {
    /// Effective gate matrix for a given key: its own override, else the
    /// pipeline-wide default.
    pub fn gates_for(&self, key: &ApiKeyConfig) -> ScanGateMatrix {
        key.gates
            .clone()
            .unwrap_or_else(|| self.default_gates.clone())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config file {path} as YAML: {source}")]
    ParseYaml {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("failed to parse config file {path}: {source}")]
    ParseStructure {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid config: {0}")]
    Invalid(String),
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        // Route through `serde_json::Value` rather than deserializing
        // `RawConfig` straight out of `serde_yaml`: serde_yaml 0.9 has a
        // known bug deserializing recursive enums nested inside sequences
        // (exactly the shape of `conditional: [{ when: { any: [...] } }]`),
        // failing with a misleading "expected a YAML tag" error. Its `Value`
        // type doesn't hit that path, and converting through JSON's
        // `Deserializer` for the typed structs sidesteps it entirely.
        let yaml_value: serde_yaml::Value =
            serde_yaml::from_str(&raw).map_err(|source| ConfigError::ParseYaml {
                path: path.to_path_buf(),
                source,
            })?;
        let json_value =
            serde_json::to_value(yaml_value).map_err(|source| ConfigError::ParseStructure {
                path: path.to_path_buf(),
                source,
            })?;
        let raw: RawConfig =
            serde_json::from_value(json_value).map_err(|source| ConfigError::ParseStructure {
                path: path.to_path_buf(),
                source,
            })?;
        raw.into_config()
    }
}

impl RawConfig {
    fn into_config(self) -> Result<Config, ConfigError> {
        let bind = self
            .server
            .bind
            .parse::<SocketAddr>()
            .map_err(|err| ConfigError::Invalid(format!("server.bind: {err}")))?;

        if self.auth.keys.is_empty() {
            return Err(ConfigError::Invalid(
                "auth.keys must contain at least one entry".to_string(),
            ));
        }
        let mut keys = Vec::with_capacity(self.auth.keys.len());
        for key in self.auth.keys {
            let allowed_categories = key
                .categories
                .map(|cats| parse_categories(&cats))
                .transpose()?;
            let default_categories = key
                .default_categories
                .map(|cats| parse_categories(&cats))
                .transpose()?;
            let key_hash = key
                .key_hash
                .strip_prefix("sha256:")
                .unwrap_or(&key.key_hash)
                .to_lowercase();
            if key_hash.len() != 64 || !key_hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ConfigError::Invalid(format!(
                    "auth.keys[{}].key_hash must be a 64-char hex sha256 digest",
                    key.name
                )));
            }
            keys.push(ApiKeyConfig {
                name: key.name,
                key_hash,
                allowed_categories,
                default_categories,
                gates: key.gates.map(RawGates::into_gate_matrix).transpose()?,
            });
        }

        let categories = parse_categories(&self.pipeline.categories)?;
        if categories.is_empty() {
            return Err(ConfigError::Invalid(
                "pipeline.categories must not be empty".to_string(),
            ));
        }
        let max_level = SecurityLevel::from_str(&self.pipeline.max_level)
            .map_err(|err| ConfigError::Invalid(format!("pipeline.max_level: {err}")))?;

        let default_gates = self
            .pipeline
            .gates
            .map(RawGates::into_gate_matrix)
            .transpose()?
            .unwrap_or_default();

        Ok(Config {
            bind,
            max_upload_bytes: self.server.max_upload_mb.saturating_mul(1024 * 1024),
            keys,
            categories,
            max_level,
            model_dir: self.pipeline.model_dir.map(PathBuf::from),
            download_files: self.pipeline.download_files,
            cache_dir: self.cache.dir.map(PathBuf::from),
            default_gates,
            dynamic_pii: self.pipeline.dynamic_pii,
            onnx_runtime: self.pipeline.onnx_runtime.into_options()?,
        })
    }
}

pub(crate) fn parse_categories(values: &[String]) -> Result<Vec<SecurityCategory>, ConfigError> {
    values
        .iter()
        .map(|value| {
            SecurityCategory::from_str(value)
                .map_err(|err| ConfigError::Invalid(format!("unknown category '{value}': {err}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use patronus_ark::{
        detectors::dlp::dlp::DLP_PATTERNS, SecurityCategory, SecurityGateway, SecurityLevel,
    };

    use super::{Config, RawGates, RawOnnxRuntime};

    #[test]
    fn onnx_runtime_config_accepts_bounded_threads() {
        let raw: RawOnnxRuntime =
            serde_yaml::from_str("intra_threads: 2\ninter_threads: 1\nspinning: false\n").unwrap();
        let options = raw.into_options().unwrap();

        assert_eq!(options.intra_threads, Some(2));
        assert_eq!(options.inter_threads, Some(1));
        assert_eq!(options.spinning, Some(false));
    }

    #[test]
    fn onnx_runtime_config_rejects_zero_threads() {
        let raw: RawOnnxRuntime = serde_yaml::from_str("intra_threads: 0\n").unwrap();

        assert!(raw.into_options().is_err());
    }

    #[test]
    fn rule_gates_parse_from_yaml_and_default_to_enabled() {
        let raw: RawGates =
            serde_yaml::from_str("rules:\n  pii_email: false\n  dlp_openai_key: true\n").unwrap();
        let gates = raw.into_gate_matrix().unwrap();

        assert!(!gates.allows_rule("pii_email"));
        assert!(gates.allows_rule("dlp_openai_key"));
        assert!(gates.allows_rule("ark.injection.override.discard_prior"));
    }

    #[test]
    fn example_config_defaults_dlp_l1_to_credentials_and_secrets() {
        let config = Config::load(Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/config.example.yaml"
        )))
        .unwrap();
        let credential_groups = [
            "API_KEY",
            "CLOUD_KEY",
            "CREDENTIAL",
            "CRYPTO_KEY",
            "PASSWORD_HASH",
            "PAYMENT_KEY",
            "PRIVATE_KEY",
            "SECRET_TOKEN",
        ];

        for pattern in DLP_PATTERNS {
            assert_eq!(
                config.default_gates.allows_rule(pattern.name),
                credential_groups.contains(&pattern.entity_group),
                "unexpected default DLP gate for {} ({})",
                pattern.name,
                pattern.entity_group
            );
        }

        assert!(config.default_gates.allows_rule("dlp_sensitive_material"));
        assert!(config.default_gates.allows_rule("dlp_secret_transfer"));
        assert!(!config.default_gates.allows_model("native:mcp_runtime_risk"));
        assert!(!config.default_gates.allows_model("native:mcp_policy"));
        assert!(!config
            .default_gates
            .allows_model("native:destructive_operation"));

        let gateway = SecurityGateway::with_max_level(
            vec![SecurityCategory::Dlp],
            SecurityLevel::L1,
            None,
            false,
        );
        gateway.set_execution_gates(config.default_gates);
        let results = gateway.scan_all(
            "password = CorrectHorseBatteryStaple\n\
             SELECT * FROM customer;\n\
             Gehalt 74.500 EUR\n\
             Fallnummer: FALL-2026-4711",
        );
        let labels = results
            .iter()
            .flat_map(|result| result.evidence_spans.iter())
            .map(|span| span.label.as_str())
            .collect::<Vec<_>>();

        assert!(labels.contains(&"CREDENTIAL"));
        assert!(!labels.iter().any(|label| label.starts_with("dlp.")));
    }
}
