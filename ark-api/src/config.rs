use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use patronus_ark::{ConditionalPipelineGate, ScanGateMatrix, SecurityCategory, SecurityLevel};
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
}

/// Mirrors `patronus_ark::ScanGateMatrix`, minus the L3 scheduler policy
/// (queue priority/timeouts), which stays at library defaults here.
///
/// `conditional` gates are deserialized straight into the library's own
/// `ConditionalPipelineGate` / `GateExpression` types, so the full
/// metadata/prior-result condition tree (`all` / `any` / `not` /
/// `metadata` / `result`, plus per-pipeline L3 policy overrides) is
/// expressible in YAML exactly as the Rust API defines it.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawGates {
    #[serde(default)]
    l1: Option<bool>,
    #[serde(default)]
    l2: Option<bool>,
    #[serde(default)]
    l3: Option<bool>,
    #[serde(default)]
    models: HashMap<String, bool>,
    #[serde(default)]
    conditional: Vec<ConditionalPipelineGate>,
}

impl From<RawGates> for ScanGateMatrix {
    fn from(raw: RawGates) -> Self {
        ScanGateMatrix {
            l1: raw.l1,
            l2: raw.l2,
            l3: raw.l3,
            models: raw.models,
            conditional: raw.conditional,
            ..ScanGateMatrix::default()
        }
    }
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
                gates: key.gates.map(ScanGateMatrix::from),
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
            .map(ScanGateMatrix::from)
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
        })
    }
}

fn parse_categories(values: &[String]) -> Result<Vec<SecurityCategory>, ConfigError> {
    values
        .iter()
        .map(|value| {
            SecurityCategory::from_str(value)
                .map_err(|err| ConfigError::Invalid(format!("unknown category '{value}': {err}")))
        })
        .collect()
}
