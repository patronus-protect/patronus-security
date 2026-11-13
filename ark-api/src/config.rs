use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use patronus_ark::{
    detectors::shell::ShellPolicyConfig, DynamicPiiConfig, L3Strategy, OnnxRuntimeOptions,
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, WolfExecutionOptions,
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
    categories: Option<Vec<SecurityCategory>>,
    #[serde(default)]
    default_categories: Option<Vec<SecurityCategory>>,
    /// Per-key gate override. Falls back to `pipeline.gates` when absent.
    #[serde(default)]
    gates: Option<ScanGateMatrix>,
}

#[derive(Debug, Deserialize)]
struct RawPipeline {
    categories: Vec<SecurityCategory>,
    max_level: SecurityLevel,
    #[serde(default)]
    model_dir: Option<String>,
    #[serde(default)]
    download_files: bool,
    /// The deployed shared classifier remains the default; dedicated models are opt-in.
    #[serde(default = "default_l3_strategy")]
    l3_strategy: String,
    /// Dedicated Wolf startup defaults, separate from request chunk-overlap options.
    #[serde(default)]
    wolf_options: WolfExecutionOptions,
    /// Default execution gates applied to every scan unless a key overrides them.
    #[serde(default)]
    gates: Option<ScanGateMatrix>,
    /// User policies and allowlist of the `shell_command` verdict.
    #[serde(default)]
    shell_command: Option<RawShellCommand>,
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

fn default_l3_strategy() -> String {
    "multi".into()
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

/// User policies and allowlist of the `shell_command` verdict: the
/// `policy_dirs` / `allowlist` keys of Ark Core's `shell` config.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawShellCommand {
    policy_dirs: Vec<PathBuf>,
    allowlist: BTreeMap<String, String>,
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
    /// `pipeline.shell_command` user policies and allowlist; `None` keeps the
    /// bundle policies only.
    pub shell_command: Option<ShellPolicyConfig>,
    /// `None` keeps the library's core Dynamic-PII bundle.
    pub dynamic_pii: Option<DynamicPiiConfig>,
    pub onnx_runtime: OnnxRuntimeOptions,
    pub l3_strategy: L3Strategy,
    pub wolf_options: WolfExecutionOptions,
}

impl Config {
    /// Apply server startup defaults through the existing gateway configuration API.
    pub fn apply_model_defaults(&self, gateway: &SecurityGateway) -> Result<(), ConfigError> {
        gateway
            .set_wolf_execution_options(self.wolf_options)
            .map_err(|error| ConfigError::Invalid(format!("pipeline.wolf_options: {error}")))?;
        gateway.set_l3_strategy(self.l3_strategy);
        if let Some(shell_command) = &self.shell_command {
            gateway
                .set_shell_command_policy_config(shell_command.clone())
                .map_err(|error| {
                    ConfigError::Invalid(format!("pipeline.shell_command: {error}"))
                })?;
        }
        Ok(())
    }

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
        let l3_strategy = self
            .pipeline
            .l3_strategy
            .parse::<L3Strategy>()
            .map_err(|error| ConfigError::Invalid(format!("pipeline.l3_strategy: {error}")))?;
        self.pipeline
            .wolf_options
            .validate()
            .map_err(|error| ConfigError::Invalid(format!("pipeline.wolf_options: {error}")))?;
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
                allowed_categories: key.categories,
                default_categories: key.default_categories,
                gates: key.gates,
            });
        }

        let categories = self.pipeline.categories;
        if categories.is_empty() {
            return Err(ConfigError::Invalid(
                "pipeline.categories must not be empty".to_string(),
            ));
        }
        for key in &keys {
            if let Some(defaults) = &key.default_categories {
                for category in defaults {
                    if !categories.contains(category)
                        || key
                            .allowed_categories
                            .as_ref()
                            .is_some_and(|allowed| !allowed.contains(category))
                    {
                        return Err(ConfigError::Invalid(format!(
                            "auth.keys[{}].default_categories contains unavailable category '{}'",
                            key.name,
                            category.as_str()
                        )));
                    }
                }
            }
        }
        let default_gates = self.pipeline.gates.unwrap_or_default();
        let shell_command = self
            .pipeline
            .shell_command
            .map(|shell| ShellPolicyConfig::load(&shell.policy_dirs, &shell.allowlist))
            .transpose()
            .map_err(|error| ConfigError::Invalid(format!("pipeline.shell_command: {error}")))?;

        Ok(Config {
            bind,
            max_upload_bytes: self.server.max_upload_mb.saturating_mul(1024 * 1024),
            keys,
            categories,
            max_level: self.pipeline.max_level,
            model_dir: self.pipeline.model_dir.map(PathBuf::from),
            download_files: self.pipeline.download_files,
            cache_dir: self.cache.dir.map(PathBuf::from),
            default_gates,
            shell_command,
            dynamic_pii: self.pipeline.dynamic_pii,
            onnx_runtime: self.pipeline.onnx_runtime.into_options()?,
            l3_strategy,
            wolf_options: self.pipeline.wolf_options,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use patronus_ark::{
        detectors::dlp::dlp::DLP_PATTERNS, SecurityCategory, SecurityGateway, SecurityLevel,
    };

    use patronus_ark::ScanGateMatrix;

    use super::{Config, RawConfig, RawOnnxRuntime};

    fn startup_config() -> serde_json::Value {
        serde_json::json!({
            "server": {"bind": "127.0.0.1:0"},
            "auth": {"keys": [{"name": "fixture", "key_hash": "0".repeat(64)}]},
            "pipeline": {"categories": ["pii"], "max_level": "L1"}
        })
    }

    #[test]
    fn pipeline_categories_and_level_accept_their_from_str_names() {
        let mut value = startup_config();
        value["pipeline"] =
            serde_json::json!({"categories": ["PII", "dynamic_pii"], "max_level": "l2"});
        let config = serde_json::from_value::<RawConfig>(value)
            .unwrap()
            .into_config()
            .unwrap();
        assert_eq!(
            config.categories,
            [SecurityCategory::Pii, SecurityCategory::DynamicPii]
        );
        assert_eq!(config.max_level, SecurityLevel::L2);
        let mut value = startup_config();
        value["pipeline"]["categories"] = serde_json::json!(["nope"]);
        assert!(serde_json::from_value::<RawConfig>(value).is_err());
    }

    #[test]
    fn gates_keep_flat_native_keys_and_reject_unknown_keys() {
        let gates: ScanGateMatrix = serde_yaml::from_str(
            "rules: {pii_email: false}\nmodels: {'native:pii': false}\nl2: false\n",
        )
        .unwrap();
        assert!(!gates.native.allows_rule("pii_email"));
        assert!(!gates.native.allows_model("native:pii"));
        assert_eq!(gates.l2, Some(false));
        assert!(serde_yaml::from_str::<ScanGateMatrix>("rule: {pii_email: false}").is_err());
    }

    #[test]
    fn startup_wolf_settings_preserve_legacy_multi_and_default_profile() {
        let raw: RawConfig = serde_json::from_value(startup_config()).unwrap();
        let config = raw.into_config().unwrap();
        assert_eq!(config.l3_strategy, patronus_ark::L3Strategy::Multi);
        assert_eq!(
            config.wolf_options,
            patronus_ark::WolfExecutionOptions::default()
        );
    }

    #[test]
    fn startup_wolf_settings_reach_the_real_gateway_before_warmup() {
        let mut value = startup_config();
        value["pipeline"]["l3_strategy"] = serde_json::json!("dedicated");
        value["pipeline"]["wolf_options"] = serde_json::json!({
            "window_tokens": 32, "overlap_tokens": 4, "batch_size": 2
        });
        let raw: RawConfig = serde_json::from_value(value).unwrap();
        let config = raw.into_config().unwrap();
        let gateway = SecurityGateway::with_max_level(Vec::new(), SecurityLevel::L1, None, false);
        config.apply_model_defaults(&gateway).unwrap();
        assert_eq!(gateway.l3_strategy(), patronus_ark::L3Strategy::Dedicated);
        assert_eq!(
            gateway.distributed_execution().wolf_execution_options(),
            config.wolf_options
        );
    }

    #[test]
    fn shell_command_policies_load_at_startup_and_reach_the_gateway() {
        let dir = std::env::temp_dir().join(format!("ark_api_shell_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("kubectl.cedar"),
            r#"@id("user.no_kubectl_delete") @decision("block")
forbid (principal, action == Action::"segment", resource)
when { context.program == "kubectl" && context.verb == "DELETE" };"#,
        )
        .unwrap();
        let mut value = startup_config();
        value["pipeline"]["shell_command"] = serde_json::json!({
            "policy_dirs": [dir],
            "allowlist": {"C2-WEBHOOK-SITE": "ask"}
        });
        let config = serde_json::from_value::<RawConfig>(value.clone())
            .unwrap()
            .into_config()
            .unwrap();
        let shell = config.shell_command.clone().unwrap();
        assert_eq!(shell.user_policies.len(), 1);
        assert_eq!(shell.allowlist["C2-WEBHOOK-SITE"], "ask");
        let gateway = SecurityGateway::with_max_level(
            vec![SecurityCategory::ShellCommand],
            SecurityLevel::L1,
            None,
            false,
        );
        config.apply_model_defaults(&gateway).unwrap();
        assert_eq!(gateway.shell_command_policy_config(), shell);

        value["pipeline"]["shell_command"]["policy_dirs"] =
            serde_json::json!([dir.join("missing")]);
        let error = serde_json::from_value::<RawConfig>(value.clone())
            .unwrap()
            .into_config()
            .unwrap_err();
        assert!(
            error.to_string().contains("pipeline.shell_command"),
            "{error}"
        );
        value["pipeline"]["shell_command"] = serde_json::json!({"policies": []});
        assert!(serde_json::from_value::<RawConfig>(value).is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn startup_wolf_settings_validate_profiles_and_strategy_during_config_loading() {
        for profile in [
            serde_json::json!({"batch_size": 0}),
            serde_json::json!({"window_tokens": 2}),
            serde_json::json!({"overlap_tokens": 254}),
        ] {
            let mut value = startup_config();
            value["pipeline"]["wolf_options"] = profile;
            let raw: RawConfig = serde_json::from_value(value).unwrap();
            assert!(raw
                .into_config()
                .unwrap_err()
                .to_string()
                .contains("pipeline.wolf_options"));
        }
        let mut value = startup_config();
        value["pipeline"]["l3_strategy"] = serde_json::json!("unknown");
        let raw: RawConfig = serde_json::from_value(value).unwrap();
        assert!(raw
            .into_config()
            .unwrap_err()
            .to_string()
            .contains("pipeline.l3_strategy"));
        let mut value = startup_config();
        value["pipeline"]["wolf_options"] = serde_json::json!({"unknown": 4});
        assert!(serde_json::from_value::<RawConfig>(value).is_err());
    }

    #[test]
    fn rejects_key_defaults_outside_allowed_categories() {
        let yaml = format!(
            "server: {{bind: '127.0.0.1:0'}}\nauth:\n  keys:\n    - name: limited\n      key_hash: '{}'\n      categories: [injection]\n      default_categories: [dlp]\npipeline:\n  categories: [injection, dlp]\n  max_level: L1\n",
            "0".repeat(64)
        );
        let raw: RawConfig = serde_yaml::from_str(&yaml).unwrap();
        assert!(raw
            .into_config()
            .unwrap_err()
            .to_string()
            .contains("default_categories"));
    }

    #[test]
    fn explain_is_explicit_and_disabled_by_default() {
        assert!(!ScanGateMatrix::default().native.explain);
        let gates: ScanGateMatrix = serde_yaml::from_str("explain: true").unwrap();
        assert!(gates.native.explain);
        assert!(serde_yaml::from_str::<ScanGateMatrix>("explain: verbose").is_err());
    }

    #[test]
    fn category_modes_are_strict_by_default_and_explicitly_configurable() {
        use patronus_ark::ScoreMode;
        for category in [
            "pii",
            "dlp",
            "injection",
            "jailbreak",
            "prompt_extraction",
            "tool_poisoning",
            "agent_config_tampering",
            "memory_poisoning",
            "exfiltration",
            "unsafe_action",
            "resource_exhaustion",
            "harmful_content",
            "toxic_language",
        ] {
            let category_id: SecurityCategory = category.parse().unwrap();
            assert_eq!(
                ScanGateMatrix::default().native.mode(category_id),
                ScoreMode::Strict
            );
            for mode in [ScoreMode::Strict, ScoreMode::Balanced, ScoreMode::Recall] {
                let gates: ScanGateMatrix =
                    serde_yaml::from_str(&format!("{category}_mode: {mode}")).unwrap();
                assert_eq!(gates.native.mode(category_id), mode, "{category}");
            }
            for invalid in ["fast", "Balanced"] {
                let yaml = format!("{category}_mode: {invalid}");
                assert!(
                    serde_yaml::from_str::<ScanGateMatrix>(&yaml).is_err(),
                    "{yaml}"
                );
            }
        }
        assert!(serde_yaml::from_str::<ScanGateMatrix>("threat_mode: strict").is_err());
    }

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
        let gates: ScanGateMatrix =
            serde_yaml::from_str("rules:\n  pii_email: false\n  dlp_openai_key: true\n").unwrap();

        assert!(!gates.native.allows_rule("pii_email"));
        assert!(gates.native.allows_rule("dlp_openai_key"));
        assert!(gates
            .native
            .allows_rule("ark.injection.override.discard_prior"));
    }

    #[test]
    fn example_config_defaults_dlp_l1_to_credentials_secrets_and_markings() {
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
        // M23 default profile: classification markings are the one document class on by default.
        let default_on_groups = ["dlp.document.classification_marking"];

        for pattern in DLP_PATTERNS {
            assert_eq!(
                config.default_gates.native.allows_rule(pattern.name),
                credential_groups.contains(&pattern.entity_group)
                    || default_on_groups.contains(&pattern.entity_group),
                "unexpected default DLP gate for {} ({})",
                pattern.name,
                pattern.entity_group
            );
        }

        assert!(config
            .default_gates
            .native
            .allows_rule("dlp_sensitive_material"));
        assert!(config
            .default_gates
            .native
            .allows_rule("dlp_secret_transfer"));
        assert!(!config
            .default_gates
            .native
            .allows_rule("dlp_mcp_runtime_risk"));
        assert!(!config.default_gates.native.allows_rule("dlp_mcp_policy"));
        assert!(!config
            .default_gates
            .native
            .allows_rule("dlp_destructive_operation"));

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
