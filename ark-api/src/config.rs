use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use patronus_ark::GatewayConfig;

use patronus_ark_core::{cascade::ScanGateMatrix, SecurityCategory};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    server: RawServer,
    auth: RawAuth,
    /// The gateway config: Ark Core's keys plus Ark's (see
    /// `patronus_ark::GatewayConfig`); `categories` and `max_level` are
    /// required; unset keys take the Rust defaults. The
    /// decision cache is the pipeline's `cache` key.
    pipeline: serde_json::Map<String, serde_json::Value>,
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
    /// Per-key override of the pipeline gates: Core's gate keys, laid over the
    /// pipeline's (see [`overlay_gates`]).
    #[serde(default)]
    gates: Option<serde_json::Map<String, serde_json::Value>>,
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
    /// The pipeline gates with this key's override laid over them; `None`
    /// when the key sets no `gates`.
    pub gates: Option<ScanGateMatrix>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub max_upload_bytes: usize,
    pub keys: Vec<ApiKeyConfig>,
    /// The `pipeline` section: the gateway's config. Its gate keys apply
    /// when the authenticated key has no gate override.
    pub gateway: GatewayConfig,
}

impl Config {
    /// Effective gate matrix for a given key: its own override, else the
    /// pipeline's gates.
    pub fn gates_for(&self, key: &ApiKeyConfig) -> ScanGateMatrix {
        key.gates
            .clone()
            .unwrap_or_else(|| self.gateway.core.gates.clone())
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

/// A key's `gates` laid over the pipeline's gate keys, field by field: a key
/// that sets `l2` keeps the pipeline's `rules`. Maps (`rules`, `models`,
/// `l3_policy`, `cascade`) merge per entry; other values, `conditional`
/// included, replace the pipeline's. Only Core's gate keys are accepted.
fn overlay_gates(
    pipeline: &serde_json::Map<String, serde_json::Value>,
    gates: serde_json::Map<String, serde_json::Value>,
) -> Result<ScanGateMatrix, serde_json::Error> {
    fn overlay(base: &mut serde_json::Value, top: serde_json::Value) {
        match (base, top) {
            (serde_json::Value::Object(base), serde_json::Value::Object(top)) => {
                for (key, value) in top {
                    overlay(base.entry(key).or_insert(serde_json::Value::Null), value);
                }
            }
            (base, top) => *base = top,
        }
    }
    let gates = serde_json::Value::Object(gates);
    ScanGateMatrix::deserialize(&gates)?;
    let mut merged = serde_json::Value::Object(pipeline.clone());
    overlay(&mut merged, gates);
    Ok(serde_json::from_value::<GatewayConfig>(merged)?.core.gates)
}

impl RawConfig {
    fn into_config(self) -> Result<Config, ConfigError> {
        let pipeline = self.pipeline;
        for required in ["categories", "max_level"] {
            if !pipeline.contains_key(required) {
                return Err(ConfigError::Invalid(format!(
                    "pipeline.{required} is required"
                )));
            }
        }
        let gateway: GatewayConfig = serde_json::from_value(pipeline.clone().into())
            .map_err(|error| ConfigError::Invalid(format!("pipeline: {error}")))?;
        gateway
            .validate()
            .map_err(|error| ConfigError::Invalid(format!("pipeline: {error}")))?;
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
            let gates = key
                .gates
                .map(|gates| overlay_gates(&pipeline, gates))
                .transpose()
                .map_err(|error| {
                    ConfigError::Invalid(format!("auth.keys[{}].gates: {error}", key.name))
                })?;
            keys.push(ApiKeyConfig {
                name: key.name,
                key_hash,
                allowed_categories: key.categories,
                default_categories: key.default_categories,
                gates,
            });
        }

        let categories = &gateway.core.categories;
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
        Ok(Config {
            bind,
            max_upload_bytes: self.server.max_upload_mb.saturating_mul(1024 * 1024),
            keys,
            gateway,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use patronus_ark::{GatewayConfig, SecurityGateway};

    use patronus_ark_core::{
        cascade::SecurityLevel, detectors::dlp::dlp::DLP_PATTERNS, SecurityCategory,
    };

    use patronus_ark_core::cascade::ScanGateMatrix;

    use super::{Config, RawConfig};

    fn startup_config() -> serde_json::Value {
        serde_json::json!({
            "server": {"bind": "127.0.0.1:0"},
            "auth": {"keys": [{"name": "fixture", "key_hash": "0".repeat(64)}]},
            "pipeline": {"categories": ["pii"], "max_level": "L1"}
        })
    }

    fn load(value: serde_json::Value) -> Result<Config, String> {
        serde_json::from_value::<RawConfig>(value)
            .map_err(|error| error.to_string())?
            .into_config()
            .map_err(|error| error.to_string())
    }

    #[test]
    fn pipeline_cache_is_the_one_cache_location_and_keeps_encryption_ttl_and_limits() {
        let mut value = startup_config();
        value["pipeline"]["cache"] = serde_json::json!({
            "storage_location": "/var/cache/ark/decisions.redb",
            "encryption_key_hex": "ab".repeat(32),
            "entry_ttl_seconds": 60,
            "memory_max_entries": 7,
            "memory_max_bytes": 4096,
        });
        let cache = load(value.clone()).unwrap().gateway.cache;
        let persistent = cache
            .persistent
            .expect("storage_location enables the persistent cache");
        assert_eq!(
            persistent.storage_location,
            Path::new("/var/cache/ark/decisions.redb")
        );
        assert!(
            persistent.encryption.is_some(),
            "the encryption key is kept"
        );
        assert_eq!(cache.entry_ttl, std::time::Duration::from_secs(60));
        assert_eq!(
            (cache.memory.max_entries, cache.memory.max_bytes),
            (7, 4096)
        );
        // The former top-level `cache.dir` is refused, not silently ignored.
        value["cache"] = serde_json::json!({"dir": "/var/cache/ark"});
        assert!(load(value).unwrap_err().contains("unknown field `cache`"));
    }

    #[test]
    fn an_encryption_key_without_a_cache_location_is_refused() {
        let mut value = startup_config();
        value["pipeline"]["cache"] = serde_json::json!({"encryption_key_hex": "ab".repeat(32)});
        assert!(load(value)
            .unwrap_err()
            .contains("set cache.storage_location"));
    }

    #[test]
    fn pipeline_categories_and_level_accept_their_from_str_names() {
        let mut value = startup_config();
        value["pipeline"] =
            serde_json::json!({"categories": ["PII", "dynamic_pii"], "max_level": "l2"});
        let config = load(value).unwrap();
        assert_eq!(
            config.gateway.core.categories,
            [SecurityCategory::Pii, SecurityCategory::DynamicPii]
        );
        assert_eq!(config.gateway.core.max_level, SecurityLevel::L2);
        for (key, invalid) in [
            ("categories", serde_json::json!(["nope"])),
            ("categories", serde_json::json!([])),
            ("model_dir", serde_json::json!("/models")),
        ] {
            let mut value = startup_config();
            value["pipeline"][key] = invalid;
            assert!(load(value).is_err(), "{key}");
        }
        for required in ["categories", "max_level"] {
            let mut value = startup_config();
            value["pipeline"].as_object_mut().unwrap().remove(required);
            assert!(load(value).unwrap_err().contains(required));
        }
    }

    #[test]
    fn gates_keep_flat_native_keys_and_reject_unknown_keys() {
        let gates: ScanGateMatrix = serde_yaml::from_str(
            "rules: {pii_email: false}\nmodels: {'native:pii': false}\nl2: false\n",
        )
        .unwrap();
        assert!(!gates.allows_rule("pii_email"));
        assert!(!gates.allows_model("native:pii"));
        assert_eq!(gates.l2, Some(false));
        assert!(serde_yaml::from_str::<ScanGateMatrix>("rule: {pii_email: false}").is_err());
        // The pipeline's gate keys sit at its top level, like Core's.
        let mut value = startup_config();
        value["pipeline"]["rules"] = serde_json::json!({"pii_email": false});
        let config = load(value).unwrap();
        assert!(!config.gateway.core.gates.allows_rule("pii_email"));
    }

    #[test]
    fn key_gates_override_only_the_pipeline_gate_keys_they_set() {
        let mut value = startup_config();
        value["pipeline"]["l2"] = serde_json::json!(false);
        value["pipeline"]["pii_mode"] = serde_json::json!("balanced");
        value["pipeline"]["rules"] = serde_json::json!({"pii_email": false, "pii_ssn": false});
        value["auth"]["keys"] = serde_json::json!([
            {"name": "plain", "key_hash": "0".repeat(64)},
            {"name": "tenant", "key_hash": "1".repeat(64), "gates": {
                "l3": false,
                "rules": {"pii_ssn": true, "dlp_openai_key": false}
            }}
        ]);
        let config = load(value).unwrap();
        assert!(config.keys[0].gates.is_none());
        let pipeline = config.gates_for(&config.keys[0]);
        assert_eq!((pipeline.l2, pipeline.l3), (Some(false), None));
        let tenant = config.gates_for(&config.keys[1]);
        assert_eq!((tenant.l2, tenant.l3), (Some(false), Some(false)));
        assert_ne!(pipeline.pii_mode, Default::default());
        assert_eq!(tenant.pii_mode, pipeline.pii_mode);
        assert!(!tenant.allows_rule("pii_email"));
        assert!(tenant.allows_rule("pii_ssn"));
        assert!(!tenant.allows_rule("dlp_openai_key"));
        assert!(pipeline.allows_rule("dlp_openai_key"));
    }

    #[test]
    fn key_gates_accept_only_core_gate_keys() {
        for gates in [
            serde_json::json!({"categories": ["pii"]}),
            serde_json::json!({"l2": "sometimes"}),
        ] {
            let mut value = startup_config();
            value["auth"]["keys"][0]["gates"] = gates;
            let error = load(value).unwrap_err();
            assert!(error.contains("auth.keys[fixture].gates"), "{error}");
        }
    }

    #[test]
    fn unset_l3_strategy_is_the_rust_default_dedicated() {
        let config = load(startup_config()).unwrap();
        assert_eq!(
            config.gateway.l3_strategy,
            patronus_ark::L3Strategy::Dedicated
        );
        assert!(config.gateway.core.wolf.is_none());
    }

    #[test]
    fn startup_wolf_settings_reach_the_real_gateway_before_warmup() {
        let mut value = startup_config();
        value["pipeline"]["l3_strategy"] = serde_json::json!("dedicated");
        value["pipeline"]["wolf"] = serde_json::json!({
            "model": "edge",
            "precision": "mixed_x86",
            "execution": {"window_tokens": 32, "overlap_tokens": 4, "batch_size": 2}
        });
        let config = load(value).unwrap();
        let gateway = SecurityGateway::new(config.gateway.clone()).unwrap();
        assert_eq!(gateway.l3_strategy(), patronus_ark::L3Strategy::Dedicated);
        let execution = gateway.distributed_execution();
        let wolf = execution.wolf();
        assert_eq!(
            wolf.execution,
            config.gateway.core.wolf.as_ref().unwrap().execution
        );
        assert_eq!(wolf.model, patronus_ark_core::wolf::WolfModel::Edge);
        assert_eq!(
            wolf.precision,
            patronus_ark_core::wolf::WolfPrecision::MixedX86
        );
    }

    #[test]
    fn startup_wolf_selection_rejects_unknown_models_and_precisions() {
        for wolf in [
            serde_json::json!({"model": "large"}),
            serde_json::json!({"precision": "int4"}),
            serde_json::json!({"model": "small", "quant": "x86"}),
        ] {
            let mut value = startup_config();
            value["pipeline"]["wolf"] = wolf;
            assert!(load(value).is_err());
        }
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
        value["pipeline"]["categories"] = serde_json::json!(["shell_command"]);
        value["pipeline"]["shell"] = serde_json::json!({
            "policy_dirs": [dir],
            "allowlist": {"C2-WEBHOOK-SITE": "ask"}
        });
        let config = load(value.clone()).unwrap();
        let gateway = SecurityGateway::new(config.gateway.clone()).unwrap();
        let shell = gateway.shell_command_policy_config();
        assert_eq!(shell.user_policies.len(), 1);
        assert_eq!(shell.allowlist["C2-WEBHOOK-SITE"], "ask");

        value["pipeline"]["shell"]["policy_dirs"] = serde_json::json!([dir.join("missing")]);
        let config = load(value.clone()).unwrap();
        let error = SecurityGateway::new(config.gateway).err().unwrap();
        assert!(error.contains("shell"), "{error}");
        value["pipeline"]["shell"] = serde_json::json!({"policies": []});
        assert!(load(value).is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn startup_wolf_settings_validate_profiles_and_strategy_during_config_loading() {
        for execution in [
            serde_json::json!({"batch_size": 0}),
            serde_json::json!({"window_tokens": 2}),
            serde_json::json!({"overlap_tokens": 254}),
            serde_json::json!({"unknown": 4}),
        ] {
            let mut value = startup_config();
            value["pipeline"]["wolf"] = serde_json::json!({ "execution": execution });
            assert!(load(value).unwrap_err().contains("pipeline"), "{execution}");
        }
        let mut value = startup_config();
        value["pipeline"]["l3_strategy"] = serde_json::json!("unknown");
        assert!(load(value).unwrap_err().contains("pipeline"));
    }

    #[test]
    fn onnx_runtime_config_accepts_bounded_threads_and_rejects_zero() {
        let mut value = startup_config();
        value["pipeline"]["onnx_runtime"] =
            serde_json::json!({"intra_threads": 2, "inter_threads": 1, "spinning": false});
        let options = load(value).unwrap().gateway.core.onnx_runtime;
        assert_eq!(options.intra_threads, Some(2));
        assert_eq!(options.inter_threads, Some(1));
        assert_eq!(options.spinning, Some(false));
        let mut value = startup_config();
        value["pipeline"]["onnx_runtime"] = serde_json::json!({"intra_threads": 0});
        assert!(load(value).is_err());
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
        assert!(!ScanGateMatrix::default().explain);
        let gates: ScanGateMatrix = serde_yaml::from_str("explain: true").unwrap();
        assert!(gates.explain);
        assert!(serde_yaml::from_str::<ScanGateMatrix>("explain: verbose").is_err());
    }

    #[test]
    fn category_modes_are_strict_by_default_and_explicitly_configurable() {
        use patronus_ark_core::native::ScoreMode;
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
                ScanGateMatrix::default().mode(category_id),
                ScoreMode::Strict
            );
            for mode in [ScoreMode::Strict, ScoreMode::Balanced, ScoreMode::Recall] {
                let gates: ScanGateMatrix =
                    serde_yaml::from_str(&format!("{category}_mode: {mode}")).unwrap();
                assert_eq!(gates.mode(category_id), mode, "{category}");
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
    fn rule_gates_parse_from_yaml_and_default_to_enabled() {
        let gates: ScanGateMatrix =
            serde_yaml::from_str("rules:\n  pii_email: false\n  dlp_openai_key: true\n").unwrap();

        assert!(!gates.allows_rule("pii_email"));
        assert!(gates.allows_rule("dlp_openai_key"));
        assert!(gates.allows_rule("ark.injection.override.discard_prior"));
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
                config.gateway.core.gates.allows_rule(pattern.name),
                credential_groups.contains(&pattern.entity_group)
                    || default_on_groups.contains(&pattern.entity_group),
                "unexpected default DLP gate for {} ({})",
                pattern.name,
                pattern.entity_group
            );
        }

        assert!(config
            .gateway
            .core
            .gates
            .allows_rule("dlp_sensitive_material"));
        assert!(config.gateway.core.gates.allows_rule("dlp_secret_transfer"));
        assert!(!config
            .gateway
            .core
            .gates
            .allows_rule("dlp_mcp_runtime_risk"));
        assert!(!config.gateway.core.gates.allows_rule("dlp_mcp_policy"));
        assert!(!config
            .gateway
            .core
            .gates
            .allows_rule("dlp_destructive_operation"));

        let gateway = SecurityGateway::new(GatewayConfig {
            core: patronus_ark_core::ScannerConfig {
                categories: vec![SecurityCategory::Dlp],
                max_level: SecurityLevel::L1,
                ..config.gateway.core
            },
            ..GatewayConfig::default()
        })
        .unwrap();
        let results = gateway
            .scan_all(
                "password = CorrectHorseBatteryStaple\n\
             SELECT * FROM customer;\n\
             Gehalt 74.500 EUR\n\
             Fallnummer: FALL-2026-4711",
            )
            .native;
        let labels = results
            .iter()
            .flat_map(|result| result.evidence_spans.iter())
            .map(|span| span.label.as_str())
            .collect::<Vec<_>>();

        assert!(labels.contains(&"CREDENTIAL"));
        assert!(!labels.iter().any(|label| label.starts_with("dlp.")));
    }
}
