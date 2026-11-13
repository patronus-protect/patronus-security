// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::detectors::dlp::dlp::{DEFAULT_ON_DOCUMENT_GROUPS, DLP_PATTERNS, SECRET_GROUPS};
use crate::detectors::pii::pii::{is_bare_rule, PII_PATTERNS};
use crate::SecurityCategory;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, str::FromStr};

/// Output mode of a native category (`<category>_mode`). `Strict` is the
/// default and the pre-score behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreMode {
    /// Rule acceptance only; every finding scores `1.0`.
    #[default]
    Strict,
    /// Model scores; candidates below `0.50` are dropped.
    Balanced,
    /// Model scores; candidates below `0.30` are dropped.
    Recall,
}

impl ScoreMode {
    /// Minimum model score of an emitted finding; `None` keeps strict scoring.
    pub const fn min_score(self) -> Option<f64> {
        match self {
            Self::Strict => None,
            Self::Balanced => Some(0.5),
            Self::Recall => Some(0.3),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Balanced => "balanced",
            Self::Recall => "recall",
        }
    }
}

impl fmt::Display for ScoreMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ScoreMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "strict" => Ok(Self::Strict),
            "balanced" => Ok(Self::Balanced),
            "recall" => Ok(Self::Recall),
            _ => Err(format!(
                "unknown score mode {value:?}; expected strict, balanced or recall"
            )),
        }
    }
}

/// DLP content rules that stay off unless a caller enables them explicitly.
const OPT_IN_RULES: [&str; 3] = [
    "dlp_mcp_runtime_risk",
    "dlp_mcp_policy",
    "dlp_destructive_operation",
];

/// Default of a rule without an explicit gate, shared by every host: all
/// non-DLP rules (Cat's shell policies included) except the bare PII forms
/// (opt-in), the DLP credential/secret rules and the classification markings
/// are on, the other DLP content rules are opt-in.
pub fn default_rule_enabled(rule_id: &str) -> bool {
    if is_bare_rule(rule_id) {
        return false;
    }
    if !rule_id.starts_with("dlp_") {
        return true;
    }
    if OPT_IN_RULES.contains(&rule_id) {
        return false;
    }
    DLP_PATTERNS
        .iter()
        .find(|pattern| pattern.name == rule_id)
        .is_none_or(|pattern| {
            SECRET_GROUPS.contains(&pattern.entity_group)
                || DEFAULT_ON_DOCUMENT_GROUPS.contains(&pattern.entity_group)
        })
}

/// Per-call native policy: rule, model, mode and diagnostics gates, shared by
/// the Core scanner and the full gateway. Missing rule entries use
/// [`default_rule_enabled`], missing model entries are enabled.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NativeGates {
    /// Per-rule overrides keyed by stable public rule id.
    pub rules: HashMap<String, bool>,
    /// Per-model or per-native-scanner overrides keyed by result model names
    /// such as `native:mcp_runtime_risk`.
    pub models: HashMap<String, bool>,
    /// Native PII output mode.
    pub pii_mode: ScoreMode,
    /// Native DLP output mode.
    pub dlp_mode: ScoreMode,
    /// Output modes of the attack classes. `strict` keeps each producer's own
    /// acceptance; `balanced`/`recall` also drop evidence scoring below
    /// [`ScoreMode::min_score`].
    pub injection_mode: ScoreMode,
    pub jailbreak_mode: ScoreMode,
    pub prompt_extraction_mode: ScoreMode,
    pub tool_poisoning_mode: ScoreMode,
    pub agent_config_tampering_mode: ScoreMode,
    pub memory_poisoning_mode: ScoreMode,
    pub exfiltration_mode: ScoreMode,
    pub unsafe_action_mode: ScoreMode,
    pub resource_exhaustion_mode: ScoreMode,
    pub harmful_content_mode: ScoreMode,
    pub toxic_language_mode: ScoreMode,
    /// Include bounded diagnostic anchor metadata. Disabled by default.
    pub explain: bool,
}

impl NativeGates {
    /// Gates with every native rule enabled, including the opt-in DLP content
    /// families and the bare PII forms.
    pub fn all_enabled() -> Self {
        let rules = DLP_PATTERNS
            .iter()
            .map(|pattern| pattern.name)
            .chain(OPT_IN_RULES)
            .chain(
                PII_PATTERNS
                    .iter()
                    .map(|pattern| pattern.name)
                    .filter(|name| is_bare_rule(name)),
            )
            .map(|id| (id.to_owned(), true))
            .collect();
        Self {
            rules,
            ..Self::default()
        }
    }

    /// The `<category>_mode` of a native category; other categories are strict.
    pub fn mode(&self, category: SecurityCategory) -> ScoreMode {
        match category {
            SecurityCategory::Pii => self.pii_mode,
            SecurityCategory::Dlp => self.dlp_mode,
            SecurityCategory::Injection => self.injection_mode,
            SecurityCategory::Jailbreak => self.jailbreak_mode,
            SecurityCategory::PromptExtraction => self.prompt_extraction_mode,
            SecurityCategory::ToolPoisoning => self.tool_poisoning_mode,
            SecurityCategory::AgentConfigTampering => self.agent_config_tampering_mode,
            SecurityCategory::MemoryPoisoning => self.memory_poisoning_mode,
            SecurityCategory::Exfiltration => self.exfiltration_mode,
            SecurityCategory::UnsafeAction => self.unsafe_action_mode,
            SecurityCategory::ResourceExhaustion => self.resource_exhaustion_mode,
            SecurityCategory::HarmfulContent => self.harmful_content_mode,
            SecurityCategory::ToxicLanguage => self.toxic_language_mode,
            _ => ScoreMode::Strict,
        }
    }

    /// Whether a model or native producer id is enabled.
    pub fn allows_model(&self, id: &str) -> bool {
        self.models.get(id).copied().unwrap_or(true)
    }

    /// Whether a stable rule id is enabled.
    pub fn allows_rule(&self, id: &str) -> bool {
        self.rules
            .get(id)
            .copied()
            .unwrap_or_else(|| default_rule_enabled(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gates_default_to_shared_rule_defaults_and_deserialize_by_key() {
        let gates = NativeGates::default();
        assert!(gates.allows_rule("pii_email"));
        assert!(gates.allows_model("native:pii"));
        assert!(!gates.allows_rule("dlp_mcp_policy"));
        assert!(NativeGates::all_enabled().allows_rule("dlp_mcp_policy"));
        assert!(!gates.allows_rule("pii_ssn_us_bare"));
        // M23: classification markings are the only document class on by default.
        assert!(gates.allows_rule("dlp_marking_tlp"));
        assert!(gates.allows_rule("dlp_marking_de_government"));
        assert!(!gates.allows_rule("dlp_document_legal_privileged"));
        assert!(NativeGates::all_enabled().allows_rule("pii_ssn_us_bare"));
        // Cat's shell policies are rules too, enabled unless gated off.
        for id in ["core.remote_to_exec", "CMD-PIPE-CURL", "user.ask_terraform"] {
            assert!(default_rule_enabled(id), "{id}");
        }
        let gates: NativeGates = serde_json::from_str(
            r#"{"rules":{"pii_email":false},"models":{"native:pii":false},"pii_mode":"recall","explain":true}"#,
        )
        .unwrap();
        assert!(!gates.allows_rule("pii_email"));
        assert!(!gates.allows_model("native:pii"));
        assert_eq!(gates.pii_mode, ScoreMode::Recall);
        assert_eq!(gates.dlp_mode, ScoreMode::Strict);
        assert!(gates.explain);
    }

    #[test]
    fn score_mode_is_strict_by_default_and_parses_canonical_names_only() {
        assert_eq!(ScoreMode::default(), ScoreMode::Strict);
        for (mode, min_score) in [
            (ScoreMode::Strict, None),
            (ScoreMode::Balanced, Some(0.5)),
            (ScoreMode::Recall, Some(0.3)),
        ] {
            assert_eq!(mode.min_score(), min_score);
            assert_eq!(mode.as_str().parse::<ScoreMode>(), Ok(mode));
            assert_eq!(mode.to_string(), mode.as_str());
            assert_eq!(serde_json::to_value(mode).unwrap(), mode.as_str());
            assert_eq!(
                serde_json::from_value::<ScoreMode>(serde_json::json!(mode.as_str())).unwrap(),
                mode
            );
        }
        for invalid in ["", "Strict", "precision", "balanced "] {
            assert!(invalid.parse::<ScoreMode>().is_err(), "{invalid:?}");
        }
        assert!(serde_json::from_str::<ScoreMode>("\"fast\"").is_err());
    }

    #[test]
    fn every_native_category_has_a_strict_by_default_mode_gate() {
        let gates = NativeGates::default();
        for category in crate::native::NATIVE_CATEGORIES {
            assert_eq!(gates.mode(category), ScoreMode::Strict, "{category:?}");
            let key = format!("{}_mode", category.as_str());
            for mode in [ScoreMode::Strict, ScoreMode::Balanced, ScoreMode::Recall] {
                let gates: NativeGates =
                    serde_json::from_value(serde_json::json!({ key.as_str(): mode })).unwrap();
                assert_eq!(gates.mode(category), mode, "{key}");
                assert_eq!(serde_json::to_value(&gates).unwrap()[&key], mode.as_str());
                for other in crate::native::NATIVE_CATEGORIES {
                    if other != category {
                        assert_eq!(gates.mode(other), ScoreMode::Strict, "{key} {other:?}");
                    }
                }
            }
            for invalid in ["fast", "Balanced", ""] {
                assert!(
                    serde_json::from_value::<NativeGates>(
                        serde_json::json!({ key.as_str(): invalid })
                    )
                    .is_err(),
                    "{key}={invalid:?}"
                );
            }
        }
        assert_eq!(
            gates.mode(SecurityCategory::ShellCommand),
            ScoreMode::Strict
        );
    }
}
