use crate::{
    detectors::{
        dlp::{
            dlp::{default_rule_enabled, DlpPipeline},
            score::DlpMode,
        },
        injection::*,
        pii::{pii::PiiPipeline, score::PiiMode},
        NativeDetection,
    },
    threat::NativeText,
    LayerResult, NativeResult, SecurityCategory,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    panic::{catch_unwind, AssertUnwindSafe},
    time::Instant,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Pii,
    Dlp,
    Injection,
}
impl Category {
    fn legacy(self) -> SecurityCategory {
        match self {
            Self::Pii => SecurityCategory::Pii,
            Self::Dlp => SecurityCategory::Dlp,
            Self::Injection => SecurityCategory::Injection,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
/// Queue-free scanner policy. Defaults to all three native categories and no Wolf.
pub struct ScannerConfig {
    pub categories: Vec<Category>,
    pub rules: HashMap<String, bool>,
    pub models: HashMap<String, bool>,
    pub pii_mode: PiiMode,
    pub dlp_mode: DlpMode,
    pub explain: bool,
    /// Maximum UTF-8 input size; exceeding it is an error. Default: 1 MiB.
    pub max_input_bytes: usize,
    /// Maximum actionable evidence spans; reports are never silently truncated.
    pub max_findings: usize,
    #[cfg(feature = "wolf")]
    pub wolf: Option<crate::wolf::WolfConfig>,
}
impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            categories: vec![Category::Pii, Category::Dlp, Category::Injection],
            rules: HashMap::new(),
            models: HashMap::new(),
            pii_mode: PiiMode::default(),
            dlp_mode: DlpMode::default(),
            explain: false,
            max_input_bytes: 1024 * 1024,
            max_findings: 10_000,
            #[cfg(feature = "wolf")]
            wolf: None,
        }
    }
}
impl ScannerConfig {
    fn allows_rule(&self, id: &str) -> bool {
        self.rules
            .get(id)
            .copied()
            .unwrap_or_else(|| default_rule_enabled(id))
    }
    fn allows_model(&self, id: &str) -> bool {
        self.models.get(id).copied().unwrap_or(true)
    }
}
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("invalid scanner configuration: {0}")]
    Config(String),
    #[error("input exceeds {limit} bytes")]
    InputLimit { limit: usize },
    #[error("findings exceed {limit}")]
    FindingLimit { limit: usize },
    #[error("native detector failed: {0}")]
    Detector(String),
    #[error("Wolf asset error: {0}")]
    Asset(String),
    #[error("Wolf inference failed: {0}")]
    Inference(String),
}
#[derive(Debug, Clone)]
/// Complete scan output; native decisions and model probabilities remain separate.
pub struct ScanReport {
    pub input_bytes: usize,
    pub native: Vec<NativeResult>,
    #[cfg(feature = "wolf")]
    pub wolf: Option<crate::wolf::WolfResult>,
}
type Producer = Box<dyn for<'a> Fn(&NativeText<'a>) -> NativeDetection + Send + Sync>;
pub struct Scanner {
    config: ScannerConfig,
    pii: PiiPipeline,
    dlp: DlpPipeline,
    catalog: rule_catalog::InjectionRuleCatalogPipeline,
    structural: structural::InjectionStructuralPipeline,
    producers: Vec<(&'static str, Producer)>,
    #[cfg(feature = "wolf")]
    wolf: Option<crate::wolf::WolfRunner>,
}
impl Scanner {
    /// Initialize native detectors and warm/verify an explicitly configured local Wolf bundle.
    pub fn new(config: ScannerConfig) -> Result<Self, ScanError> {
        if config.max_input_bytes == 0 || config.max_findings == 0 || config.categories.is_empty() {
            return Err(ScanError::Config(
                "categories and positive resource limits are required".into(),
            ));
        }
        if config
            .categories
            .iter()
            .enumerate()
            .any(|(i, c)| config.categories[..i].contains(c))
        {
            return Err(ScanError::Config("duplicate category".into()));
        }
        let mut producers: Vec<(&'static str, Producer)> = Vec::new();
        macro_rules! add {
            ($ty:path,$id:literal) => {{
                let pipeline = <$ty>::new();
                producers.push((
                    $id,
                    Box::new(move |prepared| pipeline.detect_prepared(prepared)),
                ));
            }};
        }
        add!(
            cross_tool_instruction::CrossToolInstructionPipeline,
            "native:cross_tool_instruction"
        );
        add!(
            instruction_leak::InstructionLeakPipeline,
            "native:instruction_leak"
        );
        add!(
            encoded_instruction::EncodedInstructionPipeline,
            "native:encoded_instruction"
        );
        add!(
            multi_turn_escalation::MultiTurnEscalationPipeline,
            "native:multi_turn_escalation"
        );
        add!(
            guardrail_tamper::GuardrailTamperPipeline,
            "native:guardrail_tamper"
        );
        add!(
            tool_output_instruction::ToolOutputInstructionPipeline,
            "native:tool_output_instruction"
        );
        add!(
            hidden_html_instruction::HiddenHtmlInstructionPipeline,
            "native:hidden_html_instruction"
        );
        add!(
            unicode_confusable::UnicodeConfusablePipeline,
            "native:unicode_confusable"
        );
        add!(
            zero_width_obfuscation::ZeroWidthObfuscationPipeline,
            "native:zero_width_obfuscation"
        );
        add!(
            agentic_control_abuse::AgenticControlAbusePipeline,
            "native:agentic_control_abuse"
        );
        add!(
            binary_smuggling::BinarySmugglingPipeline,
            "native:binary_smuggling"
        );
        add!(
            instruction_override::InstructionOverridePipeline,
            "native:instruction_override"
        );
        add!(
            jailbreak_framing::JailbreakFramingPipeline,
            "native:jailbreak_framing"
        );
        add!(
            covert_instruction::CovertInstructionPipeline,
            "native:covert_instruction"
        );
        add!(
            instruction_boundary::InstructionBoundaryPipeline,
            "native:instruction_boundary"
        );
        add!(
            authority_escalation::AuthorityEscalationPipeline,
            "native:authority_escalation"
        );
        add!(
            tool_call_injection::ToolCallInjectionPipeline,
            "native:tool_call_injection"
        );
        add!(
            output_manipulation::OutputManipulationPipeline,
            "native:output_manipulation"
        );
        Ok(Self {
            pii: PiiPipeline::new(),
            dlp: DlpPipeline::new(),
            catalog: rule_catalog::InjectionRuleCatalogPipeline::new(),
            structural: structural::InjectionStructuralPipeline::new(),
            producers,
            #[cfg(feature = "wolf")]
            wolf: config
                .wolf
                .as_ref()
                .map(crate::wolf::WolfRunner::new)
                .transpose()?,
            config,
        })
    }
    /// Run all configured stages synchronously. Any incomplete stage returns an error.
    pub fn scan(&mut self, text: &str) -> Result<ScanReport, ScanError> {
        if text.len() > self.config.max_input_bytes {
            return Err(ScanError::InputLimit {
                limit: self.config.max_input_bytes,
            });
        }
        let native = catch_unwind(AssertUnwindSafe(|| self.scan_native(text)))
            .map_err(|_| ScanError::Detector("native scanner panicked".into()))??;
        #[cfg(feature = "wolf")]
        let wolf = self
            .wolf
            .as_mut()
            .map(|runner| runner.scan(text))
            .transpose()?;
        Ok(ScanReport {
            input_bytes: text.len(),
            native,
            #[cfg(feature = "wolf")]
            wolf,
        })
    }
    fn scan_native(&self, text: &str) -> Result<Vec<NativeResult>, ScanError> {
        let prepared = NativeText::new(text);
        let mut results = Vec::new();
        for category in &self.config.categories {
            match category {
                Category::Pii if self.config.allows_model("native:pii") => {
                    results.push(measure(category.legacy(), "native:pii", text, || {
                        self.pii.detect_prepared_with_mode(
                            &prepared,
                            |id| self.config.allows_rule(id),
                            self.config.explain,
                            self.config.pii_mode,
                        )
                    }))
                }
                Category::Dlp => {
                    if self.config.allows_model("native:dlp") {
                        results.push(measure(category.legacy(), "native:dlp", text, || {
                            self.dlp.detect_prepared_with_mode(
                                &prepared,
                                |id| self.config.allows_rule(id),
                                self.config.explain,
                                self.config.dlp_mode,
                            )
                        }));
                    }
                    macro_rules! extra {
                        ($ty:path,$id:literal,$rule:literal) => {
                            if self.config.allows_model($id) && self.config.allows_rule($rule) {
                                let pipe = <$ty>::new();
                                results.push(measure(category.legacy(), $id, text, || {
                                    pipe.detect_prepared(&prepared)
                                }));
                            }
                        };
                    }
                    extra!(
                        crate::detectors::dlp::sensitive_material::SensitiveMaterialPipeline,
                        "native:sensitive_material",
                        "dlp_sensitive_material"
                    );
                    extra!(
                        crate::detectors::dlp::secret_transfer::SecretTransferPipeline,
                        "native:secret_transfer",
                        "dlp_secret_transfer"
                    );
                    extra!(
                        crate::detectors::mcp::mcp_runtime_risk::McpRuntimeRiskPipeline,
                        "native:mcp_runtime_risk",
                        "dlp_mcp_runtime_risk"
                    );
                    extra!(
                        crate::detectors::mcp::mcp_policy::McpPolicyPipeline,
                        "native:mcp_policy",
                        "dlp_mcp_policy"
                    );
                    extra!(
                        crate::detectors::dlp::destructive_operation::DestructiveOperationPipeline,
                        "native:destructive_operation",
                        "dlp_destructive_operation"
                    );
                }
                Category::Injection if self.config.allows_model("native:injection_l1") => {
                    let mut outputs = Vec::new();
                    if self.config.allows_model("native:injection_rule_catalog") {
                        outputs.push(measure(
                            category.legacy(),
                            "native:injection_rule_catalog",
                            text,
                            || {
                                self.catalog
                                    .detect_prepared(&prepared, |id| self.config.allows_rule(id))
                            },
                        ));
                    }
                    if self.config.allows_model("native:injection_structural")
                        && self
                            .config
                            .allows_rule("ark.injection.structure.override_sensitive_disclosure")
                    {
                        outputs.push(measure(
                            category.legacy(),
                            "native:injection_structural",
                            text,
                            || self.structural.detect_prepared(&prepared),
                        ));
                    }
                    for (id, produce) in &self.producers {
                        if self.config.allows_model(id)
                            && self.config.allows_rule(signal::native_rule_id(id))
                        {
                            outputs
                                .push(measure(category.legacy(), id, text, || produce(&prepared)));
                        }
                    }
                    if !outputs.is_empty() {
                        results.push(crate::injection_l1::aggregate(text, outputs));
                    }
                }
                _ => {}
            }
        }
        let secrets = results
            .iter()
            .filter(|r| r.category == "dlp")
            .flat_map(|r| &r.evidence_spans)
            .filter(|s| crate::detectors::dlp::dlp::SECRET_GROUPS.contains(&s.label.as_str()))
            .map(|s| (s.start_byte, s.end_byte))
            .collect::<Vec<_>>();
        for result in &mut results {
            if result.category == "pii" {
                result.evidence_spans.retain(|s| {
                    !secrets
                        .iter()
                        .any(|&(start, end)| s.start_byte < end && s.end_byte > start)
                });
            }
        }
        if results
            .iter()
            .map(|r| r.evidence_spans.len())
            .sum::<usize>()
            > self.config.max_findings
        {
            return Err(ScanError::FindingLimit {
                limit: self.config.max_findings,
            });
        }
        if results.iter().any(|r| {
            r.class_name == "error" || r.decision.as_ref().is_some_and(|d| d.terminality.degraded)
        }) {
            return Err(ScanError::Detector(
                "one or more native producers failed".into(),
            ));
        }
        Ok(results)
    }
}
fn measure(
    category: SecurityCategory,
    model: &str,
    text: &str,
    detect: impl FnOnce() -> NativeDetection,
) -> NativeResult {
    let start = Instant::now();
    let detection = detect();
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    let spans = crate::post_prediction::filter_evidence(category, text, detection.evidence_spans);
    let confidence = spans
        .iter()
        .map(|s| s.score)
        .reduce(f64::max)
        .unwrap_or(detection.result.confidence);
    NativeResult {
        category: category.as_str().into(),
        class_name: detection.result.class_name.clone(),
        confidence,
        level: "L1".into(),
        model: model.into(),
        duration_ms,
        layers: vec![LayerResult {
            level: "L1".into(),
            layer_type: "native".into(),
            class_name: detection.result.class_name,
            confidence,
            matched: true,
            duration_ms,
            thresholds: HashMap::new(),
            details: detection.details,
        }],
        evidence_spans: spans,
        label_scores: Vec::new(),
        decision: None,
    }
}
