// SPDX-License-Identifier: MIT OR Apache-2.0
use super::ScoreMode;
use crate::cascade::ScanGateMatrix;
use crate::detectors::NativeDetector;
use crate::{
    detectors::{dlp, injection::*, mcp, pii, threat, NativeDetection},
    threat::NativeText,
    SecurityCategory,
};
use std::sync::{Arc, LazyLock, OnceLock};

const INJECTION_L1: &str = crate::injection_l1::MODEL;

type Detect = Box<dyn Fn(&NativeText<'_>, &ScanGateMatrix) -> NativeDetection + Send + Sync>;
type Prepare = Box<dyn Fn(&ScanGateMatrix) + Send + Sync>;

/// An opaque producer and its shared outer gates. Pipeline state lives with the spec.
pub struct NativeProducerSpec {
    category: SecurityCategory,
    id: &'static str,
    parent: Option<&'static str>,
    rule: Option<&'static str>,
    detect: Detect,
    /// Builds what a scan under the gates runs (the enabled rules, the
    /// pipeline itself), so that the scan builds nothing; see
    /// [`super::NativeEngine::prepare`].
    prepare: Prepare,
}

impl NativeProducerSpec {
    pub fn id(&self) -> &'static str {
        self.id
    }
    pub fn category(&self) -> SecurityCategory {
        self.category
    }

    /// Whether this producer reports `ark.injection.*` rules, whose candidates
    /// the injection L1 scorer merges into one decision per category.
    pub fn scored(&self) -> bool {
        self.parent == Some(INJECTION_L1)
    }

    /// Parent/model/required-rule gates, independent of host level or conditional gates.
    pub fn enabled(&self, gates: &ScanGateMatrix) -> bool {
        self.parent.is_none_or(|id| gates.allows_model(id))
            && gates.allows_model(self.id)
            && self.rule.is_none_or(|id| gates.allows_rule(id))
    }

    /// Builds what a scan under `gates` runs; call it for an enabled producer.
    pub(super) fn prepare(&self, gates: &ScanGateMatrix) {
        (self.prepare)(gates);
    }

    /// PII and DLP apply their mode inside the pipeline (per match before
    /// overlap resolution, per text view before the decoded merge); the
    /// attack classes share the floor of their `<category>_mode` here.
    pub(super) fn detect(&self, text: &NativeText<'_>, gates: &ScanGateMatrix) -> NativeDetection {
        let detection = (self.detect)(text, gates);
        match self.category {
            SecurityCategory::Pii | SecurityCategory::Dlp => detection,
            category => apply_score_floor(detection, gates.mode(category)),
        }
    }
}

/// Drops evidence `mode` refuses; a detection left without evidence becomes
/// `benign` with the complementary confidence.
fn apply_score_floor(mut detection: NativeDetection, mode: ScoreMode) -> NativeDetection {
    if detection.evidence_spans.is_empty() {
        return detection;
    }
    detection.retain_admitted(mode);
    if detection.evidence_spans.is_empty() {
        detection.result.class_name = "benign".into();
        detection.result.confidence = 1.0 - detection.result.confidence;
        if let Some(accepted) = detection.details.get_mut("accepted") {
            *accepted = false.into();
        }
    }
    detection
}

/// The PII pipeline, set up once per process: every engine and gateway
/// shares its rules instead of compiling them again.
fn pii_pipeline() -> &'static pii::pii::PiiPipeline {
    static PIPELINE: LazyLock<pii::pii::PiiPipeline> = LazyLock::new(pii::pii::PiiPipeline::new);
    &PIPELINE
}

/// A family pipeline built on first use: a producer that the gates keep off
/// costs no memory. Returns its detection and its preparation.
fn lazy_pipeline<P>(detect: fn(&P, &NativeText<'_>) -> NativeDetection) -> (Detect, Prepare)
where
    P: Default + Send + Sync + 'static,
{
    let pipeline = Arc::new(OnceLock::<P>::new());
    let built = Arc::clone(&pipeline);
    (
        Box::new(move |prepared, _gates| detect(pipeline.get_or_init(P::default), prepared)),
        Box::new(move |_gates| {
            built.get_or_init(P::default);
        }),
    )
}

/// The bounded attack-class rules of `category`, gated per rule by the rules map.
fn add_threat_rules(specs: &mut Vec<NativeProducerSpec>, category: SecurityCategory) {
    static PIPELINE: LazyLock<threat::ThreatPipeline> = LazyLock::new(threat::ThreatPipeline::new);
    specs.push(NativeProducerSpec {
        category,
        id: "native:threat_l1",
        parent: None,
        rule: None,
        detect: Box::new(move |prepared, gates| {
            PIPELINE.detect_prepared(
                prepared,
                category,
                |id| gates.allows_rule(id),
                &gates.threat_thresholds(),
            )
        }),
        prepare: Box::new(move |gates| PIPELINE.prepare(category, |id| gates.allows_rule(id))),
    });
}

/// The `ark.injection.*` rules that report under `category`, scored together
/// by the injection L1 aggregation; [`signal::rule_category`] routes each rule
/// to the attack class the threat taxonomy assigns it.
fn add_injection_rules(specs: &mut Vec<NativeProducerSpec>, category: SecurityCategory) {
    macro_rules! add {
        ($ty:path, $id:literal, $rule:expr) => {{
            let (detect, prepare) =
                lazy_pipeline::<$ty>(|pipeline, prepared| pipeline.detect_prepared(prepared));
            specs.push(NativeProducerSpec {
                category,
                id: $id,
                parent: Some(INJECTION_L1),
                rule: Some($rule),
                detect,
                prepare,
            });
        }};
    }
    let catalog = Arc::new(rule_catalog::InjectionRuleCatalogPipeline::for_category(
        category,
    ));
    if !catalog.is_empty() {
        let prepared_catalog = Arc::clone(&catalog);
        specs.push(NativeProducerSpec {
            category,
            id: "native:injection_rule_catalog",
            parent: Some(INJECTION_L1),
            rule: None,
            detect: Box::new(move |prepared, gates| {
                catalog.detect_prepared(prepared, |id| gates.allows_rule(id))
            }),
            prepare: Box::new(move |gates| prepared_catalog.prepare(|id| gates.allows_rule(id))),
        });
    }
    macro_rules! injection {
        ($ty:path, $id:literal) => {
            injection!($ty, $id, signal::native_rule_id($id));
        };
        ($ty:path, $id:literal, $rule:expr) => {
            if signal::rule_category($rule) == category {
                add!($ty, $id, $rule);
            }
        };
    }
    injection!(
        structural::InjectionStructuralPipeline,
        "native:injection_structural",
        "ark.injection.structure.override_sensitive_disclosure"
    );
    injection!(
        cross_tool_instruction::CrossToolInstructionPipeline,
        "native:cross_tool_instruction"
    );
    injection!(
        instruction_leak::InstructionLeakPipeline,
        "native:instruction_leak"
    );
    injection!(
        encoded_instruction::EncodedInstructionPipeline,
        "native:encoded_instruction"
    );
    injection!(
        multi_turn_escalation::MultiTurnEscalationPipeline,
        "native:multi_turn_escalation"
    );
    injection!(
        guardrail_tamper::GuardrailTamperPipeline,
        "native:guardrail_tamper"
    );
    injection!(
        tool_output_instruction::ToolOutputInstructionPipeline,
        "native:tool_output_instruction"
    );
    injection!(
        hidden_html_instruction::HiddenHtmlInstructionPipeline,
        "native:hidden_html_instruction"
    );
    injection!(
        unicode_confusable::UnicodeConfusablePipeline,
        "native:unicode_confusable"
    );
    injection!(
        zero_width_obfuscation::ZeroWidthObfuscationPipeline,
        "native:zero_width_obfuscation"
    );
    injection!(
        agentic_control_abuse::AgenticControlAbusePipeline,
        "native:agentic_control_abuse"
    );
    injection!(
        binary_smuggling::BinarySmugglingPipeline,
        "native:binary_smuggling"
    );
    injection!(
        instruction_override::InstructionOverridePipeline,
        "native:instruction_override"
    );
    injection!(
        jailbreak_framing::JailbreakFramingPipeline,
        "native:jailbreak_framing"
    );
    injection!(
        covert_instruction::CovertInstructionPipeline,
        "native:covert_instruction"
    );
    injection!(
        instruction_boundary::InstructionBoundaryPipeline,
        "native:instruction_boundary"
    );
    injection!(
        authority_escalation::AuthorityEscalationPipeline,
        "native:authority_escalation"
    );
    injection!(
        tool_call_injection::ToolCallInjectionPipeline,
        "native:tool_call_injection"
    );
    injection!(
        output_manipulation::OutputManipulationPipeline,
        "native:output_manipulation"
    );
}

/// Producers of one native category; see [`super::NATIVE_CATEGORIES`].
pub(super) fn producers(category: SecurityCategory) -> Vec<NativeProducerSpec> {
    let mut specs = Vec::new();
    macro_rules! add {
        ($ty:path, $id:literal, $parent:expr, $rule:expr) => {{
            let (detect, prepare) =
                lazy_pipeline::<$ty>(|pipeline, prepared| pipeline.detect_prepared(prepared));
            specs.push(NativeProducerSpec {
                category,
                id: $id,
                parent: $parent,
                rule: $rule,
                detect,
                prepare,
            });
        }};
    }
    match category {
        SecurityCategory::Pii => {
            let pipeline = pii_pipeline();
            specs.push(NativeProducerSpec {
                category,
                id: "native:pii",
                parent: None,
                rule: None,
                detect: Box::new(move |prepared, gates| {
                    pipeline.detect_prepared_with_mode(
                        prepared,
                        |id| gates.allows_rule(id),
                        gates.explain,
                        gates.pii_mode,
                    )
                }),
                prepare: Box::new(move |gates| {
                    pipeline.prepare(|id| gates.allows_rule(id), gates.pii_mode)
                }),
            });
        }
        SecurityCategory::Dlp => {
            let pipeline = dlp::dlp::DlpPipeline::shared();
            specs.push(NativeProducerSpec {
                category,
                id: "native:dlp",
                parent: None,
                rule: None,
                detect: Box::new(move |prepared, gates| {
                    pipeline.detect_prepared_with_mode(
                        prepared,
                        |id| gates.allows_rule(id),
                        gates.explain,
                        gates.dlp_mode,
                    )
                }),
                prepare: Box::new(move |gates| pipeline.prepare(|id| gates.allows_rule(id))),
            });
            add!(
                mcp::mcp_policy::McpPolicyPipeline,
                "native:mcp_policy",
                None,
                Some("dlp_mcp_policy")
            );
        }
        SecurityCategory::UnsafeAction => {
            add_threat_rules(&mut specs, category);
            add_injection_rules(&mut specs, category);
            add!(
                dlp::sensitive_material::SensitiveMaterialPipeline,
                "native:sensitive_material",
                None,
                Some("dlp_sensitive_material")
            );
            add!(
                mcp::mcp_runtime_risk::McpRuntimeRiskPipeline,
                "native:mcp_runtime_risk",
                None,
                Some("dlp_mcp_runtime_risk")
            );
            add!(
                dlp::destructive_operation::DestructiveOperationPipeline,
                "native:destructive_operation",
                None,
                Some("dlp_destructive_operation")
            );
        }
        SecurityCategory::Exfiltration => {
            add_threat_rules(&mut specs, category);
            add_injection_rules(&mut specs, category);
            add!(
                dlp::secret_transfer::SecretTransferPipeline,
                "native:secret_transfer",
                None,
                Some("dlp_secret_transfer")
            );
        }
        SecurityCategory::Injection
        | SecurityCategory::Jailbreak
        | SecurityCategory::PromptExtraction => add_injection_rules(&mut specs, category),
        SecurityCategory::ToolPoisoning
        | SecurityCategory::AgentConfigTampering
        | SecurityCategory::MemoryPoisoning => {
            add_threat_rules(&mut specs, category);
            add_injection_rules(&mut specs, category);
        }
        SecurityCategory::HarmfulContent
        | SecurityCategory::ResourceExhaustion
        | SecurityCategory::ToxicLanguage => {
            add_threat_rules(&mut specs, category);
        }
        _ => {}
    }
    specs
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
